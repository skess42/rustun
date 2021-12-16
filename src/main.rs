use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use libc::{ioctl, open, read, write};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::{SocketAddr, UdpSocket};
use std::os::raw::{c_char, c_short};
use std::sync::{Arc, Mutex};
use std::{env, io, mem, thread, time::Instant};
const TUNSETIFF: u64 = 0x400454ca;
const SIOCGIFFLAGS: u64 = 0x8913;
const SIOCSIFFLAGS: u64 = 0x8914;
const SIOCSIFADDR: u64 = 0x8916;
const SIOCSIFNETMASK: u64 = 0x891c;
const IFF_RUNNING: c_short = 0x40;
const IFF_UP: c_short = 0x1;
const IFF_TUN: c_short = 0x0001;
const IFF_NO_PI: c_short = 0x1000;
#[repr(C, align(16))] //struct for TUNSETIFF and SIOCGIFFLAGS/SIOCSIFFLAGS ioctl's
pub struct SetIff {
    ifname: [c_char; 16],
    flags: c_short,
    slack: [u8; 128],
}
#[repr(C, align(16))] //struct for SIOCSIFADDR ioctl
pub struct SetAddr {
    ifname: [c_char; 16],
    addr: libc::sockaddr_in,
}

#[derive(Deserialize)]
struct JsonKeys {
    keys: Vec<JsonKey>,
}

#[derive(Deserialize)]
struct JsonKey {
    #[serde(rename = "key_ID")]
    key_id: String,
    key: String,
}

#[derive(Deserialize, Serialize)]
struct Message {
    nonce: [u8; 12],
    key_id: String,
    ciphertext: Vec<u8>,
}

fn check(ret: i32) -> io::Result<()> {
    if ret != 0 {
        return Err(io::Error::from_raw_os_error(ret));
    }
    Ok(())
}
fn main() -> io::Result<()> {
    let arg = env::args()
        .nth(1)
        .expect("Argument missing! IP:port or -s to run as server");
    let socket = if arg == "-s" {
        UdpSocket::bind("0.0.0.0:3030")? //server: bind to 3030
    } else {
        UdpSocket::bind("0.0.0.0:0")? //client: let system select port to bind to
    };
    let addr: Arc<Mutex<Option<SocketAddr>>> = if arg == "-s" {
        //addr will be shared by each thread
        Arc::new(Mutex::new(None)) //server doesn't know who to talk to yet
    } else {
        Arc::new(Mutex::new(Some(arg.parse().expect("Invalid IP:port")))) //client parses IP:port
    };

    let mut new_key_measurement = OpenOptions::new()
        .write(true)
        .append(true)
        .open("new-key-measurement")
        .unwrap();

    let mut aes_measurement = OpenOptions::new()
        .write(true)
        .append(true)
        .open("aes-measurement")
        .unwrap();

    let mut key_lookup_measurement = OpenOptions::new()
        .write(true)
        .append(true)
        .open("key-lookup-measurement")
        .unwrap();

    let fd = unsafe { open(CString::new("/dev/net/tun").unwrap().as_ptr(), 2) };
    let mut params = SetIff {
        ifname: [
            b't' as i8, b'u' as i8, b'n' as i8, b'1' as i8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ], //"tun1",
        flags: IFF_TUN | IFF_NO_PI,
        slack: [0; 128],
    };
    check(unsafe { ioctl(fd, TUNSETIFF, &params) })?; //Set tun flags
    let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_IP) }; //ioctl socket
    let last_octet = if arg == "-s" { 3 } else { 2 }; // server is 10.0.5.3 client is 10.0.5.2
    let mut tun_addr = SetAddr {
        ifname: params.ifname.clone(), //same interface
        addr: libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes([10, 0, 5, last_octet]),
            }, //10.0.5.X
            sin_zero: [0; 8],
        },
    };
    check(unsafe { ioctl(s, SIOCSIFADDR, &tun_addr) })?; //Set address of interface (10.0.5.X)
    check(unsafe { ioctl(s, SIOCGIFFLAGS, &params) })?; //get flags
    params.flags = params.flags | IFF_RUNNING | IFF_UP; //add UP+RUNNING to flags
    check(unsafe { ioctl(s, SIOCSIFFLAGS, &params) })?; //set flags (turns interface on)
    tun_addr.addr.sin_addr.s_addr = u32::from_ne_bytes([255, 255, 255, 0]);
    check(unsafe { ioctl(s, SIOCSIFNETMASK, &tun_addr) })?; //set netmask (255.255.255.0)
    let addr_ref = Arc::clone(&addr); //reference to addr for recv thread to update
    let rcv_sock = socket.try_clone()?; //clone socket handle for thread to use
    let arg_cpy = arg.clone();

    thread::spawn(move || {
        //this thread forwards from socket to tun device
        let mut buf = [0; 65536]; //support full jumbo frames
        while let Ok((rcvd, src_addr)) = rcv_sock.recv_from(&mut buf) {
            let _ = addr_ref.lock().and_then(|mut a| Ok(a.replace(src_addr))); //save addr

            let message: Message = bincode::deserialize(&buf[..rcvd]).unwrap();
            // println!("Recieved encrypted packet: {:x?}", message.ciphertext);

            //use matching qkd-key for decryption
            let key = lookup_key(&arg_cpy, message.key_id, &mut key_lookup_measurement).unwrap();
            let key = Key::from_slice(&key[0..32]);
            let cipher = Aes256Gcm::new(key);

            let nonce = Nonce::from_slice(&message.nonce);
            let plaintext = cipher.decrypt(nonce, message.ciphertext.as_ref()).unwrap();
            // println!("Send plaintext packet on tun1: {:?}", &plaintext);

            let plaintext_len = plaintext.len();
            let origptr: *const u8 = &plaintext[0]; //we'll need transmute to convert *const u8 to void*
            let res = unsafe { write(fd, mem::transmute(origptr), plaintext_len) }; //send it along
            if res != plaintext_len as isize {
                eprintln!("Error? {} vs expected {}", res, plaintext_len);
                std::process::exit(1) //exit if write fails
            }
        }
    });
    let mut buf = [0; 65536]; //support full jumbo frames
    let buf_u8_ptr: *mut u8 = &mut buf[0]; //we'll need transmute to convert *mut u8 to void*
    loop {
        let read_res = unsafe { read(fd, mem::transmute(buf_u8_ptr), 65536) };
        if read_res <= 0 {
            eprintln!("Error? read {}", read_res);
            break;
        }

        let message = &buf[..read_res as usize];
        // println!("Recieved packet on tun1: {:?}", message);

        // recieve new key from qkd-device
        let client = if arg == "-s" { "ETSIA" } else { "ETSIB" };
        let url = format!("https://127.0.0.1:5000/api/v1/keys/{}/enc_keys", client);
        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        let get_new_key = Instant::now();
        let response = client.get(&url).send().unwrap().text().unwrap();
        let duration = get_new_key.elapsed();
        if arg != "-s" {
            writeln!(new_key_measurement, "{:.3?}", duration)?;
        }
        // println!("Get QKD key: {}", response);

        let mut response: JsonKeys = serde_json::from_str(&response).unwrap();
        let JsonKey { key_id, key } = response.keys.pop().unwrap();
        let qkd_key = base64::decode(key).unwrap();

        //use qkd-key for encryption
        let cipher = Aes256Gcm::new(Key::from_slice(&qkd_key[0..32]));
        let nonce = rand::thread_rng().gen::<[u8; 12]>(); // unique nonce per message
        let aes_encryption = Instant::now();
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), message.as_ref())
            .unwrap();
        let duration = aes_encryption.elapsed();
        if arg != "-s" {
            writeln!(aes_measurement, "{:.3?}", duration)?;
        }
        // println!("Encrypted packet: {:x?}", &ciphertext);

        let encrypted_message = Message {
            nonce,
            key_id,
            ciphertext,
        };
        let encrypted_message = bincode::serialize(&encrypted_message).unwrap();

        if let Ok(addr_guard) = addr.lock() {
            if let Some(addr_real) = *addr_guard {
                //server sends to last seen addr
                socket.send_to(&encrypted_message, addr_real)?;
            }
        }
    }
    Ok(())
}

fn lookup_key(arg: &str, key_id: String, key_lookup_measurement: &mut File) -> io::Result<Vec<u8>> {
    let client = if arg == "-s" { "ETSIA" } else { "ETSIB" };
    let url = format!("https://127.0.0.1:5000/api/v1/keys/{}/dec_keys", client);
    let body = format!(r#"{{"key_IDs":[{{"key_ID":"{}"}}]}}"#, key_id);
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let lookup_key = Instant::now();
    let response = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .unwrap()
        .text()
        .unwrap();
    let duration = lookup_key.elapsed();
    if arg != "-s" {
        writeln!(key_lookup_measurement, "{:.3?}", duration)?;
    }
    // println!("Lookup QKD key response: {}", response);
    let mut answer: JsonKeys = serde_json::from_str(&response).unwrap();
    let JsonKey { key_id: _, key } = answer.keys.pop().unwrap();
    let key = base64::decode(key).unwrap();
    Ok(key)
}
