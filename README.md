# rustun
Simple Linux tunnel ("VPN") in Rust. IPv4.
The tunnel ist AES encrpyted using quantum keys. The keys have to be provided by a REST service running on 127.0.0.1:5000 which is expected to follow the ETSI 014 standard.

This is a PoC, not an OpenVPN replacement.

# Building
- Clone or download this repository onto a Linux system
- Ensure you have a Rust build environment https://rustup.rs
- Run `cargo build --release`

# Usage
- Copy rustun to your Linux server and client systems
- On the server box, run `sudo ./rustun -s`
- On the client box, run `sudo ./rustun your.server.ip:3030`
- You should now have a tunnel. You can verify this by running `ifconfig` on each box
- Use your tunnel by running `ping 10.0.5.3` on your client. It should ping the server and you should see replies. If not, check firewalls in between.
