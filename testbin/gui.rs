//! A GUI-subsystem control child: connect to `argv[1]`, tag, then block on the same socket.
//!
//! On Windows the subsystem marking is the whole point — such an image never attaches to its
//! spawner's console, whatever creation flags the spawn passed, so it is the only way a test
//! can construct a child whose flags say "in our console" while the OS says otherwise. The
//! crate attribute is inert everywhere else, and a `[[bin]]` target cannot be `cfg`-ed out, so
//! this binary compiles and behaves identically on every platform.
#![cfg_attr(windows, windows_subsystem = "windows")]

use std::io::{Read, Write};

fn main() {
    let addr = std::env::args().nth(1).expect("argv[1]: the control address");
    let mut sock = std::net::TcpStream::connect(&addr).expect("connect control socket");
    sock.write_all(b"G").expect("write tag");
    sock.flush().expect("flush tag");
    // Blocks until the socket closes (our death, or the test dropping its end).
    let mut buf = [0u8; 1];
    let _ = sock.read(&mut buf);
}
