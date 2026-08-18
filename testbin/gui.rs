//! A GUI-subsystem control child: connect to `argv[1]`, tag, then block on the same socket.
//!
//! On Windows the subsystem marking is the whole point — such an image never attaches to its
//! spawner's console, whatever creation flags the spawn passed, so it is the only way a test
//! can construct a child whose flags say "in our console" while the OS says otherwise. The
//! crate attribute is inert everywhere else, and a `[[bin]]` target cannot be `cfg`-ed out, so
//! this binary compiles and behaves identically on every platform.
//!
//! It also serves `report-console-identity`, sharing that mode's body with the
//! console-subsystem testbin so the two differ in exactly one thing: the image's subsystem.
#![cfg_attr(windows, windows_subsystem = "windows")]

/// The `report-console-identity` mode, shared verbatim with `testbin/main.rs`.
#[cfg(windows)]
#[path = "console_identity.rs"]
mod console_identity;

use std::io::{Read, Write};

fn main() {
    let first = std::env::args().nth(1).expect("argv[1]: a mode or the control address");
    #[cfg(windows)]
    if first == "report-console-identity" {
        let addr = std::env::args().nth(2).expect("argv[2]: the report address");
        let caller_pid: u32 = std::env::args()
            .nth(3)
            .expect("argv[3]: the spawning process's pid")
            .parse()
            .expect("argv[3] parses as a pid");
        console_identity::run(&addr, caller_pid);
        return;
    }
    let mut sock = std::net::TcpStream::connect(&first).expect("connect control socket");
    sock.write_all(b"G").expect("write tag");
    sock.flush().expect("flush tag");
    // Blocks until the socket closes (our death, or the test dropping its end).
    let mut buf = [0u8; 1];
    let _ = sock.read(&mut buf);
}
