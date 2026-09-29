//! The accept handshake shared by the testbin (the connecting side) and `tests/common/accept.rs`
//! (the accepting side, which includes this file with `#[path]`, so there is one definition).
//!
//! A target that connects and then exits races the connection's arrival in the listener's accept
//! queue against its own exit notification: `connect()` returning does not mean the server side
//! has queued the connection. So a death-watched accept cannot tell "died after connecting" from
//! "died before connecting" by looking at the queue. The handshake removes the question: an
//! opted-in target blocks after connecting until the harness has accepted the connection and
//! written [`ACK_BYTE`] to it. An opted-in target therefore cannot exit between `connect()` and
//! the accept, so an exit seen before the accept means the handshake never completed, and the
//! harness reports it as dead without consulting the queue.
//!
//! Opt-in, by [`ACK_ENV`] in the target's environment (inherited by its descendants): a site
//! that still uses a plain `accept()` sets nothing and its targets do not wait.

#![allow(dead_code, reason = "the testbin only reads acks; `tests/common` only writes them")]

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};

/// Set (to any value) in a target's environment to make its connections wait for the ack.
pub const ACK_ENV: &str = "COSCA_TEST_ACCEPT_ACK";

/// The single byte the harness writes to a connection right after accepting it.
pub const ACK_BYTE: u8 = 0xA5;

/// Whether this process was asked to wait for acks.
pub fn enabled() -> bool {
    std::env::var_os(ACK_ENV).is_some()
}

/// Test seam for `tests/windows_testbin_ack.rs`, read by [`connect_control`]. Unset outside those
/// tests. It probes the opt-in that a testbin mode gives its own children (`.env(ACK_ENV, "1")`),
/// which an inherited [`ACK_ENV`] would otherwise hide.
///
/// - [`SEAM_STRICT`]: a connect without [`ACK_ENV`] panics, and once connected the process drops
///   [`ACK_ENV`] from its own environment, so only an explicit `.env` reaches its children.
/// - [`SEAM_DIE`]: once connected the process sets [`SEAM_DIE_NOW`], under which a descendant's
///   connect exits before connecting: a child that dies before the mode's accept.
pub const SEAM_ENV: &str = "COSCA_TEST_ACK_SEAM";
pub const SEAM_STRICT: &str = "strict";
pub const SEAM_DIE: &str = "die";
pub const SEAM_DIE_NOW: &str = "die-now";

/// `TcpStream::connect`, then, when [`enabled`], block until the harness's [`ACK_BYTE`] arrives.
pub fn connect_control(addr: impl ToSocketAddrs) -> std::io::Result<TcpStream> {
    let seam = std::env::var(SEAM_ENV).ok();
    match seam.as_deref() {
        Some(SEAM_STRICT) => assert!(
            enabled(),
            "{ACK_ENV} is not set: whoever spawned this process forgot to opt it in to the accept handshake"
        ),
        Some(SEAM_DIE_NOW) => std::process::exit(3),
        _ => {}
    }
    let mut sock = TcpStream::connect(addr)?;
    wait_for_ack(&mut sock);
    match seam.as_deref() {
        Some(SEAM_STRICT) => std::env::remove_var(ACK_ENV),
        Some(SEAM_DIE) => std::env::set_var(SEAM_ENV, SEAM_DIE_NOW),
        _ => {}
    }
    Ok(sock)
}

/// When [`enabled`], block until the harness writes [`ACK_BYTE`] on `sock`. Also used for the
/// second ack of the grandchild-pid report, which releases the reporter.
pub fn wait_for_ack(sock: &mut TcpStream) {
    if !enabled() {
        return;
    }
    let mut byte = [0u8; 1];
    sock.read_exact(&mut byte)
        .expect("the harness closed the connection before acknowledging it");
    assert_eq!(byte[0], ACK_BYTE, "the acknowledgement byte was {:#x}", byte[0]);
}

/// Writes [`ACK_BYTE`] to `sock`: the harness's half.
pub fn send_ack(sock: &mut TcpStream) -> std::io::Result<()> {
    sock.write_all(&[ACK_BYTE])
}
