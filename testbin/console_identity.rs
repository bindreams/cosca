//! The `report-console-identity` mode, shared by the console-subsystem testbin and the
//! GUI-subsystem fixture: only the image's subsystem differs between them, and that difference
//! is the whole point of running the same probe from both.
//!
//! Every fact is measured BY THIS PROCESS ABOUT ITSELF, after it is running — console
//! registration is not synchronous with the spawner's `CreateProcess` returning, so a fact
//! measured from the parent at that instant reads "absent" for every flag word.

use std::io::{Read, Write};

use windows::Win32::Foundation::{SetLastError, ERROR_INVALID_HANDLE, WIN32_ERROR};
use windows::Win32::System::Console::{GetConsoleProcessList, GetConsoleWindow};
use windows::Win32::UI::WindowsAndMessaging::IsWindowVisible;

/// Percent-escape everything outside `[A-Za-z0-9._-]`, so an unbounded value stays ONE
/// whitespace-free token in a whitespace-delimited record. `argv[0]` is a filesystem path, and a
/// user profile or checkout directory containing a space would otherwise split the record.
fn escape(value: &str) -> String {
    let mut out = String::new();
    for b in value.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-') {
            out.push(*b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// This process's own console process list, or `None` when there is none / the probe failed.
///
/// Grows to whatever count the API reports rather than capping: a too-small buffer makes it
/// return the REQUIRED count without filling, which a fixed cap would silently read as "absent".
/// The last error is cleared first so a zero return is attributable to THIS call.
fn console_pids() -> Option<Vec<u32>> {
    let mut buf = vec![0u32; 16];
    loop {
        // SAFETY: both calls are standard Win32; `buf` is a valid writable slice.
        let n = unsafe {
            SetLastError(WIN32_ERROR(0));
            GetConsoleProcessList(&mut buf)
        } as usize;
        if n == 0 {
            return None;
        }
        if n <= buf.len() {
            buf.truncate(n);
            return Some(buf);
        }
        buf.resize(n, 0);
    }
}

/// Connect to `report_addr` FIRST (so a panic below reaches the test as socket EOF, never a
/// hang), report this process's console identity, then block on the same socket until the test
/// closes it — which is what makes the report describe a live process without any timer.
///
/// `caller_pid` is the spawning process's pid, whose presence in THIS process's console list is
/// the `sees_caller` field.
///
/// Every field is one whitespace-free token, because the report is parsed by splitting on
/// whitespace. `console` is three-way — `1` has one, `0` a MEASURED absence
/// (`ERROR_INVALID_HANDLE`), `?` the probe itself failed — so a broken probe can never satisfy
/// a test's `console=0` guard.
pub fn run(report_addr: &str, caller_pid: u32) {
    let mut sock = std::net::TcpStream::connect(report_addr).expect("connect report socket");

    let pids = console_pids();
    let (console, sees_caller) = match &pids {
        Some(list) => ("1", if list.contains(&caller_pid) { "1" } else { "0" }),
        // A zero return is also how this API reports failure, so the two are told apart by the
        // code THIS call set: a console-less process gets ERROR_INVALID_HANDLE.
        None if std::io::Error::last_os_error().raw_os_error() == Some(ERROR_INVALID_HANDLE.0 as i32) => ("0", "?"),
        None => ("?", "?"),
    };

    // SAFETY: standard Win32 calls; `GetConsoleWindow` returns null when there is no console
    // window, and `IsWindowVisible` tolerates any handle value (returning false for null).
    let (hwnd, visible) = unsafe {
        let h = GetConsoleWindow();
        if h.is_invalid() {
            ("0", "0")
        } else {
            ("1", if IsWindowVisible(h).as_bool() { "1" } else { "0" })
        }
    };

    let argv0 = std::env::args().next().unwrap_or_default();
    let line = format!(
        "pid={} console={console} sees_caller={sees_caller} hwnd={hwnd} visible={visible} argv0={}\n",
        std::process::id(),
        escape(&argv0),
    );
    sock.write_all(line.as_bytes()).expect("write report");
    sock.flush().expect("flush report");

    let mut buf = [0u8; 1];
    let _ = sock.read(&mut buf); // blocks until the test closes the socket
}
