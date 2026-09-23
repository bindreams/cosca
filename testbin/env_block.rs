//! The `dump-env-block` and `spawn-dump-env-block` modes: the environment block a child receives
//! from each Windows backend, byte for byte.

use std::io::Write;

use windows::core::PCWSTR;
use windows::Win32::System::Environment::{FreeEnvironmentStringsW, GetEnvironmentStringsW};

/// Print this process's environment block in block order, one entry per line, each UTF-16 unit
/// as four hex digits. Read from `GetEnvironmentStringsW`, so casing, order and unpaired
/// surrogates are what the OS holds.
pub fn dump() {
    // SAFETY: no preconditions; the block is freed below.
    let block = unsafe { GetEnvironmentStringsW() };
    assert!(!block.is_null(), "GetEnvironmentStringsW failed");
    let mut out = std::io::stdout().lock();
    let mut entry = block.0;
    loop {
        // SAFETY: the block is a run of NUL-terminated entries closed by an empty one, so every
        // read up to and including the terminators is in bounds.
        let len = (0..).take_while(|&i| unsafe { *entry.add(i) } != 0).count();
        if len == 0 {
            break;
        }
        // SAFETY: `len` units starting at `entry` were just read.
        let units = unsafe { std::slice::from_raw_parts(entry, len) };
        let hex: String = units.iter().map(|u| format!("{u:04x}")).collect();
        writeln!(out, "{hex}").unwrap();
        // SAFETY: skips this entry and its NUL, landing on the next entry or the terminator.
        entry = unsafe { entry.add(len + 1) };
    }
    out.flush().unwrap();
    // SAFETY: `block` came from `GetEnvironmentStringsW` and is freed once.
    unsafe { FreeEnvironmentStringsW(PCWSTR(block.0)) }.expect("FreeEnvironmentStringsW");
}

/// Spawn `dump-env-block` through cosca's `backend` (`raw` or `std`) after replaying `ops`, and
/// relay its output. An op is `set:KEY=VAL`, `remove:KEY` or `clear`.
pub fn spawn(backend: &str, ops: &[String]) {
    let exe = std::env::current_exe().expect("current_exe");
    let mut cmd = cosca::Command::new();
    match backend {
        // `executable()` always routes to the raw `CreateProcessW` backend.
        "raw" => cmd.executable(&exe).commandline("cosca_testbin dump-env-block"),
        "std" => cmd.arg(&exe).arg("dump-env-block"),
        other => panic!("unknown backend {other:?}"),
    };
    for op in ops {
        if op == "clear" {
            cmd.env_clear();
        } else if let Some(key) = op.strip_prefix("remove:") {
            cmd.env_remove(key);
        } else if let Some((key, val)) = op.strip_prefix("set:").and_then(|kv| kv.split_once('=')) {
            cmd.env(key, val);
        } else {
            panic!("unknown op {op:?}");
        }
    }
    let out = cmd.output().expect("spawn dump-env-block");
    assert!(
        out.status.success(),
        "dump-env-block failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::io::stdout().write_all(&out.stdout).unwrap();
}
