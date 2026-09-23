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

/// Run `spawn-dump-env-block <backend>` (no ops) in a child whose environment block is exactly
/// `entries`, in order, and relay its exit code.
pub fn spawn_with_block(backend: &str, entries: &[String]) {
    let code = create_with_block(entries, &format!("spawn-dump-env-block {backend}")).expect("CreateProcessW");
    std::process::exit(code as i32);
}

/// Report whether `CreateProcessW` accepts `entries` as a child's block: `ok`, or `err=<code>`
/// with the Win32 error code.
pub fn try_block(entries: &[String]) {
    match create_with_block(entries, "exit 0") {
        Ok(code) => {
            assert_eq!(code, 0, "the probe child failed");
            println!("ok");
        }
        Err(e) => println!("err={}", e.code().0 & 0xFFFF),
    }
}

/// Run `cosca_testbin <args>` with an environment block of exactly `entries`, in order, and wait for
/// its exit code. std's `Command` cannot build such a block (it dedupes and sorts), so this calls
/// `CreateProcessW` itself.
fn create_with_block(entries: &[String], args: &str) -> windows::core::Result<u32> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{CloseHandle, SetHandleInformation, HANDLE_FLAG_INHERIT};
    use windows::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
    use windows::Win32::System::Threading::{
        CreateProcessW, GetExitCodeProcess, WaitForSingleObject, CREATE_UNICODE_ENVIRONMENT, INFINITE,
        PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
    };

    let mut block: Vec<u16> = entries.iter().flat_map(|e| e.encode_utf16().chain([0])).collect();
    block.push(0);
    let exe: Vec<u16> = std::env::current_exe()
        .expect("current_exe")
        .as_os_str()
        .encode_wide()
        .chain([0])
        .collect();
    let mut cmdline: Vec<u16> = format!("cosca_testbin {args}\0").encode_utf16().collect();
    let mut si = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        dwFlags: STARTF_USESTDHANDLES,
        ..Default::default()
    };
    // SAFETY: querying and marking this process's own std handles inheritable; this process is
    // single-threaded and spawns nothing else.
    unsafe {
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE).expect("stdin");
        si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE).expect("stdout");
        si.hStdError = GetStdHandle(STD_ERROR_HANDLE).expect("stderr");
        for h in [si.hStdInput, si.hStdOutput, si.hStdError] {
            if !h.is_invalid() && !h.0.is_null() {
                SetHandleInformation(h, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT).expect("mark inheritable");
            }
        }
    }
    let mut pi = PROCESS_INFORMATION::default();
    // SAFETY: every pointer is live for the call; `cmdline` is mutable and NUL-terminated; `block`
    // is a double-NUL-terminated UTF-16 block, as CREATE_UNICODE_ENVIRONMENT declares.
    unsafe {
        CreateProcessW(
            PCWSTR(exe.as_ptr()),
            Some(PWSTR(cmdline.as_mut_ptr())),
            None,
            None,
            true,
            CREATE_UNICODE_ENVIRONMENT,
            Some(block.as_ptr().cast()),
            PCWSTR::null(),
            &si,
            &mut pi,
        )
    }?;
    let mut code = 0u32;
    // SAFETY: `pi`'s handles are owned here and closed once.
    unsafe {
        WaitForSingleObject(pi.hProcess, INFINITE);
        GetExitCodeProcess(pi.hProcess, &mut code).expect("GetExitCodeProcess");
        CloseHandle(pi.hThread).expect("close thread");
        CloseHandle(pi.hProcess).expect("close process");
    }
    Ok(code)
}
