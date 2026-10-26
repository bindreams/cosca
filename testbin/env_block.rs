//! The `dump-env-block` and `spawn-dump-env-block` modes: the environment block a child receives
//! from each Windows backend, byte for byte. Also `with-env-block`, which runs any mode in a block
//! given entry by entry, `env-set-probe`, which records what `SetEnvironmentVariableW` does to
//! such a block, `spawn-consent-with-block`, which starts `consent-spawn` in a given block, and
//! `try-cwd`, which reports what `CreateProcessW` does with a given `lpCurrentDirectory`.

use windows::core::PCWSTR;
use windows::Win32::System::Environment::{FreeEnvironmentStringsW, GetEnvironmentStringsW};

/// Print this process's environment block in block order, one entry per line, each UTF-16 unit
/// as four hex digits. Read from `GetEnvironmentStringsW`, so casing, order and unpaired
/// surrogates are what the OS holds.
pub fn dump() {
    let units = block_units();
    let mut lines = String::new();
    for entry in units.split(|&u| u == 0).take_while(|e| !e.is_empty()) {
        let hex: String = entry.iter().map(|u| format!("{u:04x}")).collect();
        lines.push_str(&hex);
        lines.push('\n');
    }
    crate::quiet_io::put_stdout(lines.as_bytes(), "dump-env-block: write stdout");
}

/// This process's environment block, UTF-16LE, through the empty entry that closes it.
pub fn block_bytes() -> Vec<u8> {
    block_units().iter().flat_map(|u| u.to_le_bytes()).collect()
}

/// This process's environment block as UTF-16 units, through the empty entry that closes it. The
/// one place in this file that reads the raw block.
fn block_units() -> Vec<u16> {
    // SAFETY: no preconditions; the block is freed below.
    let block = unsafe { GetEnvironmentStringsW() };
    assert!(!block.is_null(), "GetEnvironmentStringsW failed");
    // SAFETY: the block is a run of NUL-terminated entries closed by an empty one, so every read up
    // to the first two NULs in a row is in bounds.
    let end = (1..)
        .find(|&i| unsafe { *block.0.add(i - 1) == 0 && *block.0.add(i) == 0 })
        .unwrap();
    // SAFETY: the `end + 1` units starting at `block` were just read.
    let units = unsafe { std::slice::from_raw_parts(block.0, end + 1) }.to_vec();
    // SAFETY: `block` came from `GetEnvironmentStringsW` and is freed once.
    unsafe { FreeEnvironmentStringsW(PCWSTR(block.0)) }.expect("FreeEnvironmentStringsW");
    units
}

/// Spawn `dump-env-block` through cosca's `backend` (`raw` or `std`) after replaying `ops`, and
/// relay its output. An op is `set:KEY=VAL`, `remove:KEY`, `clear`, or `contain`.
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
        if op == "contain" {
            cmd.contain();
        } else if op == "clear" {
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
    crate::quiet_io::put_stdout(&out.stdout, "spawn-dump-env-block: write stdout");
}

/// Run `spawn-dump-env-block <dump_args>` in a child whose environment block is exactly `entries`,
/// in order, and relay its exit code. `dump_args` is the backend and any ops, space-separated.
pub fn spawn_with_block(dump_args: &str, entries: &[String]) {
    let code = create_with_block(entries, &format!("spawn-dump-env-block {dump_args}"), None).expect("CreateProcessW");
    std::process::exit(code as i32);
}

/// `spawn-consent-with-block <report> <envdump> <own-envdump> <dir> <block-file>`: run `consent-spawn`
/// with the first four arguments in a child whose environment block is exactly the entries of
/// `<block-file>`, in order, and relay its exit code. Each entry in the file ends in a NUL. The block
/// goes through a file because a whole inherited environment can exceed the command line's 32767 units.
pub fn spawn_consent_with_block(args: &[String]) {
    let [report, env_dump, own_dump, dir, block_file] = args else {
        panic!("spawn-consent-with-block <report> <envdump> <own-envdump> <dir> <block-file>, got {args:?}");
    };
    let block = std::fs::read_to_string(block_file).expect("read the block file");
    let entries: Vec<String> = block.split_terminator('\0').map(str::to_owned).collect();
    let line: Vec<String> = ["consent-spawn", report, env_dump, own_dump, dir]
        .iter()
        .map(|a| quote(a))
        .collect();
    let code = create_with_block(&entries, &line.join(" "), None).expect("CreateProcessW");
    std::process::exit(code as i32);
}

/// `with-env-block [--cwd <dir>] <entries>... -- <args>...`: run `cosca_testbin <args>` in a child
/// given exactly `entries`, in order, as its environment block, and exit with its exit code. The
/// child runs in `<dir>`, passed as `lpCurrentDirectory`, or without `--cwd` in this process's cwd.
/// Windows on Arm adds `PROCESSOR_ARCHITECTURE` to that block on its own.
pub fn with_block(args: &[String]) {
    let (cwd, args) = match args {
        [flag, cwd, rest @ ..] if flag == "--cwd" => (Some(cwd.as_str()), rest),
        _ => (None, args),
    };
    let split = args
        .iter()
        .position(|a| a == "--")
        .expect("with-env-block needs `--` before the mode");
    let line: Vec<String> = args[split + 1..].iter().map(|a| quote(a)).collect();
    let code = create_with_block(&args[..split], &line.join(" "), cwd).expect("CreateProcessW");
    std::process::exit(code as i32);
}

/// `arg` quoted for the command line, as the CRT and `CommandLineToArgvW` parse it back.
fn quote(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        return arg.to_owned();
    }
    let mut out = String::from('"');
    let mut backslashes = 0;
    for c in arg.chars() {
        if c == '\\' {
            backslashes += 1;
            continue;
        }
        let escaped = if c == '"' { backslashes * 2 + 1 } else { backslashes };
        out.push_str(&"\\".repeat(escaped));
        out.push(c);
        backslashes = 0;
    }
    out.push_str(&"\\".repeat(backslashes * 2));
    out.push('"');
    out
}

/// `env-set-probe <op>...`: dump this process's block under `# before`, then apply each op to this
/// process's own environment with `SetEnvironmentVariableW` and dump it again under
/// `# after <op>`. An op is `set:NAME=VALUE` or `remove:NAME`.
pub fn set_probe(ops: &[String]) {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::System::Environment::SetEnvironmentVariableW;

    let wide = |s: &str| std::ffi::OsStr::new(s).encode_wide().chain([0]).collect::<Vec<u16>>();
    println!("# before");
    dump();
    for op in ops {
        let (name, value) = if let Some(kv) = op.strip_prefix("set:") {
            let (name, value) = kv.split_once('=').expect("set:NAME=VALUE");
            (wide(name), Some(wide(value)))
        } else if let Some(name) = op.strip_prefix("remove:") {
            (wide(name), None)
        } else {
            panic!("unknown op {op:?}");
        };
        let value = value.as_ref().map_or(PCWSTR::null(), |v| PCWSTR(v.as_ptr()));
        // SAFETY: `name` and `value` are NUL-terminated and outlive the call.
        unsafe { SetEnvironmentVariableW(PCWSTR(name.as_ptr()), value) }.expect("SetEnvironmentVariableW");
        println!("# after {op}");
        dump();
    }
}

/// Report whether `CreateProcessW` accepts `entries` as a child's block: `ok`, or `err=<code>`
/// with the Win32 error code.
pub fn try_block(entries: &[String]) {
    match create_with_block(entries, "exit 0", None) {
        Ok(code) => {
            assert_eq!(code, 0, "the probe child failed");
            outln!("ok");
        }
        Err(e) => outln!("err={}", e.code().0 & 0xFFFF),
    }
}

/// `try-cwd <dir>`: run `cosca_testbin cwd` through a bare `CreateProcessW` with `<dir>` as its
/// `lpCurrentDirectory`. The child prints its cwd, then this prints `ok`; if the call fails it prints
/// `err=<code>` with the Win32 error code instead.
pub fn try_cwd(dir: &str) {
    let system_root = format!("SystemRoot={}", std::env::var("SystemRoot").expect("SystemRoot"));
    match create_with_block(&[system_root], "cwd", Some(dir)) {
        Ok(code) => {
            assert_eq!(code, 0, "the probe child failed");
            outln!("ok");
        }
        Err(e) => outln!("err={}", e.code().0 & 0xFFFF),
    }
}

/// Run `cosca_testbin <args>` with an environment block of exactly `entries`, in order, in `cwd` (or
/// this process's cwd for `None`), and wait for its exit code. std's `Command` cannot build such a
/// block (it dedupes and sorts), so this calls `CreateProcessW` itself.
fn create_with_block(entries: &[String], args: &str, cwd: Option<&str>) -> windows::core::Result<u32> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{CloseHandle, SetHandleInformation, HANDLE_FLAG_INHERIT};
    use windows::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
    use windows::Win32::System::Threading::{
        CreateProcessW, GetExitCodeProcess, WaitForSingleObject, CREATE_UNICODE_ENVIRONMENT, INFINITE,
        PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
    };

    let mut block: Vec<u16> = entries.iter().flat_map(|e| e.encode_utf16().chain([0])).collect();
    // An empty block is two NULs, as std writes one.
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    let cwd: Option<Vec<u16>> = cwd.map(|c| c.encode_utf16().chain([0]).collect());
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
            cwd.as_ref().map_or(PCWSTR::null(), |c| PCWSTR(c.as_ptr())),
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
