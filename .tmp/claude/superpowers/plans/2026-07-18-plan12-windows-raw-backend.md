# Plan 12 — Windows raw `CreateProcessW` backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Lift the two Windows-only `Unsupported` rejections `std::process` cannot express — `fd(n≥3)` and `executable()`+`commandline()` (plus the `executable()`-alone argv[0] degradation) — via a raw `CreateProcessW` backend on both the sync and async surfaces.

**Architecture:** A `#[cfg(windows)]` raw spawn path, routed ONLY when the std path can't express the request (`executable()` set OR any fd ≥ 3). A process-handle enum (`ProcHandle` sync / `ProcSource` async) lets the raw child coexist with `SharedChild`/`tokio::process::Child`. EVERY raw spawn sets `STARTF_USESTDHANDLES` + `hStd*` (wires 0/1/2) and a `STARTUPINFOEX` `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` (scopes inheritance to exactly its own child ends); fd ≥ 3 additionally rides the MSVCRT `lpReserved2` fd-table. `lpApplicationName` is set independently of `lpCommandLine`, only when `executable()` is set. A crate-wide, poison-tolerant spawn mutex serializes the brief mark-inheritable→spawn window across raw AND std paths. Containment reuses `attach_job`; sync and async raw waits share one handle-based cancellable primitive.

**Tech Stack:** Rust (MSRV 1.87). Existing `windows` 0.62 dep (add Threading/attribute-list/wait/`Win32_Storage_FileSystem` items). No new crate deps (a `which` evaluation is recorded in Task 3; a small local resolver is used). Existing `shared_child`, `tokio`, `libc`.

## Global Constraints

- Spec: `.tmp/claude/superpowers/specs/2026-07-18-plan12-windows-raw-backend-design.md`.
- **Windows is the PRIMARY runtime** (host is Windows 11): after each task run `cargo test --locked` and `cargo test --locked --features tokio` on the host. **Unix untouched** — after each task also run the WSL suite: `MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-24.04 -- bash -lc 'cd /mnt/c/Users/bindreams/src/subprocess && export CARGO_TARGET_DIR=/tmp/sp-target && cargo test --locked --features tokio && cargo test --locked'`. Pipe long outputs to files under `.tmp/claude/`; never `| tail`.
- **No-time-sync test discipline:** exits and wait-cancellation are proven by pipe EOF, an inspected `ExitStatus`, or an event-driven channel/`Notify` signal — never a sleep/poll/wall-clock. No arbitrary retry/loop caps. Tests never skip on a missing dependency: the one console-adjacent case is made deterministic via the `NUL` char device (no console provisioning needed).
- **Routing invariant:** `needs_raw == (cmd.executable_path().is_some() || fds.keys().any(|f| f.raw() >= 3))`. When false, the std/tokio path is byte-for-byte unchanged.
- **Inheritance safety:** the raw path holds a crate-wide **poison-tolerant** spawn mutex (`crate::child::spawn::spawn_lock()`, `.lock().unwrap_or_else(|e| e.into_inner())`) across the mark-inheritable → `CreateProcessW` → **close-child-ends** window, and the child ends are closed BEFORE the guard is released on EVERY exit path (success and error). The std/tokio paths take the SAME lock around their `spawn()` call. Every raw spawn passes `bInheritHandles=TRUE` scoped by a `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` naming exactly its child ends. (Residual race vs. spawns outside this crate is documented, matching std's own residual.)
- **`executable()` resolution rule (a deliberate, documented rule — NOT byte-parity with CreateProcessW's full 6-location search):** an absolute+existing `executable()` is used as-is; a bare/relative name is resolved against **[parent cwd, then each PATH dir]**, appending `.exe` when it has no extension, first hit wins. Only set on the raw path when `executable()` is set; the fd ≥ 3-only route leaves `lpApplicationName` NULL so `CreateProcessW` resolves `lpCommandLine`'s first token itself (matching std). `.bat`/`.cmd` programs are a loud `Unsupported` on the raw path too (`reject_batch_program`, CVE-2024-24576), checked BEFORE resolution.
- **Loud, never silent:** DETECTABLE cases stay loud `Unsupported` and are tested — `Stdio::inherit()` on fd ≥ 3 (also hardened in `inherit_end`), chained merges, `.bat`/`.cmd`. An oversized fd-table (checked **analytically before allocation**, `> u16::MAX` bytes), any embedded-NUL in a program/arg/**cwd**/env string, and a `SetHandleInformation` failure are loud `Error`s. Every discarded FFI `Result` in a Drop/best-effort path carries a `log::debug!` (and `debug_assert!` only where a panic cannot poison a held lock).
- **fd ≥ 3 is MSVC/UCRT-children faithful** (spec §divergence). For a non-MSVCRT child the handles are still inherited but that foreign CRT won't expose them as numbered fds — inherent, **documented**, NOT a detectable rejection.
- **Unsafe hygiene:** every `unsafe` block carries a `// SAFETY:` note. All owned handles are RAII (`OwnedHandle`/`ChildEnd`/`ParentEnd`).
- Before every commit: `cargo +stable fmt --check`; `cargo clippy --locked --features tokio --all-targets`; `cargo clippy --locked --all-targets`; `prek run --all-files` (docs LF; normalize before `git add`).
- Single-line commit messages. Rust style: `foo.rs` + `foo/` modules; unit tests in sibling `*_tests.rs`.
- Branch `azhukova/<issue#>`; never commit to `main`. Never `git add -A` — stage explicit paths; `git add -f` the plan/spec under `.tmp/claude/superpowers/`.

---

### Task 1: testbin fd-relay + argv0 + isatty report modes

**Files:** Modify `testbin/main.rs`, `Cargo.toml` (windows-target `libc` for the testbin), `tests/raw_windows.rs` (new)

**Interfaces (testbin CLI):** `read-fd <n>` (copy fd n → stdout); `write-fd <n> <text>`; `argv0-report` (`argv0=<argv[0]>` + `image=<current_exe()>`); `isatty-fd <n>` (`isatty=<0|1>` via `libc::isatty(n)`).

- [ ] **Step 1: Read `testbin/main.rs`** to match its `args[1]` dispatch.

- [ ] **Step 2: Write the failing test** — new `tests/raw_windows.rs`:

```rust
#![cfg(windows)]
mod common;
#[test]
fn testbin_argv0_report_echoes_argv0() {
    let out = std::process::Command::new(common::testbin())
        .args(["subprocess_testbin", "argv0-report"]).output().expect("spawn");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("argv0=subprocess_testbin") && s.contains("image="), "got: {s}");
}
```

- [ ] **Step 3: Run it, expect FAIL** — `cargo test --locked --test raw_windows testbin_argv0_report`.

- [ ] **Step 4: Implement the modes** — CRT-fd → `File`:

```rust
#[cfg(windows)]
fn file_from_fd(fd: i32) -> std::fs::File {
    use std::os::windows::io::{FromRawHandle, RawHandle};
    let h = unsafe { libc::get_osfhandle(fd) };
    assert!(h != -1, "fd {fd} not wired into the CRT fd table");
    unsafe { std::fs::File::from_raw_handle(h as RawHandle) }
}
#[cfg(unix)]
fn file_from_fd(fd: i32) -> std::fs::File {
    use std::os::fd::{FromRawFd, RawFd};
    unsafe { std::fs::File::from_raw_fd(fd as RawFd) }
}
```

`read-fd`=`io::copy(fd→stdout)`; `write-fd`=write; `argv0-report`=the two lines; `isatty-fd <n>`=`println!("isatty={}", unsafe { libc::isatty(n) })`. `std::mem::forget` each `File` after use.

- [ ] **Step 5: Run tests, expect PASS**; then `cargo test --locked`.

- [ ] **Step 6: Commit** — `git add testbin/main.rs Cargo.toml tests/raw_windows.rs && git commit -m "test: testbin fd-relay + argv0 + isatty modes for the raw backend"`

---

### Task 2: MSVCRT `lpReserved2` fd-table encoder + device classifier

**Files:** Create `src/child/spawn/windows_raw.rs` (module root, `#[cfg(windows)]`), `src/child/spawn/windows_raw/crt_fds.rs` (+ `crt_fds_tests.rs`)

**Interfaces:**
- `enum FdKind { Pipe, File, CharDev }`; `pub(crate) fn classify(h: HANDLE) -> Result<FdKind, Error>` — `GetFileType`: `FILE_TYPE_PIPE→Pipe`, `FILE_TYPE_CHAR→CharDev`, `FILE_TYPE_DISK→File`; on `FILE_TYPE_UNKNOWN` inspect `GetLastError` — nonzero → `Error::Io`, `NO_ERROR` → `File`.
- `pub(crate) struct FdTable { pub bytes: Vec<u8>, pub handles: Vec<HANDLE> }`; `pub(crate) fn encode(entries:&BTreeMap<Fd,(HANDLE,FdKind)>) -> FdTable`. `pub(crate) fn encoded_len(maxfd: i32) -> usize` computed with **overflow-safe** arithmetic — `usize::try_from(maxfd).ok().and_then(|m| m.checked_add(1)).and_then(|n| n.checked_mul(1 + size_of::<HANDLE>())).and_then(|x| x.checked_add(4)).unwrap_or(usize::MAX)` — so an `i32::MAX` fd or a 32-bit `usize` multiply saturates to `usize::MAX` and `table_fits` cleanly rejects (never a wrap-to-small that lets a giant `encode` allocation through). `pub(crate) fn table_fits(byte_len: usize) -> bool` (`<= u16::MAX`).

- [ ] **Step 1: Write the failing tests** — `crt_fds_tests.rs` (layout + size-cap boundary + **`classify` on an invalid handle**):

```rust
use super::*;
use std::collections::BTreeMap;
use crate::stdio::Fd;
const FOPEN: u8 = 0x01; const FPIPE: u8 = 0x08; const HSZ: usize = std::mem::size_of::<*mut core::ffi::c_void>();
fn h(v: isize) -> windows::Win32::Foundation::HANDLE { windows::Win32::Foundation::HANDLE(v as _) }

#[test]
fn encodes_count_flags_and_handles_for_fd3() {
    let mut m = BTreeMap::new();
    for (n,v) in [(0i32,10isize),(1,11),(2,12)] { m.insert(Fd::from_raw(n),(h(v),FdKind::CharDev)); }
    m.insert(Fd::from_raw(3),(h(99),FdKind::Pipe));
    let t = encode(&m);
    assert_eq!(&t.bytes[0..4], &4i32.to_le_bytes());
    assert_eq!(t.bytes[4+3] & (FOPEN|FPIPE), FOPEN|FPIPE);
    assert_eq!(t.bytes.len(), 4 + 4 + 4*HSZ);
    assert_eq!(t.bytes.len(), encoded_len(3));
    assert_eq!(t.handles.len(), 4);
}
#[test]
fn interior_gap_is_invalid_handle_and_zero_flag() {
    let mut m = BTreeMap::new();
    m.insert(Fd::from_raw(3),(h(30),FdKind::Pipe)); m.insert(Fd::from_raw(5),(h(50),FdKind::File));
    let t = encode(&m);
    assert_eq!(&t.bytes[0..4], &6i32.to_le_bytes());
    assert_eq!(t.bytes[4+4], 0);
    let off = 4 + 6 + 4*HSZ;
    assert_eq!(&t.bytes[off..off+HSZ], &(-1isize as usize).to_ne_bytes()[..]);
    assert_eq!(t.handles.len(), 2);
}
#[test]
fn cap_computed_len_boundary_and_overflow_safe() {
    assert!(table_fits(encoded_len(10)));
    // exact boundary: the largest maxfd whose encoded_len <= u16::MAX fits; the next does not.
    let hsz = std::mem::size_of::<*mut core::ffi::c_void>();
    let max_n = (u16::MAX as usize - 4) / (1 + hsz);       // N slots fit
    assert!(table_fits(encoded_len((max_n - 1) as i32)));
    assert!(!table_fits(encoded_len((max_n + 8) as i32)));
    // overflow-safe: i32::MAX must saturate, not panic/wrap, and cleanly reject.
    assert_eq!(encoded_len(i32::MAX), usize::MAX);
    assert!(!table_fits(encoded_len(i32::MAX)));
}
#[test]
fn classify_invalid_handle_is_error() {
    // An invalid handle drives GetFileType -> FILE_TYPE_UNKNOWN with a nonzero GetLastError.
    assert!(classify(windows::Win32::Foundation::INVALID_HANDLE_VALUE).is_err());
}
```

- [ ] **Step 2: Run, expect FAIL** — `cargo test --locked crt_fds`.

- [ ] **Step 3: Implement.** `encode`: `N=maxfd+1`; present fd → flag `FOPEN|kind_bits`, handle + push to `handles`; absent → flag `0`, `INVALID_HANDLE_VALUE`. Flags `FOPEN=0x01,FPIPE=0x08,FDEV=0x40`. `classify` per interface. `encoded_len`/`table_fits` per interface (used by Task 5 to check the cap BEFORE `encode` allocates). Add `Fd::from_raw(i32)` to `src/stdio.rs` if absent.

- [ ] **Step 4: Run, expect PASS** — `cargo test --locked crt_fds`.

- [ ] **Step 5: Commit** — `git add src/child/spawn/windows_raw.rs src/child/spawn/windows_raw/ src/stdio.rs && git commit -m "feat: MSVCRT lpReserved2 fd-table encoder + GetFileType classifier + pre-alloc size cap"`

---

### Task 3: `executable()` resolution, env block, NUL guard

**Files:** Create `src/child/spawn/windows_raw/resolve.rs` (+ `resolve_tests.rs`)

**Interfaces:**
- `pub(crate) fn resolve_executable_in(exe:&Path, base_cwd:&Path, path:Option<&OsStr>) -> Result<PathBuf, Error>` — the testable core (absolute+exists → as-is; else search `[base_cwd] ++ path`, appending `.exe` if no extension; `Error::Io(NotFound)` on miss) — and `pub(crate) fn resolve_executable(exe:&Path) -> Result<PathBuf, Error>` = the core with `std::env::current_dir()?` + `PATH`. **Tests drive the core with an explicit base dir — never `SetCurrentDirectory` (process-global; would race parallel tests).**
- `pub(crate) fn build_env_block_from(base:&[(OsString,OsString)], ops:&[EnvOp]) -> Result<Option<Vec<u16>>, Error>` and `pub(crate) fn build_env_block(ops:&[EnvOp]) -> Result<Option<Vec<u16>>, Error>` (former seeded from `std::env::vars_os()`). `Ok(None)` when `ops` is empty (inherit); else the sorted, wide, double-NUL block; `Err` on embedded NUL. **Tests use `build_env_block_from` with a fixed base — never mutate global env.**
- `pub(crate) fn ensure_no_nul_wide(s: &OsStr) -> Result<(), Error>` (`Error::Io(InvalidInput)`).

**Dependency evaluation (recorded):** `which` v7 was evaluated but honors the full `PATHEXT` in `PATHEXT` order, diverging from what we want for `executable()` (a small `.exe`-appending cwd+PATH rule that keeps `.bat`/`.cmd` out of resolution so `reject_batch_program` owns that rejection). A minimal local resolver is used (evaluate-then-local pattern, cf. Plan 11 `kinfo`). No new dependency.

- [ ] **Step 1: Write the failing tests** — `resolve_tests.rs` (base-cwd shadow via an explicit base dir; env via fixed base — no global-state mutation anywhere):

```rust
use super::*;
use crate::command::EnvOp;
use std::ffi::OsString;

#[test]
fn resolve_absolute_existing_is_returned_as_is() {
    let me = std::env::current_exe().unwrap();
    assert_eq!(resolve_executable(&me).unwrap(), me);
}
#[test]
fn resolve_bare_name_prefers_base_cwd_over_path() {
    let dir = tempfile::tempdir().unwrap();
    let shadow = dir.path().join("sp_shadow.exe");
    std::fs::copy(std::env::current_exe().unwrap(), &shadow).unwrap();
    // Explicit base dir — no process-global SetCurrentDirectory, so parallel tests can't race.
    let got = resolve_executable_in(std::path::Path::new("sp_shadow"), dir.path(), None).unwrap();
    assert_eq!(got.canonicalize().unwrap(), shadow.canonicalize().unwrap());
}
#[test]
fn resolve_bare_name_appends_exe_from_path() {
    let p = resolve_executable(std::path::Path::new("cmd")).unwrap();
    assert!(p.is_absolute() && p.exists() && p.extension().is_some_and(|e| e.eq_ignore_ascii_case("exe")), "{p:?}");
}
#[test]
fn empty_ops_inherit() { assert!(build_env_block(&[]).unwrap().is_none()); }
#[test]
fn set_sorts_ci_and_double_nul() {
    let b = build_env_block_from(&[], &[EnvOp::Set("Zeta".into(),"1".into()), EnvOp::Set("alpha".into(),"2".into())]).unwrap().unwrap();
    assert_eq!(&b[b.len()-2..], &[0u16,0u16]);
    let s = String::from_utf16(&b).unwrap();
    assert!(s.find("alpha=").unwrap() < s.find("Zeta=").unwrap(), "{s:?}");
}
#[test]
fn remove_is_case_insensitive() {
    let b = build_env_block_from(&[(OsString::from("SP_R"),OsString::from("x"))], &[EnvOp::Remove("sp_r".into())]).unwrap().unwrap();
    assert!(!String::from_utf16(&b).unwrap().to_uppercase().contains("SP_R="));
}
#[test]
fn clear_then_set_yields_only_the_set_var() {
    let b = build_env_block_from(&[(OsString::from("PATH"),OsString::from("x"))], &[EnvOp::Clear, EnvOp::Set("ONLYME".into(),"1".into())]).unwrap().unwrap();
    let s = String::from_utf16(&b).unwrap();
    assert!(s.contains("ONLYME=1") && !s.to_uppercase().contains("PATH="));
}
#[test]
fn embedded_nul_is_rejected() {
    let e = build_env_block_from(&[], &[EnvOp::Set("K".into(), OsString::from("a\u{0}b"))]).unwrap_err();
    assert!(matches!(e, crate::error::Error::Io(_)));
}
```

- [ ] **Step 2: Run, expect FAIL** — `cargo test --locked resolve_ set_ remove_ clear_ embedded_ empty_ops`.

- [ ] **Step 3: Implement** per the interfaces (`resolve_executable` search `[current_dir()?] ++ PATH`; `build_env_block_from` seeds a `BTreeMap<upper(key),(key,val)>`, applies Set/Remove/Clear, `ensure_no_nul_wide` each, emits sorted `KEY=VAL\0` + trailing `\0`).

- [ ] **Step 4: Run, expect PASS** — same filter.

- [ ] **Step 5: Commit** — `git add src/child/spawn/windows_raw/ && git commit -m "feat: raw-path executable resolution + env block + NUL guard"`

---

### Task 4: sync backend enum + `RawChild` + poison-tolerant spawn lock + raw spawn (executable path)

**Files:** Create `src/child/proc_handle.rs`; Modify `src/child.rs`, `src/child/spawn/windows_raw.rs`, `src/child/spawn.rs` (routing + `spawn_lock()` + wrap std spawn + harden `inherit_end`), `Cargo.toml`, `tests/raw_windows.rs`

**Interfaces:**
- `enum ProcHandle { Std(SharedChild), #[cfg(windows)] Raw(windows_raw::RawChild) }` + `wait`/`try_wait`/`kill`/`id`.
- `struct RawChild { proc: OwnedHandle, pid: u32 }` + `wait`/`try_wait`/`kill`/`id`/`process_handle`.
- `pub(crate) fn spawn_lock() -> std::sync::MutexGuard<'static,()>` over a crate `static SPAWN_MUTEX: Mutex<()>`, acquired **poison-tolerantly** (`.lock().unwrap_or_else(|e| e.into_inner())`) — held across the inheritable→spawn→close window on the raw path AND around `std_cmd.spawn()`/`tcmd.spawn()`.
- `pub(crate) enum WaitOutcome { Exited, Cancelled }`; `pub(crate) fn wait_handle_or_cancel(proc: HANDLE, cancel: Option<HANDLE>) -> io::Result<WaitOutcome>`.
- `pub(crate) fn create_process(app: Option<&[u16]>, cmdline:&mut Vec<u16>, si:&mut STARTUPINFOEXW, env:&Option<Vec<u16>>, cwd:&Option<Vec<u16>>, flags:u32) -> Result<(OwnedHandle,u32), Error>` (shared by sync/async; sets `si.StartupInfo.cb`; caller pre-fills `dwFlags`/`hStd*`/attribute list).
- `pub(crate) fn spawn_raw(cmd:&Command, fds:BTreeMap<Fd,ResolvedStdio>, kill_on_drop:bool) -> Result<Child, Error>`.

- [ ] **Step 1: Write the failing tests** (executable≠argv0; end-to-end embedded-NUL; batch rejection via a REAL `.bat`; embedded-NUL cwd):

```rust
#[test]
fn executable_independent_of_argv0_on_windows() {
    let exe = common::testbin();
    let mut c = subprocess::Command::new();
    c.executable(&exe).commandline("pretend-name argv0-report").stdout(subprocess::Stdio::pipe()).unwrap();
    let mut child = c.spawn().expect("raw spawn");
    let mut s = String::new();
    std::io::Read::read_to_string(&mut child.stdout().unwrap(), &mut s).unwrap();
    child.wait().unwrap();
    assert!(s.contains("argv0=pretend-name") && s.to_lowercase().contains("testbin"), "{s}");
}
#[test]
fn embedded_nul_in_commandline_is_rejected() {
    let e = subprocess::Command::new().executable(common::testbin()).commandline("a\u{0}b").spawn().unwrap_err();
    assert!(matches!(e, subprocess::error::Error::Io(_)), "{e:?}");
}
#[test]
fn embedded_nul_in_cwd_is_rejected() {
    let mut c = subprocess::Command::new();
    c.executable(common::testbin()).commandline("x argv0-report").current_dir(std::path::PathBuf::from("a\u{0}b"));
    assert!(matches!(c.spawn().unwrap_err(), subprocess::error::Error::Io(_)));
}
#[test]
fn batch_script_via_executable_is_unsupported() {
    let dir = tempfile::tempdir().unwrap();
    let bat = dir.path().join("x.bat");
    std::fs::write(&bat, b"@echo off\n").unwrap();
    let e = subprocess::Command::new().executable(&bat).commandline("x.bat").spawn().unwrap_err();
    assert!(matches!(e, subprocess::error::Error::Unsupported{..}), "{e:?}");
}
```

- [ ] **Step 2: Run, expect FAIL** — `cargo test --locked --features tokio --test raw_windows executable_independent embedded_nul batch_script_via_executable`.

- [ ] **Step 3: Refactor `Child` onto `ProcHandle`** (pure refactor; forward the four methods + Drop). Add `spawn_lock()` (poison-tolerant) and wrap `std_cmd.spawn()` in `src/child/spawn.rs` with `let _g = spawn_lock();`. Run `cargo test --locked` + WSL → green.

- [ ] **Step 4: Implement `wait_handle_or_cancel` + `RawChild`** — `wait_handle_or_cancel`: `Some(cancel)`→`WaitForMultipleObjects(&[proc,cancel],FALSE,INFINITE)` (idx0 `Exited`, idx1 `Cancelled`, `WAIT_FAILED`→Err); `None`→`WaitForSingleObject(proc,INFINITE)`. `RawChild::wait`=it with `None`+`GetExitCodeProcess`; `try_wait`=`WaitForSingleObject(h,0)`; `kill`=`TerminateProcess(h,1)` with an already-exited failure mapped to `Ok(())`.

- [ ] **Step 5: Implement `spawn_raw`** — order: **reject-batch (before resolve)** → resolve → NUL-check (program, cwd, argv/commandline components) → resolve stdio → build STARTUPINFOEXW (`USESTDHANDLES`+`hStd*`+attr list) → spawn under the lock closing child ends on every path → teardown-symmetric identity/attach.

```rust
pub(crate) fn spawn_raw(cmd: &Command, fds: BTreeMap<Fd, ResolvedStdio>, kill_on_drop: bool) -> Result<Child, Error> {
    // .bat/.cmd rejected on the raw program token BEFORE resolution (a bad/nonexistent path still errors loudly).
    reject_batch_program(cmd)?;                                   // checks executable() ext, else commandline/argv[0] token
    let image: Option<PathBuf> = cmd.executable_path().map(resolve::resolve_executable).transpose()?;
    if let Some(p) = &image { resolve::ensure_no_nul_wide(p.as_os_str())?; }
    if let Some(c) = cmd.cwd() { resolve::ensure_no_nul_wide(c.as_os_str())?; }
    let app_name: Option<Vec<u16>> = image.as_ref().map(|p| to_wide_nul(p.as_os_str()));
    let mut cmdline = raw_program_and_line(cmd)?;                 // each token ensure_no_nul_wide'd
    cmdline.push(0);
    let env_block = resolve::build_env_block(cmd.env_ops())?;     // Task 6 may add the contain marker
    let cwd_w = cmd.cwd().map(|c| to_wide_nul(c.as_os_str()));

    let slots = [Fd::STDIN, Fd::STDOUT, Fd::STDERR];             // Task 5 adds fd>=3
    let (child_ends, parent_ends) = resolve_stdio(&fds, &slots, PipeOwnership::Owned)?;

    // STARTUPINFOEXW: cb, STARTF_USESTDHANDLES + hStd* for 0/1/2, and an attribute list of exactly our
    // child ends. hStd* wires the child's stdio; the HANDLE_LIST scopes inheritance AND backs
    // EXTENDED_STARTUPINFO_PRESENT. (Task 5 adds fd>=3 handles to the list + lpReserved2.)
    let mut si = STARTUPINFOEXW::default();
    si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    si.StartupInfo.dwFlags |= windows::Win32::System::Threading::STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput  = HANDLE(child_ends[&Fd::STDIN ].as_raw_handle());
    si.StartupInfo.hStdOutput = HANDLE(child_ends[&Fd::STDOUT].as_raw_handle());
    si.StartupInfo.hStdError  = HANDLE(child_ends[&Fd::STDERR].as_raw_handle());
    let all_handles: Vec<HANDLE> = child_ends.values().map(|e| HANDLE(e.as_raw_handle())).collect(); // 0/1/2, all distinct; Task 5 REPLACES with table.handles
    let attr = build_attribute_list(&all_handles)?;              // Init/Update; Delete after spawn (both paths)
    si.lpAttributeList = attr.ptr();
    let contain_flags = 0u32;                                    // Task 6 sets this
    let flags = CREATE_UNICODE_ENVIRONMENT.0 | EXTENDED_STARTUPINFO_PRESENT.0 | contain_flags;

    // UNDER THE LOCK: mark listed child ends inheritable, spawn, then CLOSE child ends BEFORE the guard
    // releases on EVERY path. `spawn_step` returns a Result WITHOUT `?`-ing past the close.
    let (proc, pid) = {
        let _guard = crate::child::spawn::spawn_lock();
        let r = spawn_step(&all_handles, &app_name, &mut cmdline, &mut si, &env_block, &cwd_w, flags);
        drop(child_ends);   // close inside the lock on success AND error
        drop(attr);         // DeleteProcThreadAttributeList
        r
    }?;
    // identity read + attach_or_fault(pid, proc.as_raw_handle(), prepared) BEFORE building Child, with the
    // SAME kill+reap error-teardown arms as src/child/spawn.rs:121-162 (dropping the OwnedHandle alone
    // neither kills nor reaps on Windows).
    // Child::from_parts(ProcHandle::Raw(RawChild{proc,pid}), id, parent_ends, kill_on_drop, containment, attached)
}
// spawn_step: for h in all_handles { set_inherit(h,true)?; }  then create_process(...). Returns Result; the
// caller drops child_ends+attr AFTER it returns (both arms) so no inheritable handle outlives the lock.
```

`create_process` (shared FFI; async reuses it):

```rust
use windows::Win32::System::Threading::{CreateProcessW, PROCESS_INFORMATION, PROCESS_CREATION_FLAGS,
    CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT};
use windows::core::{PCWSTR, PWSTR};
let mut pi = PROCESS_INFORMATION::default();
let app = app.map_or(PCWSTR::null(), |w| PCWSTR(w.as_ptr()));
let cwd = cwd.as_ref().map_or(PCWSTR::null(), |w| PCWSTR(w.as_ptr()));
// SAFETY: pointers valid for the call; cmdline is a mutable NUL-terminated buffer CreateProcessW may edit.
unsafe { CreateProcessW(app, Some(PWSTR(cmdline.as_mut_ptr())), None, None, true,
    PROCESS_CREATION_FLAGS(flags), env.as_ref().map(|b| b.as_ptr() as *const _), cwd,
    &si.StartupInfo, &mut pi) }.map_err(Error::Io)?;
let proc = unsafe { OwnedHandle::from_raw_handle(pi.hProcess.0 as _) };
// SAFETY: hThread is owned + unneeded. Under the spawn lock, so log-only (a debug_assert!(false) here would
// poison the lock and cascade to every future spawn).
if let Err(e) = unsafe { windows::Win32::Foundation::CloseHandle(pi.hThread) } { log::debug!("CloseHandle(hThread): {e:?}"); }
```

`reject_batch_program`: extension check on `executable()` if set, else the commandline/argv[0] first token — reuse `reject_batch_script`'s logic. `raw_program_and_line`: `commandline()` → argv[0]=`first_token_wide`, full line; `argv` → `join_wide`; each token `ensure_no_nul_wide`; argv[0] is always the user's name.

- [ ] **Step 6: Route + harden** in `src/child/spawn.rs`:

```rust
#[cfg(windows)]
if cmd.executable_path().is_some() || fds.keys().any(|f| f.raw() >= 3) {
    return windows_raw::spawn_raw(cmd, fds, kill_on_drop);
}
```

Remove the old fd≥3 loop + the `build_from_commandline` executable rejection. **Harden `inherit_end`'s Windows arm (`src/child/spawn.rs:506-524`)** to reject fd ≥ 3 (mirror the Unix arm).

- [ ] **Step 7: Run, expect PASS** — the four new tests; then `cargo test --locked` + `--features tokio`; then WSL both.

- [ ] **Step 8: Commit** — `git add src/child.rs src/child/proc_handle.rs src/child/spawn.rs src/child/spawn/windows_raw.rs Cargo.toml tests/raw_windows.rs && git commit -m "feat: sync raw CreateProcessW backend — executable/argv0, USESTDHANDLES, poison-tolerant spawn lock"`

---

### Task 5: sync fd ≥ 3 (`lpReserved2` + HANDLE_LIST) + inherit guard + pre-alloc cap + device-class tests

**Files:** Modify `src/child/spawn/windows_raw.rs`, `tests/raw_windows.rs`; consumes `crt_fds::{encode, classify, encoded_len, table_fits, FdKind}`.

- [ ] **Step 1: Write the failing tests** — round-trip both directions; retained inherit rejection; **File→isatty=0** and **NUL(char-device)→isatty=1** (deterministic `classify` coverage, no console needed); **oversized-fd rejection**:

```rust
#[test] fn fd3_pipe_out_delivers_child_bytes() { /* write-fd 3 "hi-fd3"; parent read end == "hi-fd3" */ }
#[test] fn fd3_pipe_in_feeds_child() { /* read-fd 3; write "ping3", drop write end (EOF); stdout == "ping3" */ }
#[test]
fn inherit_on_fd3_is_unsupported() {
    let e = subprocess::Command::new().args(["subprocess_testbin","exit","0"])
        .fd(3, subprocess::Stdio::inherit()).unwrap().spawn().unwrap_err();
    assert!(matches!(e, subprocess::error::Error::Unsupported{..}), "{e:?}");
}
#[test]
fn fd3_file_is_not_a_tty() { /* fd(3, Stdio::file(tempfile)); isatty-fd 3 -> "isatty=0" */ }
#[test]
fn fd3_nul_is_a_char_device() {
    // NUL is FILE_TYPE_CHAR -> classify=CharDev -> FDEV -> child _isatty(3)==1. Deterministic, no console.
    let mut c = subprocess::Command::new();
    c.args(["subprocess_testbin","isatty-fd","3"]).fd(3, subprocess::Stdio::null()).unwrap()
     .stdout(subprocess::Stdio::pipe()).unwrap();
    let mut child = c.spawn().unwrap(); let mut s = String::new();
    std::io::Read::read_to_string(&mut child.stdout().unwrap(), &mut s).unwrap(); child.wait().unwrap();
    assert!(s.contains("isatty=1"), "NUL on fd3 is a char device: {s}");
}
#[test]
fn oversized_fd_is_unsupported() {
    let e = subprocess::Command::new().args(["subprocess_testbin","exit","0"])
        .fd(70_000, subprocess::Stdio::null()).unwrap().spawn().unwrap_err();
    assert!(matches!(e, subprocess::error::Error::Unsupported{..}), "{e:?}");
}
```

(Adjust `Stdio::file`/`null`/accessor names to the real API from `src/stdio.rs`/`src/command.rs`.)

- [ ] **Step 2: Run, expect FAIL** — `cargo test --locked --features tokio --test raw_windows fd3_ inherit_on_fd3 oversized_fd`.

- [ ] **Step 3: Extend `spawn_raw`.** BEFORE resolving stdio, reject each configured fd ≥ 3 whose `ResolvedStdio` is `Inherit` → `Error::Unsupported`. **Check the cap BEFORE allocating:** `let maxfd = fds.keys().map(|f| f.raw()).max().unwrap_or(2); if !crt_fds::table_fits(crt_fds::encoded_len(maxfd)) { return Err(Error::Unsupported{ detail:"fd table > 64KiB".into(), .. }); }` Then add fd ≥ 3 to the resolve slots; `classify(handle)?` each; `table = encode(0..=maxfd)`; `si.StartupInfo.cbReserved2 = table.bytes.len() as u16; lpReserved2 = table.bytes.as_ptr()` (kept alive past spawn). **Set `all_handles = table.handles`** — a SINGLE source that already covers 0/1/2 + fd ≥ 3 (each a distinct fresh dup from `resolve_stdio`, so no duplicate handle reaches the list), and whose 0/1/2 entries ARE the same handles wired into `hStd*`. Do NOT append to Task 4's 0/1/2 vector (that would duplicate 0/1/2). The attribute list built in Task 4 is now over this `all_handles`.

- [ ] **Step 4: Run, expect PASS** — the new tests; full host + WSL suites.

- [ ] **Step 5: Commit** — `git add src/child/spawn/windows_raw.rs tests/raw_windows.rs && git commit -m "feat: sync fd>=3 via lpReserved2 + HANDLE_LIST; inherit guard; pre-alloc cap; device-class tests"`

---

### Task 6: containment over the raw path (shared, mode-gated flag computation)

**Files:** Modify `src/containment/dispatch.rs`, `src/child/spawn/windows_raw.rs`, `tests/raw_windows.rs`

**Interfaces:** `#[cfg(windows)] pub(crate) fn windows_contain_setup(req:&ContainRequest, is_root:bool) -> WindowsContain` where `struct WindowsContain { creation_flags: u32, marker_env: bool }` — the decision inlined in `prepare` (dispatch.rs:276-288); **returns `{0,false}` when `req.mode` is `None`.** `prepare` (std path) calls it under its existing `if mode.is_some()` gate and applies as today.

- [ ] **Step 1: Write the failing tests** — contained raw child in our job + `kill_tree` reaps (fd3 read to EOF, not payload-size-dependent); AND an **uncontained** raw child reports `Containment::None`:

```rust
#[test]
fn contained_raw_child_is_in_our_job_and_kill_tree_reaps() {
    let mut c = subprocess::Command::new();
    c.args(["subprocess_testbin","write-fd","3","x"]).fd(3, subprocess::Stdio::pipe()).unwrap().contain();
    let mut child = c.spawn().expect("contained raw spawn");
    assert!(child.test_job_handle_contains_self());
    let mut s = String::new();
    std::io::Read::read_to_string(&mut child.fd_read_end(subprocess::Fd::from_raw(3)).unwrap(), &mut s).unwrap();
    assert_eq!(s, "x");
    child.kill_tree().expect("kill_tree");
}
#[test]
fn uncontained_raw_child_has_no_containment() {
    let mut c = subprocess::Command::new();
    c.executable(common::testbin()).commandline("x argv0-report").stdout(subprocess::Stdio::pipe()).unwrap();
    assert!(matches!(c.spawn().unwrap().containment(), subprocess::Containment::None));
}
```

- [ ] **Step 2: Run, expect FAIL** — `cargo test --locked --features tokio --test raw_windows contained_raw uncontained_raw`.

- [ ] **Step 3: Refactor + wire.** (a) Extract `windows_contain_setup` from dispatch.rs:276-288 (`{0,false}` for `mode==None`); std `prepare` calls it under its `if mode.is_some()` gate + applies as today (full suite → std path unchanged). (b) In `spawn_raw`, **gated on `cmd.contain_request().mode.is_some()`**: compute `is_root` as `prepare` does, call `windows_contain_setup`, OR `creation_flags` into `flags`, when `marker_env` push `(NESTED_ENV,"1")` into the env ops feeding `build_env_block`, and call `clear_std_handle_inheritance()`. When `mode` is `None`, none of this runs. Then `attach_or_fault(pid, proc.as_raw_handle(), prepared)` (construct `Prepared{mode,is_root,..}`). `attach_job` resumes the CREATE_SUSPENDED child via Toolhelp — unchanged.

- [ ] **Step 4: Run, expect PASS** — both tests; full host + WSL suites.

- [ ] **Step 5: Commit** — `git add src/containment/dispatch.rs src/child/spawn/windows_raw.rs tests/raw_windows.rs && git commit -m "feat: containment over the sync raw backend — shared mode-gated flag computation"`

---

### Task 7: async backend enum + `RawAsyncChild` + async raw spawn (executable path)

Mirror Task 4 for tokio. Async wait reuses the shared `wait_handle_or_cancel` on the OWNED handle (no foreign pid-reopen), with **`Arc`-owned handles** so a dropped wait future or dropped child never closes a parked-on handle.

**Files:** Create `src/tokio/child/proc_source.rs`, `src/tokio/spawn/windows_raw.rs`; Modify `src/tokio/child.rs`, `src/tokio/child/pump.rs`, `src/tokio/child/graceful.rs`, `src/tokio/spawn.rs` (routing + `spawn_lock` around `tcmd.spawn()`), `src/wait/windows.rs` (generalize the watcher core to a `HANDLE`); Create `tests/raw_windows_async.rs`

**Interfaces:**
- `enum ProcSource { Tokio(::tokio::process::Child), #[cfg(windows)] Raw(windows_raw::RawAsyncChild) }` + `id`, `#[cfg(windows)] raw_handle`, `async fn wait(&mut self)`, `try_wait`, `start_kill`, stdin/stdout/stderr (Tokio arm).
- `struct RawAsyncChild { proc: Arc<OwnedHandle>, pid: u32, exited: Option<ExitStatus> }`. `wait(&mut self)`: return cached `exited` if set; else create a cancel event (`Arc<OwnedHandle>`), clone `proc`+`cancel` Arcs into `spawn_blocking(move || wait_handle_or_cancel(HANDLE(proc.as_raw_handle()), Some(HANDLE(cancel.as_raw_handle()))))`, hold a `CancelGuard(Arc<cancel>)` in the future that `SetEvent`s on drop (`log::debug!` on failure — Drop can't propagate). The `Arc`s keep both handles alive until the blocking task returns. Await the `JoinHandle`; a `JoinError` (task panic / runtime shutdown) → `Error::Io(other("wait task failed"))`. On `Exited` → `GetExitCodeProcess`, cache `exited`. `try_wait` = zero-timeout poll; `start_kill` = `TerminateProcess`.
- A `#[cfg(test)]` **per-instance** observable seam: `RawAsyncChild` carries an optional observer (`started` + `outcome` senders) injected by a test-only spawn variant (`spawn_with_wait_observer`), NOT a process-global free function — a global seam would let a parallel tokio test's `wait()` fire into this test's channels. The blocking closure signals "started" and sends its `WaitOutcome` on THAT child's channels only, so the test observes exactly the child under test — deterministic, event-driven.
- `src/wait/windows.rs`'s watcher core is refactored to take a `HANDLE` (+ cancel event); the foreign caller opens the handle, the raw async path passes its owned handle.

- [ ] **Step 1: Write the failing async tests** — executable≠argv0, AND a **cancellation** test that (a) polls the wait to parking and (b) observes the `Cancelled` outcome:

```rust
#![cfg(all(windows, feature = "tokio"))]
mod common;
#[tokio::test]
async fn async_executable_independent_of_argv0() { /* mirror the sync test with AsyncReadExt */ }

#[tokio::test]
async fn async_wait_drop_cancels_and_child_stays_waitable() {
    // testbin blocks until stdin EOF. Install a test observable, START wait() as a task so it PARKS
    // (await the closure's "started" signal), then abort/drop it and AWAIT the "cancelled" signal —
    // no wall-clock. Then close stdin (EOF) and prove a fresh wait() still resolves.
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (outcome_tx, outcome_rx) = tokio::sync::oneshot::channel();
    let mut c = subprocess::tokio::Command::new();
    c.args(["subprocess_testbin","read-fd","0"]).stdin(subprocess::Stdio::pipe()).unwrap();
    // test-only spawn variant injects the observer into THIS child only (no process-global seam).
    let mut child = c.spawn_with_wait_observer(started_tx, outcome_tx).unwrap();
    let task = tokio::spawn(async move { let _ = child.wait().await; });
    started_rx.await.unwrap();          // THIS child's blocking wait has parked
    task.abort();                       // drop the in-flight wait future -> CancelGuard fires SetEvent
    assert_eq!(outcome_rx.await.unwrap(), WaitOutcome::Cancelled);   // observed on THIS child, event-driven
}
```

- [ ] **Step 2: Run, expect FAIL** (`Unsupported` / missing hook) — `cargo test --locked --features tokio --test raw_windows_async async_executable async_wait_drop_cancels`.

- [ ] **Step 3: Introduce `ProcSource`** as a pure refactor (Tokio arm only): update `child.rs`, `pump.rs`, `graceful.rs`; expose `ProcSource::wait(&mut self)`. Full tokio suite host + WSL → green.

- [ ] **Step 4: Generalize the watcher + implement `RawAsyncChild`** per the interface (Arc-owned handles; `CancelGuard`; `JoinError` mapping; the `#[cfg(test)]` observable). Refactor `src/wait/windows.rs`'s blocking core to take a `HANDLE`.

- [ ] **Step 5: Implement async `spawn_raw`** — reuse `create_process`, the STARTUPINFOEXW/USESTDHANDLES/HANDLE_LIST build, and the lock/close discipline (child ends closed before the guard releases); piped std ends via the tokio overlapped-pipe machinery; identity read BEFORE any await; `attach_or_fault(...)` **with the SAME kill+reap error-teardown arms as the sync-raw/std spawn**. Route with the SAME predicate; `spawn_lock()` around the raw window and `tcmd.spawn()`.

- [ ] **Step 6: Run, expect PASS** — the async tests; full tokio host + WSL suites.

- [ ] **Step 7: Commit** — `git add src/tokio/ src/wait/windows.rs tests/raw_windows_async.rs && git commit -m "feat: async raw CreateProcessW backend — executable/argv0; Arc-owned cancellable async wait"`

---

### Task 8: async fd ≥ 3 + containment parity

**Files:** Modify `src/tokio/spawn/windows_raw.rs`, `src/tokio/child.rs` (Windows fd ≥ 3 async parent-end accessors — mirror the Unix Plan-10 surface), `tests/raw_windows_async.rs`; consumes `create_process` + `crt_fds`.

- [ ] **Step 1: Write the failing tests** — async fd-3 round-trip both directions (exit proven by pipe EOF) + a contained-async twin (`test_job_handle_contains_self`).

- [ ] **Step 2: Run, expect FAIL** — `cargo test --locked --features tokio --test raw_windows_async async_fd3_ async_contained`.

- [ ] **Step 3: Implement** — fd ≥ 3 child ends into `create_process` (same `lpReserved2`/HANDLE_LIST/pre-alloc-cap/inherit-guard/lock path); surface Windows fd ≥ 3 parent ends as tokio async pipe ends (owned by the async raw path, like the Plan-10 merge-target overlapped pairs); containment via `windows_contain_setup` (mode-gated); **SAME kill+reap teardown arms**.

- [ ] **Step 4: Run, expect PASS** — full tokio host + WSL suites.

- [ ] **Step 5: Commit** — `git add src/tokio/ tests/raw_windows_async.rs && git commit -m "feat: async fd>=3 + contained raw backend parity (tokio, Windows)"`

---

### Task 9: retire the rejections, refresh docs/error text, spec/TODO, end-to-end flips

**Files:** Modify `src/command.rs`, `src/child/spawn.rs` + `src/tokio/spawn.rs` (residual `Plan 4` text), `src/child/spawn.rs` `inherit_end` message, `TODO.md`, the design spec (mark landed), `tests/spawn_io.rs` / `tests/tokio_io.rs`.

- [ ] **Step 1: Grep** `rg -n "Plan 4|raw backend" src tests` — each hit removed or reworded (no future-backend promise). Resolve every hit.

- [ ] **Step 2: Flip the `Unsupported` tests to END-TO-END** — not `spawn().is_ok()`: `executable()+commandline()` reads back `argv0-report` (argv[0] from commandline, image = executable); fd ≥ 3 round-trips bytes. Keep `Unsupported` for retained cases (inherit-on-fd ≥ 3, chained merge, `.bat`/`.cmd`).

- [ ] **Step 3: Run the FULL matrix** — host `cargo test --locked` + `--features tokio`; WSL both; `cargo +stable fmt --check`; `cargo clippy --locked --features tokio --all-targets` + `--all-targets`; `prek run --all-files`. All green/clean.

- [ ] **Step 4: Docs** — `command.rs` platform notes: supported behavior + MSVC/UCRT-only fd ≥ 3 caveat + the `executable()` cwd+PATH resolution rule + retained limits + inherent non-MSVCRT note. Normalize docs to LF.

- [ ] **Step 5: Commit** — `git add src tests TODO.md Cargo.toml Cargo.lock && git add -f .tmp/claude/superpowers/specs/2026-07-18-plan12-windows-raw-backend-design.md .tmp/claude/superpowers/plans/2026-07-18-plan12-windows-raw-backend.md && git commit -m "feat: retire the Windows fd>=3 / executable+commandline Unsupported paths; docs + spec/TODO"` (`.gitignore` was already committed at branch start; `CLAUDE.local.md` is gitignored/untracked — do NOT add it)

---

## Self-Review

**Spec coverage:** §1 → Tasks 4/7. §2 → Task 4 (+5/6). §3 + classify → Task 2, wired 5/8. §4 → Task 3. §5 → Task 6 (+8). §6 + shared wait → Task 4. §7 → Task 7. §8 routing → 4/7. §9 features → 3/4. Deferrals retained loud → 4/5/9. **Covered.**

**Round-3 must_fix dispositions (all FIXED):** async cancel test unpolled/unobservable (4077a20c, 4671b42d) → the test spawns the wait as a task, awaits a "started" park signal, aborts it, and awaits an observed `Cancelled` outcome via a `#[cfg(test)]` seam (Task 7). resolver parity overclaim (2972f846) → parity claim dropped; the cwd+PATH+`.exe` rule is stated as deliberate (Global Constraints, Task 3). missing USESTDHANDLES/hStd*/cb (67ff57ac) → set explicitly in `spawn_raw` (Task 4). CharDev/classify coverage (1b1c6059, 2fb2b893) → deterministic `NUL`→CharDev→isatty=1 test + `classify` invalid-handle unit test (Tasks 5/2). lock-release-before-close race (277c09bf) → `spawn_step` returns a Result and child ends+attr are dropped BEFORE the guard on both arms (Task 4). cwd NUL (14cd19d6) → `ensure_no_nul_wide(cwd)` + test (Task 4). cap-after-alloc (c44613d7) → `encoded_len`/`table_fits` checked before `encode` (Tasks 2/5). mutex poison cascade (d196d5af) → poison-tolerant `spawn_lock` + the in-lock `CloseHandle(hThread)` is log-only, not `debug_assert!(false)` (Task 4). JoinError (a003e2b0) → mapped to `Error::Io` (Task 7). batch ordering/test (6e58395b) → `reject_batch_program` runs before resolution; the test uses a REAL temp `.bat` (Task 4). Dropped-but-tightened: the embedded-NUL assertion pins `Error::Io`.

**Round-4 must_fix dispositions.** Fixed in-plan: `encoded_len` overflow-safe (702cf004, Task 2 + boundary/overflow test); HANDLE_LIST single-sourced from `table.handles`, no 0/1/2 duplication (8fe02265, Tasks 4/5); per-instance async observer, not a global seam (6ee52540, 2a35c875, Task 7); `resolve_executable_in` explicit base dir, no global-cwd mutation in tests (aa2a98ce, Task 3). Resolved during implementation under the mandatory **code-mode** review (they need real code / empirical Windows behavior, not a plan edit): extract `needs_raw`, `build_raw_spawn_plan`, and `teardown_on_attach_failure` as named shared sync/async functions (62577a91, 3c6cf898, eee6d001 — the DRY structure emerges when writing the shared FFI, and the plan already names `create_process`/`crt_fds`/`resolve`/`windows_contain_setup` as shared); `RawChild::kill`/`start_kill` disposition — `TerminateProcess` on a handle we still hold succeeds even post-exit, so map errors normally rather than special-casing "already exited" (2363b09b — verify against real error codes when the code runs); `GetExitCodeProcess` failure → `Error::Io` and `CancelGuard` `SetEvent` failure → `log::error!` (aebc0dce, 1c270906); drop Task 5's redundant inherit-fd≥3 pre-check now that `inherit_end`'s Windows arm is the single hardened source (e9ec04ef); add tests exercising the poison-tolerant lock after a held-lock panic and the `JoinError`→`Error::Io` mapping (8868a744, e4938b15) and a `record-the-raw-FFI-approach` evaluation note (ed8ef289) during Task 4/7 implementation. These are exactly the class the code-mode panel verifies against compiled, tested code.

**Conciseness cuts applied (verified present):** the accepted cuts (create_process/spawn_raw comment trims, the `argv0-report` block trailing comment, the round-2-dispositions verbosity, the `std::mem::forget` phrasing, the batch/USESTDHANDLES inline notes) are gone; the CharDev-hedge cut is NOT applied as a mere trim — it is resolved substantively (the `NUL` deterministic test) per must_fix 1b1c6059.

**Type consistency:** `ProcHandle`/`ProcSource` sets consistent; `RawChild{proc:OwnedHandle,pid}` / `RawAsyncChild{proc:Arc<OwnedHandle>,pid,exited}`; `crt_fds::{encode,classify,encoded_len,table_fits,FdTable,FdKind}` 2↔5↔8; `resolve::{resolve_executable,build_env_block,build_env_block_from,ensure_no_nul_wide}` 3↔4; `wait_handle_or_cancel`/`WaitOutcome` 4↔7; `spawn_lock` 4↔7; `create_process` 4↔7; `windows_contain_setup`/`WindowsContain` std↔raw.

## Recorded decisions
- Scope = sync + async in one plan (user, 2026-07-18).
- Routing = hybrid, raw only when needed.
- `executable()` bare-name resolution = a deliberate cwd+PATH+`.exe` rule (NOT full CreateProcessW-search parity; documented).
- fd ≥ 3 = `lpReserved2` numbered fds, MSVC/UCRT-faithful; non-MSVCRT inherent+documented (spec §144).
- Deferred (user-agreed): chained merges, inherit-on-fd ≥ 3 — retained as loud `Unsupported`.
- Inheritance safety via a poison-tolerant crate spawn mutex + always-on USESTDHANDLES/HANDLE_LIST; child ends closed before the guard releases on every path.
- Shared handle-based wait; async uses Arc-owned handles + observable cancel-on-drop.
- Workflow: issue → branch `azhukova/<issue#>` → PR → CI.
