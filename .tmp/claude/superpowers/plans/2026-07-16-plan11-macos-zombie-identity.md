# Plan 11 — macOS Zombie-Inclusive Identity + Follow-up Sweep Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close issue #2 — macOS identity resolution becomes zombie-inclusive via `sysctl(KERN_PROC_PID)` — which deflakes issue #3's class at the source, then clear the queued small follow-ups (logging sweep, comment trim, getrandom bump).

**Architecture:** HYBRID macOS identity backend: `proc_pidinfo` (Apple's stable libproc API) stays the PRIMARY source; `sysctl`/`kinfo_proc` is the FALLBACK on a libproc miss — exactly the zombie case. `is_running`/`created_at` keep their shipped bodies (a libproc miss is gone-or-zombie, both "not running"); only `start_token` gains the fallback. `kinfo_proc` is a minimal faithful local `#[repr(C)]` definition (libc lacks it on apple — dependency evaluation recorded in the spec), guarded by a compile-time size tripwire plus CI-run oracles (kernel-reported written size; live-token equality against `proc_pidinfo` — the load-bearing cross-source invariant); a hypothetical layout drift on an end-user OS degrades only zombie resolution (token mismatch — the pre-fix behavior), never live identity.

**Tech Stack:** Rust (MSRV 1.87), libc (existing dep). No new dependencies; Task 2 attempts a `getrandom` 0.3→0.4 bump (windows-only, existing dep).

## Global Constraints

- Spec: `.tmp/claude/superpowers/specs/2026-07-16-plan11-macos-zombie-identity.md`.
- **macOS runtime is CI-only**: the local loop is `cargo clippy --locked --features tokio --all-targets --target aarch64-apple-darwin` (compile) + host/WSL suites; darwin behavior is verified by pushing the branch and running CI (`gh workflow run ci.yaml --ref plan-11-macos-zombie-identity`, watched via `gh-ci`). Expect iteration through CI for Task 1.
- **No-time-sync test discipline:** exits proven by pipe EOF or an inspected `ExitStatus` on an owned handle; never sleep/poll/wall-clock.
- `is_running`/`is_alive` stay zombie-EXCLUSIVE; `exists()`/`start_token` become zombie-INCLUSIVE on macOS (Linux parity). No test-side masking of the identity race (recorded on issue #3).
- No changes to `containment/enumerate/macos.rs` (out of scope — spec rationale).
- Before every commit: `cargo +stable fmt --check`, `cargo clippy --locked --features tokio --all-targets`, `cargo clippy --locked --all-targets`, `cargo clippy --locked --features tokio --all-targets --target aarch64-apple-darwin` — all clean; `prek run --all-files` clean (docs must be LF — the mixed-line-ending hook fixes to LF).
- After each task, the WSL run: `MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-24.04 -- bash -lc 'cd /mnt/c/Users/bindreams/src/subprocess && export CARGO_TARGET_DIR=/tmp/sp-target && cargo test --locked --features tokio && cargo test --locked'`. Pipe long outputs to files under `.tmp/claude/`; never `| tail`.
- Single-line commit messages. Rust style: `foo.rs` + `foo/` modules; unit tests in sibling `*_tests.rs`.

---

### Task 1: macOS zombie-inclusive identity backend

**Files:**
- Create: `src/identity/macos/kinfo.rs` (repr(C) `kinfo_proc` + the `sysctl` read)
- Create: `src/identity/macos/kinfo_tests.rs` (macOS-only layout/value oracles)
- Create: `src/log_capture.rs` (shared cfg(test) capturing logger) + Modify: `src/lib.rs` (its declaration)
- Modify: `.github/workflows/ci.yaml` (one darwin-only release-mode `--lib` test step)
- Modify: `src/identity/macos.rs` (backend rewritten onto `kinfo`)
- Modify: `src/identity.rs` (`exists()` doc: drop the macOS caveat)
- Modify: `tests/identity_lifecycle.rs` (the all-platform zombie-resolution acceptance test)
- Modify: `tests/process.rs` (un-gate two Linux-only sites; pid-1 root branch stays Linux-only), `src/child/graceful_tests.rs` + `src/tokio/child/graceful_tests.rs` (un-gate the four zombie-exists asserts), `src/child/spawn.rs` (~:600 `assert_child_reaped` rationale)

**Interfaces:**
- Consumes: `super::{RawPid, StartToken}` (identity.rs), `StartToken::from_raw(u64)`, `libc::{sysctl, CTL_KERN, KERN_PROC, KERN_PROC_PID, SZOMB, timeval, c_char, c_uint, c_void}`.
- Produces: `pub(super) fn kinfo(pid: RawPid) -> Option<kinfo_proc>` and the `kinfo_proc`/`extern_proc` types in `kinfo.rs`; the backend fns keep their existing signatures (`start_token`, `is_running`, `created_at`) — no caller changes.

- [ ] **Step 1: Write the failing acceptance test** — append to `tests/identity_lifecycle.rs` (read the file first and reuse its existing imports/testbin helper idioms; the body below is normative):

```rust
/// An exited-but-unreaped (zombie) child must still resolve by identity on EVERY platform.
/// Exit is proven by stdout EOF — the child's write end closes at process exit.
#[test]
fn identity_resolves_an_exited_unreaped_child() {
    use std::io::Read;
    let mut child = std::process::Command::new(common::testbin())
        .args(["subprocess_testbin", "exit", "0"])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    let mut buf = Vec::new();
    child
        .stdout
        .take()
        .expect("piped stdout")
        .read_to_end(&mut buf)
        .expect("EOF");
    let id = subprocess::ProcessId::of(child.id()).expect("an unreaped exit must resolve by pid");
    assert!(id.exists(), "an unreaped exit must remain visible to exists()");
    child.wait().expect("reap");
}

/// The start token must be STABLE across the alive -> zombie transition — the property
/// `is_running`'s reused-PID guard depends on. `waitid(WEXITED | WNOWAIT)` pins the
/// zombie: it returns only once the child IS a zombie and leaves it unreaped.
#[cfg(unix)]
#[test]
fn identity_survives_the_alive_to_zombie_transition() {
    // _sock must stay alive: dropping our socket end would unblock the child early.
    let (mut child, _sock) = common::spawn_blocker();
    let id = subprocess::ProcessId::of(child.id()).expect("live child resolves");
    assert!(id.exists(), "live child exists");
    assert!(id.is_alive(), "live child is alive");
    child.kill().expect("kill");
    // WNOWAIT: leaves the zombie unreaped.
    let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: `si` is a valid out-param; the child is ours and unreaped.
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            child.id() as libc::id_t,
            &mut si,
            libc::WEXITED | libc::WNOWAIT,
        )
    };
    assert_eq!(rc, 0, "waitid(WNOWAIT): {}", std::io::Error::last_os_error());
    assert!(id.exists(), "the pre-exit token must still match the unreaped zombie");
    assert!(!id.is_alive(), "a zombie is not alive");
    child.wait().expect("reap");
    assert!(!id.exists(), "a reaped process is gone");
}
```

(Reuse the file's existing `common` module and helper idioms — `spawn_blocker` mirrors
`tests/tokio_foreign.rs`; add the `#[path = "common/mod.rs"] mod common;` declaration and a
`libc` dev-dependency import path as the file's siblings do (libc is already a unix
dependency of the crate; tests use it via the existing pattern in tests/process.rs). If
`ProcessId::of` is not re-exported under the name the file already uses, mirror the file's
existing resolution idiom — the assertion sets are what matter.)

Run: `cargo test --locked --test identity_lifecycle identity_`
Expected: PASS already on WSL (both tests; Linux procfs is zombie-inclusive today) and on
the Windows host (the first test; the transition test is `cfg(unix)` — Windows has no
zombie state, and its post-exit handle window is covered by the first test). The failing
platform is macOS, which only CI can show — these are the darwin acceptance gates in
Step 7.

- [ ] **Step 2: The `kinfo` module** — create `src/identity/macos/kinfo.rs`:

```rust
//! `sysctl(KERN_PROC_PID)` / `kinfo_proc` — the BSD interface that resolves ZOMBIES
//! (libproc's `proc_pidinfo` does not). libc has no apple definition for these structs,
//! so this is a minimal faithful local one. Only `p_un.p_starttime` is read; everything
//! else is layout. Layout is triple-checked: the compile-time size tripwires below, the
//! kernel-size oracle, and the token-vs-libproc oracle (kinfo_tests.rs).
#![allow(non_camel_case_types)]

use super::super::RawPid;

/// `struct kinfo_proc` (LP64): `extern_proc` head + opaque `eproc` tail.
#[repr(C)]
pub(super) struct kinfo_proc {
    pub(super) kp_proc: extern_proc,
    kp_eproc: [u8; 352],
}

/// `struct extern_proc` (LP64 user copy, from XNU's proc.h). Kernel pointers are
/// represented as `u64` (they are opaque user_addr_t values in the sysctl copy).
#[repr(C)]
pub(super) struct extern_proc {
    pub(super) p_un: p_un,
    p_vmspace: u64,
    p_sigacts: u64,
    p_flag: libc::c_int,
    p_stat: libc::c_char,
    p_pid: libc::pid_t,
    p_oppid: libc::pid_t,
    p_dupfd: libc::c_int,
    user_stack: u64,
    exit_thread: u64,
    p_debugger: libc::c_int,
    sigwait: libc::c_int, // boolean_t
    p_estcpu: libc::c_uint,
    p_cpticks: libc::c_int,
    p_pctcpu: u32, // fixpt_t
    p_wchan: u64,
    p_wmesg: u64,
    p_swtime: libc::c_uint,
    p_slptime: libc::c_uint,
    p_realtimer: itimerval,
    p_rtime: libc::timeval,
    p_uticks: u64,
    p_sticks: u64,
    p_iticks: u64,
    p_traceflag: libc::c_int,
    p_tracep: u64,
    p_siglist: libc::c_int,
    p_textvp: u64,
    p_holdcnt: libc::c_int,
    p_sigmask: u32, // sigset_t
    p_sigignore: u32,
    p_sigcatch: u32,
    p_priority: u8,
    p_usrpri: u8,
    p_nice: libc::c_char,
    p_comm: [libc::c_char; 17], // MAXCOMLEN + 1
    p_pgrp: u64,
    p_addr: u64,
    p_xstat: u16,
    p_acflag: u16,
    p_ru: u64,
}

#[repr(C)]
pub(super) union p_un {
    p_st1: run_sleep_queue,
    pub(super) p_starttime: libc::timeval,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct run_sleep_queue {
    p_forw: u64,
    p_back: u64,
}

#[repr(C)]
struct itimerval {
    it_interval: libc::timeval,
    it_value: libc::timeval,
}

// Compile-time layout tripwire: sizeof(struct kinfo_proc) == 648 on LP64 darwin (ps and
// libtop hard-code the same). The kernel-size oracle in kinfo_tests.rs re-checks this
// against the running kernel.
const _: () = assert!(std::mem::size_of::<kinfo_proc>() == 648);
const _: () = assert!(std::mem::size_of::<extern_proc>() == 296);

/// Read one `kinfo_proc` for `pid`. `None` means "not resolvable" — the EXPECTED miss is
/// a nonexistent pid (sysctl SUCCESS with `size == 0`); a real sysctl failure or a
/// wrong-sized record is a contract violation and leaves a trace before the same `None`.
/// EINTR retries, per the codebase convention (see `wait/linux.rs`, `wait/macos.rs`).
pub(super) fn kinfo(pid: RawPid) -> Option<kinfo_proc> {
    read_record(pid, libc::KERN_PROC_PID)
}

/// The selector-parameterized core. The `selector` parameter is a TEST SEAM (production
/// always passes `KERN_PROC_PID` via `kinfo()`; the codebase's fault-seam precedent) —
/// it lets a unit test drive the contract-violation arm with an invalid selector.
fn read_record(pid: RawPid, selector: libc::c_int) -> Option<kinfo_proc> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROC, selector, pid as libc::c_int];
    loop {
        let mut info: kinfo_proc = unsafe { std::mem::zeroed() };
        let mut size = std::mem::size_of::<kinfo_proc>();
        // SAFETY: `info` and `size` describe one kinfo_proc; sysctl writes at most `size`.
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                &mut info as *mut _ as *mut libc::c_void,
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            super::contract_violation(format_args!(
                "sysctl(KERN_PROC selector {selector}, {pid}) failed: {e}"
            ));
            return None;
        }
        if size == 0 {
            return None;
        }
        if size != std::mem::size_of::<kinfo_proc>() {
            // Layout drift — never trust a partial/foreign-sized record.
            super::contract_violation(format_args!(
                "sysctl(KERN_PROC selector {selector}, {pid}) wrote {size} bytes, expected {}",
                std::mem::size_of::<kinfo_proc>()
            ));
            return None;
        }
        return Some(info);
    }
}


#[cfg(test)]
#[path = "kinfo_tests.rs"]
mod kinfo_tests;
```

(If `RawPid`'s path differs from `super::super::RawPid` after the module wiring in Step 3,
adjust the import — the signature is what matters. If the compile-time asserts trip on the
cross-target check, the field list has drifted from XNU's proc.h — fix the STRUCT, never
the constant: 648/296 are the kernel's numbers.)

- [ ] **Step 3: The HYBRID backend** — in `src/identity/macos.rs`. The design and its
drift-fails-safe rationale live in the module doc below (the shipped artifact); only
`start_token` and `bsd_info` change:

```rust
//! macOS process-identity backend: `proc_pidinfo` (Apple's stable public libproc API) is
//! the PRIMARY source; `sysctl(KERN_PROC_PID)` (the `kinfo` module) is the FALLBACK for
//! what libproc cannot see — ZOMBIES — keeping identity resolution zombie-inclusive like
//! Linux procfs while the common live path stays on the stable ABI. Both sources report
//! the process start time in µs (cross-source equality pinned by the kinfo_tests oracle),
//! so a layout drift in the undocumented kinfo_proc ABI degrades only zombie resolution
//! (a token mismatch — the pre-fix behavior), never live identity.
```

`token_of` (rename to `token_of_bsd`), `is_running`, and `created_at` keep their shipped
bodies. `bsd_info` gains the SAME failure disposition as the fallback (the hybrid's two
sources must not have asymmetric visibility): `n == size` is success; an errno of ESRCH
(gone/zombie — the miss the fallback exists for) or EPERM (an unprivileged cross-user
query; the fallback resolves it via sysctl, which is world-readable) is a calm `None`;
anything else — another errno or a partial record — is a traced contract violation:

```rust
fn bsd_info(pid: RawPid) -> Option<libc::proc_bsdinfo> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: proc_pidinfo writes up to `size` bytes into `info`; pointer and size match.
    let n = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            size,
        )
    };
    if n == size {
        return Some(info);
    }
    if n <= 0 {
        let e = std::io::Error::last_os_error();
        match e.raw_os_error() {
            // Expected misses: gone/zombie (ESRCH) or an unprivileged cross-user query
            // (EPERM) — the sysctl fallback covers both.
            Some(libc::ESRCH) | Some(libc::EPERM) => {}
            _ => contract_violation(format_args!("proc_pidinfo({pid}) failed: {e}")),
        }
        return None;
    }
    // 0 < n < size: a partial record — never trust it.
    contract_violation(format_args!("proc_pidinfo({pid}) wrote {n} bytes, expected {size}"));
    None
}

/// The shared contract-violation disposition for BOTH identity sources: trace FIRST (so
/// the warn executes in every build mode), then the debug tripwire.
pub(super) fn contract_violation(what: std::fmt::Arguments<'_>) {
    log::warn!("{what}");
    debug_assert!(false, "{what}");
}
```

(`contract_violation` moves UP from `kinfo.rs` to here — `kinfo.rs`'s `read_record` calls
`super::contract_violation`; delete the kinfo-local copy. The `pub(super)` is for the
sibling test modules.) Add the module declaration and the fallback:

```rust
#[path = "macos/kinfo.rs"]
mod kinfo;

fn token_of_kinfo(info: &kinfo::kinfo_proc) -> StartToken {
    // SAFETY: the kernel's KERN_PROC copy always fills `p_starttime` (XNU
    // fill_externproc); the union's other arm is kernel-internal queue pointers never
    // exported here. Both arms are plain old data, so the read is defined.
    let start = unsafe { info.kp_proc.p_un.p_starttime };
    StartToken::from_raw(start.tv_sec as u64 * 1_000_000 + start.tv_usec as u64)
}

pub(super) fn start_token(pid: RawPid) -> Option<StartToken> {
    if let Some(info) = bsd_info(pid) {
        return Some(token_of_bsd(&info));
    }
    // libproc-invisible: gone or a ZOMBIE — only sysctl resolves the latter.
    kinfo::kinfo(pid).as_ref().map(token_of_kinfo)
}
```

(`p_stat` in `kinfo.rs` becomes a private field — production never reads it in the hybrid
(`is_running`'s zombie-exclusion still comes from `pbi_status`/libproc-miss); drop its
`pub(super)`. `containment/enumerate/macos.rs` keeps its own libproc uses — out of scope.)

- [ ] **Step 4: The macOS oracles** — create `src/identity/macos/kinfo_tests.rs` (runs only
on the darwin CI cells; compiles under the cross-target check):

```rust
//! Layout/value oracles for the local kinfo_proc definition. macOS-only at runtime.

use super::*;

// The kernel must agree with our struct size exactly: for a real one-record fetch, XNU
// sets the written size to sizeof(struct kinfo_proc). (A NULL-buffer probe is NOT usable
// here — XNU inflates it by KERN_PROCSLOP = 5*sizeof, so it reports 6*sizeof for one pid.)
#[test]
fn kernel_writes_exactly_our_kinfo_proc_size() {
    let mut buf = [0u8; 2 * std::mem::size_of::<kinfo_proc>()];
    let mut size = buf.len();
    let mut mib = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_PID,
        std::process::id() as libc::c_int,
    ];
    // SAFETY: `buf`/`size` describe the buffer; sysctl writes at most `size` bytes. No
    // field is read from `buf`, so its alignment is irrelevant.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    assert_eq!(rc, 0, "sysctl fetch failed: {}", std::io::Error::last_os_error());
    assert_eq!(
        size,
        std::mem::size_of::<kinfo_proc>(),
        "kernel kinfo_proc record size disagrees with our layout"
    );
}

// The rc!=0 contract-violation arm, driven through the selector test seam (a SYNTHETIC
// invalid selector — the arm's real triggers are unconstructible with a correct mib). In
// debug builds the tripwire panics AFTER the warn executed (this test expects the panic);
// in the release lane the same straight-line code minus the compiled-out assert runs to
// `None`, which the assert below pins.
#[cfg_attr(debug_assertions, should_panic(expected = "sysctl(KERN_PROC"))]
#[test]
fn read_record_flags_an_invalid_selector() {
    let r = super::read_record(std::process::id() as super::super::RawPid, -1);
    assert!(r.is_none(), "an invalid selector must never yield a record");
}

// Verifies contract_violation's warn is actually captured, not just that debug panics —
// the release lane (no should_panic) asserts the captured record directly.
#[cfg_attr(debug_assertions, should_panic(expected = "synthetic"))]
#[test]
fn contract_violation_traces_then_trips() {
    crate::log_capture::install();
    super::super::contract_violation(format_args!("synthetic contract violation (test)"));
    // Only reachable in release (debug panicked above, as expected):
    assert!(
        crate::log_capture::contains("synthetic contract violation (test)"),
        "the warn must have fired before the (compiled-out) tripwire"
    );
}

/// Minimal capturing logger: installed once per process (`log::set_logger` is
/// once-per-process); records every message so tests assert by unique marker.
mod capture {
    use std::sync::{Mutex, OnceLock};

    struct CaptureLog;
    static RECORDS: Mutex<Vec<String>> = Mutex::new(Vec::new());
    static INSTALLED: OnceLock<()> = OnceLock::new();

    impl log::Log for CaptureLog {
        fn enabled(&self, _: &log::Metadata<'_>) -> bool {
            true
        }
        fn log(&self, record: &log::Record<'_>) {
            RECORDS.lock().unwrap().push(record.args().to_string());
        }
        fn flush(&self) {}
    }

    pub(super) fn install() {
        INSTALLED.get_or_init(|| {
            log::set_logger(&CaptureLog).expect("first logger in this test process");
            log::set_max_level(log::LevelFilter::Trace);
        });
    }

    pub(super) fn contains(marker: &str) -> bool {
        RECORDS.lock().unwrap().iter().any(|m| m.contains(marker))
    }
}

// Value oracle: for a LIVE process the sysctl-derived token must equal the
// proc_pidinfo-derived token — a wrong `p_un` offset or padding error fails here.
// `proc_pidinfo` survives ONLY as this oracle.
#[test]
fn sysctl_token_matches_libproc_for_a_live_process() {
    let pid = std::process::id() as libc::c_int;

    let ours = kinfo(pid as super::super::RawPid).expect("self resolves via sysctl");
    let ours = {
        // SAFETY: as in token_of — the kernel fills p_starttime for KERN_PROC copies.
        let t = unsafe { ours.kp_proc.p_un.p_starttime };
        t.tv_sec as u64 * 1_000_000 + t.tv_usec as u64
    };

    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: proc_pidinfo writes up to `size` bytes into `info`.
    let n = unsafe {
        libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, &mut info as *mut _ as *mut libc::c_void, size)
    };
    assert_eq!(n, size, "proc_pidinfo oracle failed for self");
    let theirs = info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec;

    assert_eq!(ours, theirs, "sysctl and libproc disagree on self's start token");
}
```

(Adjust the `RawPid` paths to the real module layout if they differ; the two assertions
are normative. Note `kinfo_proc`, `kinfo`, and `p_un.p_starttime` must be visible to this
sibling test module — the `pub(super)` markers in Step 2 provide exactly that.)

- [ ] **Step 5: Un-gate the zombie-motivated Linux-only sites + docs**

1. `src/identity.rs` — two doc updates. The `exists()` doc replaces the macOS-caveat
   sentences:

```rust
    /// zombie-inclusive sense, matching psutil's `is_running`). True for a not-yet-reaped
    /// zombie on every platform: Linux (`/proc` persists), macOS (`sysctl KERN_PROC`
    /// resolves zombies), and Windows (during the post-exit handle window). For
    /// "is it still running?", use [`ProcessId::is_alive`].
```

   And the module doc (~:8-13) still names the macOS token source as "`proc_bsdinfo`
   start µs" — replace that clause with "`sysctl KERN_PROC` (`kinfo_proc`) start µs" so
   the module's own source list matches the new backend.

2. `src/child/graceful_tests.rs` AND its async twin `src/tokio/child/graceful_tests.rs`
   (byte-identical gating: sync ~:32-38 lone ~:63-69; tokio ~:27-33 and ~:58-64) — in all
   FOUR tests: delete the `#[cfg(target_os = "linux")]` attribute on the `!id.exists()`
   assert and the paired `#[cfg(not(target_os = "linux"))] let _ = id;` escape — the assert
   runs unconditionally (the fns are already `cfg(unix)`; on Windows they don't exist, and
   the assert now discriminates reaped-vs-zombie on macOS too). Update every assert message
   ("on Linux a zombie would still exist" → "a zombie would still exist") and BOTH files'
   header comments that explain the gate — the sync lone twin's (~:43-46) and the sync
   tree test's (~:8-12 — "macOS's proc_pidinfo does not see zombies (identity.rs), so the
   assert is Linux-gated"), plus any equivalent sentences in the tokio twin: state instead
   that the assert runs on all Unix (procfs / sysctl KERN_PROC are both zombie-inclusive).

3. `tests/process.rs` ~:243-246 — remove the inner `#[cfg(target_os = "linux")]` on the
   zombie-still-resolvable assertion and rewrite its comment: exists() is zombie-inclusive
   on ALL Unixes now (procfs / sysctl KERN_PROC); keep any Windows gating as is.

3b. `src/child/spawn.rs` ~:599-604 — `assert_child_reaped`'s rationale credits only
   "Linux /proc persists" for the zombie-catching property; amend it: on macOS the zombie
   also persists (sysctl KERN_PROC), so the identity assertion is zombie-catching on all
   Unix. NOTE for Step 7: this assertion was previously vacuous on macOS — if a darwin CI
   cell newly fails it, that is a REAL latent unreaped-child bug being surfaced; investigate
   the call site, do not re-gate.

4. `tests/process.rs` ~:187-215 — the pid-1 (launchd/init) EPERM test un-gates to
   `#[cfg(unix)]` BUT the root branch stays effectively Linux-only (see the replacement
   header comment for why; CI runners are non-root, so the EPERM branch is what darwin CI
   exercises). Replace the whole test +
   header comment with:

```rust
// pid 1 (init/launchd) is world-resolvable AND non-root-unkillable on Linux and macOS:
// procfs / sysctl KERN_PROC both resolve it, and a non-root kill(1) returns EPERM, which
// Process::kill must SURFACE as Err (not swallow into Ok). The ROOT branch stays
// Linux-only: Linux provably discards unhandled SIGKILL to pid 1 (SIGNAL_UNKILLABLE);
// XNU's launchd protection is unverified, and being wrong panics the machine — so as
// root on non-Linux we refuse to signal pid 1 at all.
#[cfg(unix)]
#[test]
fn foreign_kill_surfaces_permission_denied() {
    let init = subprocess::Process::from_pid(1).expect("pid 1 resolves");
    assert!(init.is_alive(), "init must be alive");
    // SAFETY: geteuid() takes no arguments and is always safe.
    let root = unsafe { libc::geteuid() } == 0;
    #[cfg(not(target_os = "linux"))]
    if root {
        // Fail LOUD, never silently pass unverified (the repo's no-silent-skip rule):
        panic!(
            "inconclusive: refusing to SIGKILL pid 1 as root on this platform \
             (unverified kernel semantics) — run this test unprivileged"
        );
    }
    let r = init.kill();
    if !root {
        assert!(
            matches!(r, Err(subprocess::error::Error::Io(_))),
            "non-root kill of init must surface EPERM as Err, got {r:?}"
        );
    } else {
        assert!(r.is_ok(), "as root, SIGKILL to init is kernel-ignored => Ok, got {r:?}");
    }
    assert!(init.is_alive(), "init must survive");
}
```

Run: `cargo test --locked > .tmp/claude/p11-t1-host.txt 2>&1` and the WSL battery
Expected: all green on host + WSL (macOS asserts compile; run on CI in Step 7).

- [ ] **Step 6: The release-mode lib-test lane + gates + commit**

In `.github/workflows/ci.yaml`, after the existing `cargo test --locked --features tokio
--target ...` step (~line 88), add one step so the debug-only tripwire dispositions get a
run where `debug_assertions` is OFF (the `should_panic` tests take their calm release arm
there):

```yaml
      - name: Unit tests (release — debug_assertions off)
        if: matrix.os == 'darwin'
        run: cargo test --locked --release --lib --target ${{ matrix.target }}
```

(darwin-only, mirroring the cgroup step's `if: matrix.os == 'linux'` precedent in the same
job — the release-vs-debug-arm tests live entirely in the macOS-gated kinfo_tests.rs.)

(`--lib` only: the point is the unit-level tripwire arms; integration suites already run
in the debug lanes.) Verify the equivalent locally on the host:
`cargo test --locked --release --lib` (the Windows-runnable subset).

Run: `cargo +stable fmt --check && cargo clippy --locked --features tokio --all-targets && cargo clippy --locked --all-targets && cargo clippy --locked --features tokio --all-targets --target aarch64-apple-darwin && prek run --all-files`
Expected: all clean (the cross-target clippy compiles the new macOS module + tests).

```bash
git add src/identity/macos.rs src/identity/macos/kinfo.rs src/identity/macos/kinfo_tests.rs src/identity.rs tests/identity_lifecycle.rs tests/process.rs src/child/graceful_tests.rs src/tokio/child/graceful_tests.rs src/child/spawn.rs .github/workflows/ci.yaml
git commit -m "feat: macOS zombie-inclusive identity via sysctl KERN_PROC"
```

- [ ] **Step 7: The darwin runtime gate** — push and watch CI:

```bash
git push -u origin plan-11-macos-zombie-identity
gh workflow run ci.yaml --ref plan-11-macos-zombie-identity
```

Watch with `gh-ci watch <run url>`. The darwin cells are the ONLY runtime verification of
Task 1: `kernel_writes_exactly_our_kinfo_proc_size`, `sysctl_token_matches_libproc_for_a_live_process`,
`read_record_flags_an_invalid_selector`, `contract_violation_traces_then_trips`,
`identity_resolves_an_exited_unreaped_child`, `identity_survives_the_alive_to_zombie_transition`,
the release `--lib` lane, and the un-gated asserts must pass there.
Iterate through CI on failures (layout errors show up as the oracles failing). Do not
proceed to Task 2 until the run is green (a known-flake re-run is acceptable only for
failures demonstrably OUTSIDE this task's class — with this fix in, the #2/#3 identity
flakes should no longer occur at all).

---

### Task 2: Logging sweep + cosmetics

**Files:**
- Modify: `src/wait/windows.rs` (~:65-76 `signal_cancel`), `src/containment/treewalk.rs` (six drop/skip sites + the Windows twin's best-effort comment), `src/child.rs` (~:106-114 kill_tree both-fail), `src/tokio/child.rs` (~:270-275 twin), `src/child/graceful.rs` (~:33-40 lone + the tree body below it), `src/tokio/child/graceful.rs` (~:42-51 lone + the tree body below it), `src/child/graceful_tests.rs` + `src/tokio/child/graceful_tests.rs` (capture assertions in the four stranding twins)
- Modify: `tests/tokio_io.rs` (~:574 comment trim)
- Modify: `Cargo.toml` + `Cargo.lock` (getrandom bump attempt)

**Interfaces:**
- Consumes: `log::{debug, error}` (existing dep). No signature changes anywhere.
- Produces: nothing new — trace lines and comment/manifest cleanups only.

- [ ] **Step 1: The logging sweep.** Read each site first; the shapes below are normative
(adjust local bindings to the file's, never the levels or the placement):

1. `src/wait/windows.rs` `signal_cancel` — the silent branch is release-during-unwind:

```rust
    debug_assert!(set.is_ok(), "SetEvent on an owned event handle failed: {set:?}");
    if !std::thread::panicking() {
        assert!(set.is_ok(), "SetEvent on an owned event handle failed: {set:?}");
    } else if let Err(e) = &set {
        // RELEASE unwind (a debug build already aborted above — visibility over grace,
        // the shipped policy): cannot assert while a panic is in flight, so leave the
        // loudest trace we can for the possible unbounded park.
        log::error!("SetEvent failed during unwind ({e}); a parked watcher may not release");
    }
```

2. `src/containment/treewalk.rs` — SIX drop/skip sites, each with the message matching its
   actual branch (read each block first; preserve the existing accept/insert semantics —
   restructure an `if cond && insert` into an early-`continue` guard only where a log needs
   the failure arm):

   - `descendants_with` ~:119-120, the UNRESOLVABLE-pid branch (`let Some(id) = id else { continue };`):
     `log::debug!("treewalk: pid {pid} unresolvable — dropping its subtree");`
   - `descendants_with` ~:124-127, the `keep(...)` token-mismatch failure (the true
     impostor case — the `if` currently has no else):
     `log::debug!("treewalk: dropping subtree under impostor pid {pid} (recycled pid / stale ppid)");`
   - `children_of_with` ~:158, the unresolvable-pid drop (`let Some(id) = resolve(pid) else { continue };`):
     `log::debug!("treewalk: pid {pid} unresolvable — dropped from children");`
   - `children_of_with` ~:160-162, the token-mismatch drop (no else today):
     `log::debug!("treewalk: dropping impostor pid {pid} (recycled pid / stale ppid)");`
   - Unix `kill_by_identity` ~:178-180, the identity-changed kill skip:
     `log::debug!("treewalk: skipping pid {pid} — identity changed since the snapshot");`
   - Windows `kill_by_identity` ~:204 — the byte-identical guard gets the SAME message as
     the Unix twin. Additionally, its discarded `TerminateProcess`/`CloseHandle` results
     (`let _ = ...;` at ~:214-215) gain the Unix twin's disposition comment class:
     `// best-effort (ERROR_ACCESS_DENIED etc.): nothing actionable to surface here` —
     the two twins must not have asymmetric visibility.

3. Both kill_tree both-fail sites — `src/child.rs` (~:113-114) and `src/tokio/child.rs`
   (~:273-275): between computing `backstop` and the final `group_result.and(backstop)`:

```rust
    if let (Err(group), Err(bs)) = (&group_result, &backstop) {
        log::debug!("kill_tree handle backstop also failed ({bs}); surfacing the group error: {group}");
    }
```

4. The four OWNED graceful subsumption sites — parity with the Plan-10 foreign bodies,
   which already log the subsumed watch error. In `src/child/graceful.rs` (lone ~:37 and
   the tree body) and `src/tokio/child/graceful.rs` (lone ~:49 and the tree body): directly
   BEFORE the escalation call whose `?` would subsume a watch `Err` (`kill()`, or the tree's
   sweep), insert (the PID in the message is load-bearing — the capture assertions below
   match on it, and tests run in parallel):

```rust
        if let Err(e) = &watch {
            log::debug!("graceful_shutdown({id}): watch error before escalation (subsumed if it also fails): {e}", id = self.id().pid());
        }
```

   In the sync lone body the escalation is `self.shared.kill().map_err(Error::Io)?` — the
   guard goes immediately above it. Adjust the message's op name per site
   (`graceful_shutdown` / `graceful_shutdown_tree`) and the pid expression to what the
   body has in scope; do NOT reorder any existing escalate-then-surface logic.

   These four lines get ASSERTED coverage: the four existing stranding twins
   (`src/child/graceful_tests.rs` `graceful_lone_watch_error_still_escalates_and_reaps` /
   `graceful_tree_watch_error_still_sweeps_and_reaps` and their tokio twins in
   `src/tokio/child/graceful_tests.rs`) already FORCE the watch error via the fault seam,
   so each gains two lines — `crate::log_capture::install();` before the graceful call and,
   after the `expect_err`, an assertion matching the pid-unique prefix:

```rust
    assert!(
        crate::log_capture::contains(&format!("graceful_shutdown({pid})", pid = id.pid())),
        "the subsumption trace must fire on the forced watch error"
    );
```

   (Tree twins match `graceful_shutdown_tree({pid})`. The remaining sweep sites —
   signal_cancel's release-unwind trace, the treewalk drops, the kill_tree both-fail
   line — have NO existing test that forces their condition and would each need a new
   fault seam to drive; recorded as a reasoned partial in the dispositions, mirroring the
   size-mismatch-arm precedent.)

- [ ] **Step 2: Comment trim** — `tests/tokio_io.rs` ~:574 (the reverify advisory, adopted
verbatim): replace

```rust
    // Regression test: stdin, stdout, stderr's take-semantics when NOT merge targets.
    // (The pre-pass skips slots it assigns; this ensures stdin/stdout/stderr still behave
    // correctly for non-merge configurations.)
```

with

```rust
    // Regression: the pre-pass skips slots it does not assign, so stdin/stdout/stderr keep
    // plain take-semantics in a non-merge config.
```

(Match the file's exact current text when editing — if the first line differs slightly,
keep its role: one comment, one why.)

- [ ] **Step 3: getrandom bump attempt** — in `Cargo.toml`, change the windows-only
`getrandom = { version = "0.3", features = ["std"] }` to version `"0.4"` (check the 0.4
docs for the feature carrying the `std::io::Error`/`std::error::Error` conversion — keep
whatever feature provides it; `getrandom::fill(&mut [u8])` must still exist). Then
`cargo update -p getrandom` and verify `Cargo.lock` no longer contains TWO getrandom
majors. If 0.4 breaks the call site or feature set, REVERT to 0.3 fully and record the
decline (with the exact error) in the task report — do not force it.

Run: `cargo test --locked --features tokio > .tmp/claude/p11-t2-host.txt 2>&1`
Expected: all green (the getrandom call site is `src/tokio/stdio.rs` — Windows host covers it).

- [ ] **Step 4: Gates + WSL + commit**

Run the Global Constraints battery (fmt, clippy ×3, prek, host suites both modes, WSL).

```bash
git add src/wait/windows.rs src/containment/treewalk.rs src/child.rs src/tokio/child.rs src/child/graceful.rs src/tokio/child/graceful.rs tests/tokio_io.rs Cargo.toml Cargo.lock
git commit -m "feat: trace previously-silent failure paths; bump getrandom to 0.4"
```

(If the getrandom bump was declined, drop Cargo.toml/Cargo.lock from the add list and the
"; getrandom 0.4" clause from the message.)

- [ ] **Step 5: Branch CI** — push and watch; all 7 jobs green is the exit gate.

---

## Panel dispositions (settled — re-raise only with new evidence)

- **Local `kinfo_proc` definition** — dependency-first rule satisfied by evidence: libc
  0.2.186 has no `kinfo_proc`/`extern_proc` for apple (source-verified); nix has no darwin
  KERN_PROC; rust-psutil/sysinfo/std hand-define it. Recorded in the spec.
- **Layout risk disposition** — compile-time 648/296 tripwires + kernel-size oracle +
  live-token-vs-libproc oracle (CI-run). `proc_pidinfo` survives only as that oracle.
- **Enumeration stays proc_pidinfo** — out of scope with rationale (kill paths act on live
  processes); a non-goal, not a deferral of a known bug.
- **macOS iteration is CI-only** — accepted by construction of Step 7 (issue #2 records
  the same constraint).
- **pid-1 root branch stays Linux-only (round 1)** — XNU's launchd SIGKILL protection could
  not be decisively verified, CI cannot exercise the root branch (runners are non-root),
  and a wrong assumption panics a real machine; on non-Linux-as-root the test refuses to
  signal pid 1 with a loud explanation. Re-open only with an XNU `kern_sig.c` citation.
- **`kinfo()` failure disposition (round 1)** — the expected miss (pid gone: rc==0,
  size==0) is a bare `None`; a real sysctl errno or a wrong-sized record is a contract
  violation: debug tripwire + `log::warn!`, then `None` (the fd_read_end pattern). Both
  call sites inherit the disposition — no per-caller logging.
- **Round-1 doc-sweep expansions** — the tree-test header, the tokio twin file, the
  identity module doc's token-source list, and `assert_child_reaped`'s rationale joined
  Step 5; the macOS-vacuous-assert note added (a new darwin failure there is a surfaced
  latent bug, not a re-gate).
- **Round-1 conciseness cuts** — all seven adopted (one partially: kinfo.rs's module doc
  keeps the only-fields-read and triple-check clauses — the implementer's map to the
  verification scheme — while the dependency survey moved to a spec pointer).
- **Size oracle vs KERN_PROCSLOP (round 2)** — the NULL-buffer probe is unusable (XNU
  inflates it by 5×sizeof); the oracle fetches into a REAL buffer and asserts the WRITTEN
  size, the same quantity `kinfo()` checks. Verified against XNU `kern_sysctl.c` by the
  panel.
- **EINTR (round 2)** — retried inside `read_record` per the codebase convention
  (`wait/linux.rs`, `wait/macos.rs`); only non-EINTR errnos reach the tripwire.
- **Zombie-transition token stability (round 2)** — pinned by
  `identity_survives_the_alive_to_zombie_transition`: the token captured while ALIVE must
  compare equal against the zombie's freshly-read one (plus is_alive zombie-exclusivity
  and post-reap disappearance).
- **kinfo error-branch coverage (rounds 2–4)** — settled: rc!=0 arm driven via the
  selector test seam (synthetic, named honestly; seam precedent `wait::fault` — the
  round-4 tests member re-flagged per instruction and itself noted no action);
  `contract_violation` traces first, tripwires second, unit-tested with a CAPTURING
  logger so the release lane asserts the warn's captured record (not vacuous no-panic);
  the size-mismatch arm = the shared tested disposition + an unforceable if-condition,
  backstopped by the 648/296 asserts and the written-size oracle.
- **Round-2 conciseness cuts** — all five adopted verbatim.
- **EOF-vs-SZOMB race (round 3)** — the transition test's zombie-exclusive assert is
  pinned by `waitid(WEXITED | WNOWAIT)` (returns only once the child IS a zombie, without
  reaping) instead of EOF, which orders fd teardown but NOT the SZOMB transition. The
  test is `cfg(unix)`; Windows' post-exit window is covered by the first acceptance test.
- **Round-3 conciseness cuts** — all six adopted (comments folded into the redesigned
  code where the lines no longer exist verbatim).
- **HYBRID backend (round 4, architecture)** — adopted: `proc_pidinfo` primary,
  `kinfo` fallback only on a libproc miss. The decisive property: kinfo layout drift on an
  end-user OS version FAILS SAFE (zombie resolution degrades to the pre-fix zombie-blind
  behavior via a token mismatch) instead of silently corrupting the common live path. The
  cross-source token-equality invariant this introduces is exactly what the value oracle
  pins. `is_running` needs no fallback at all (libproc miss ⇒ gone-or-zombie ⇒ not
  running) — its shipped body is untouched.
- **signal_cancel policy (round 4)** — the shipped debug-aborts-even-during-unwind policy
  (deliberate, Plan-9-reviewed: "an abort is an acceptable price for visibility") is KEPT;
  the new `log::error!` covers the RELEASE-unwind gap only, and the comment now says
  exactly that (the round-4 draft's "never double-panic" claim was the defect — the
  comment contradicted the retained mechanism).
- **treewalk logging precision (round 4)** — the sweep names all SIX drop/skip sites with
  branch-accurate messages: unresolvable-pid vs impostor (token-mismatch) in BOTH
  `descendants_with` and `children_of_with`, and the identity-changed kill skip in BOTH
  the Unix and Windows `kill_by_identity`.
- **Round-4 conciseness cuts** — all six adopted.
- **Round 5 (conditionally-approved — final round)** — all five conditions applied: the
  release lane is darwin-gated (`if: matrix.os == 'darwin'`, the cgroup-step precedent);
  `bsd_info` gains the SAME disposition as the fallback (ESRCH/EPERM = calm expected
  misses; other errnos or a partial record = the shared `contract_violation`, which moved
  up to `macos.rs`); the Windows `kill_by_identity`'s discarded kill results gain the Unix
  twin's best-effort comment; the four graceful subsumption logs carry pids and are
  ASSERTED via the shared capturing logger in the four existing stranding twins (the
  remaining sweep sites have no forcing test and would each need a new fault seam —
  reasoned partial, the size-arm precedent); the root-on-non-Linux refusal PANICS
  ("inconclusive") instead of silently passing, per the repo's no-silent-skip rule. All
  five round-5 cuts adopted.
