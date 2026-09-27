//! Runtime-chosen fds can be >= 10. `/bin/sh` on Debian/Ubuntu is dash, whose `<&N` parses only a
//! single digit and fails with "Bad fd number" past 9 — so reads go through `/dev/fd/N`
//! (`read_fd`).

use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

#[cfg(target_os = "macos")]
use super::install_preserved;
use super::{install, FdMapping};

/// A throwaway file holding `content`, rewound to its start so a child reading it from the
/// beginning sees exactly `content`.
fn file_with(content: &str) -> File {
    let mut f = tempfile::tempfile().expect("tempfile");
    f.write_all(content.as_bytes()).expect("write tempfile");
    f.seek(SeekFrom::Start(0)).expect("seek to start");
    f
}

/// Spawn `/bin/sh -c script` with `mappings` installed exactly as a real `Command::fd()` caller
/// would, and return its captured stdout as a `String`.
fn run_sh(script: &str, mappings: Vec<FdMapping>) -> String {
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c").arg(script).stdout(Stdio::piped());
    install(&mut cmd, mappings).expect("install");
    let out = cmd.output().expect("spawn /bin/sh");
    assert!(out.status.success(), "child failed: {out:?}");
    String::from_utf8(out.stdout).expect("utf8 stdout")
}

/// A shell snippet that reads `fd` via `/dev/fd/N`, never via `<&N` (see the module docs).
fn read_fd(fd: RawFd) -> String {
    format!("cat /dev/fd/{fd}")
}

// Basic mapping =====

#[test]
fn a_simple_mapping_lands_the_parent_fd_on_the_requested_child_number() {
    let f = file_with("hello-fd5");
    let out = run_sh(
        &read_fd(5),
        vec![FdMapping {
            parent_fd: f.into(),
            child_fd: 5,
        }],
    );
    assert_eq!(out, "hello-fd5");
}

#[test]
fn empty_mappings_installs_nothing_and_spawns_normally() {
    assert_eq!(run_sh("echo ok", vec![]).trim(), "ok");
}

// The "already on the right number" branch: CLOEXEC cleared in place, fd survives exec =====

#[test]
fn a_mapping_onto_its_own_current_number_clears_cloexec_so_the_fd_survives_exec() {
    let f = file_with("self-mapped");
    let owned: OwnedFd = f.into();
    let raw = owned.as_raw_fd();
    let out = run_sh(
        &read_fd(raw),
        vec![FdMapping {
            parent_fd: owned,
            child_fd: raw,
        }],
    );
    assert_eq!(out, "self-mapped");
}

// Colliding mappings deliver each file's own content =====

/// Map file A onto file B's current number and file B onto file A's — the swap that, internally,
/// forces a collision-avoiding temporary-fd shuffle (mirrors command-fds' own `swap_mappings`
/// test). This only checks the externally visible outcome (each file's own content, uncorrupted);
/// it does not observe the shuffle itself, since any mechanism that resolves the collision without
/// corrupting either file's content would pass it too.
#[test]
fn colliding_mappings_deliver_each_files_own_content() {
    let a = file_with("AAA");
    let b = file_with("BBB");
    let a_owned: OwnedFd = a.into();
    let b_owned: OwnedFd = b.into();
    let a_raw = a_owned.as_raw_fd();
    let b_raw = b_owned.as_raw_fd();
    let out = run_sh(
        &format!("{}; {}", read_fd(b_raw), read_fd(a_raw)),
        vec![
            FdMapping {
                parent_fd: a_owned,
                child_fd: b_raw,
            },
            FdMapping {
                parent_fd: b_owned,
                child_fd: a_raw,
            },
        ],
    );
    // a's content now lives at b's old number (a -> b_raw), and vice versa.
    assert_eq!(
        out, "AAABBB",
        "the swap must deliver each file's OWN content, uncorrupted"
    );
}

/// Three-way rotation (A->B, B->C, C->A): the simple two-mapping swap above cannot catch a
/// shuffle that only handles ONE collision at a time.
#[test]
fn a_three_way_rotation_of_colliding_mappings_resolves_correctly() {
    let a = file_with("AAA");
    let b = file_with("BBB");
    let c = file_with("CCC");
    let a_owned: OwnedFd = a.into();
    let b_owned: OwnedFd = b.into();
    let c_owned: OwnedFd = c.into();
    let a_raw = a_owned.as_raw_fd();
    let b_raw = b_owned.as_raw_fd();
    let c_raw = c_owned.as_raw_fd();
    let out = run_sh(
        &format!("{}; {}; {}", read_fd(a_raw), read_fd(b_raw), read_fd(c_raw)),
        vec![
            FdMapping {
                parent_fd: c_owned,
                child_fd: a_raw,
            },
            FdMapping {
                parent_fd: a_owned,
                child_fd: b_raw,
            },
            FdMapping {
                parent_fd: b_owned,
                child_fd: c_raw,
            },
        ],
    );
    assert_eq!(out, "CCCAAABBB");
}

// A duplicate child fd is rejected in every build profile =====

/// Two mappings that both target `child_fd: 5` must be rejected by `install` itself, as an
/// ordinary `io::Error`, in a RELEASE build exactly as reliably as in a debug build. Both
/// production callers build their mapping set from a `BTreeMap<Fd, _>`, whose keys are already
/// unique, so this is unreachable from them — but `install` takes a plain `Vec<FdMapping>`, and
/// nothing about that signature stops some OTHER caller (present or future) from handing it a
/// duplicate. A check that only fires via `debug_assert!` protects debug builds and nothing else:
/// in release, `Plan::apply`'s pass 2 would dup2 both mappings onto fd 5 in order, so the second
/// mapping's source silently wins and the first is silently misrouted with no error and no crash
/// — a strictly weaker disposition than an explicit `Err`.
#[test]
fn install_rejects_a_duplicate_child_fd_in_every_build_profile() {
    let a = file_with("A");
    let b = file_with("B");
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c").arg("true");
    let err = install(
        &mut cmd,
        vec![
            FdMapping {
                parent_fd: a.into(),
                child_fd: 5,
            },
            FdMapping {
                parent_fd: b.into(),
                child_fd: 5,
            },
        ],
    )
    .expect_err("a duplicate child fd must be rejected by install itself, in every build profile");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::InvalidInput,
        "expected InvalidInput (mirrors Command::fd's own negative-fd rejection), got {err:?}"
    );
}

// preserved_fds equivalent =====

#[cfg(target_os = "macos")]
#[test]
fn install_preserved_clears_cloexec_so_the_fd_survives_exec() {
    let f = file_with("preserved");
    let owned: OwnedFd = f.into();
    let raw = owned.as_raw_fd();
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c").arg(read_fd(raw)).stdout(Stdio::piped());
    install_preserved(&mut cmd, vec![owned]);
    let out = cmd.output().expect("spawn");
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "preserved");
}

/// Baseline for the previous test: the identical setup MINUS `install_preserved` must NOT
/// survive exec (`std`'s `File`/`OwnedFd` is `FD_CLOEXEC` by default) — proves the previous
/// test is actually exercising the CLOEXEC-clearing code path, not passing by accident (e.g.
/// because `/bin/sh` itself happened to inherit the fd some other way).
#[cfg(target_os = "macos")]
#[test]
fn without_install_preserved_the_fd_is_closed_at_exec() {
    let f = file_with("not-preserved");
    let owned: OwnedFd = f.into();
    let raw = owned.as_raw_fd();
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg(format!("{} 2>/dev/null || echo CLOSED", read_fd(raw)))
        .stdout(Stdio::piped());
    let out = cmd.output().expect("spawn");
    drop(owned); // keep it alive in the parent until after spawn, exactly like a real caller
    assert_eq!(String::from_utf8(out.stdout).unwrap().trim(), "CLOSED");
}

// Very large child fds fail at spawn, not at install =====

/// `child_fd == i32::MAX` must be ACCEPTED by `install` in the parent — its per-mapping
/// `F_DUPFD_CLOEXEC` search starts at 3 and never computes `i32::MAX + 1` at all — and fails only
/// later, in the child, at `dup2`: an ordinary `EBADF`, not a parent-side refusal and not an
/// abort.
#[test]
fn an_i32_max_child_fd_fails_at_spawn_not_at_install() {
    let f = file_with("x");
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c").arg("true").stdout(Stdio::piped());
    install(
        &mut cmd,
        vec![FdMapping {
            parent_fd: f.into(),
            child_fd: i32::MAX,
        }],
    )
    .expect("i32::MAX must be accepted by install");
    let err = cmd
        .spawn()
        .and_then(|c| c.wait_with_output())
        .expect_err("dup2 onto i32::MAX must fail the spawn with an Err, not abort the child");
    // EBADF (or whatever the target OS reports for an out-of-range dup2 target) — not a crash,
    // not a hang, just a normal io::Error.
    assert!(err.raw_os_error().is_some(), "expected an OS error, got {err:?}");
}

/// An out-of-range but representable child fd (e.g. one far beyond any real process' open-file
/// limit) is NOT a parent-side rejection — `install` accepts it, and the resulting spawn fails
/// at `dup2` in the child instead, surfaced as an ordinary `Err` from `Command::spawn` rather
/// than an abort. This is the process-level regression test; `cosca::Command::fd`-level coverage
/// lives in `tests/spawn_io.rs`.
///
/// Lowers the CHILD's own `RLIMIT_NOFILE` to 256 via a `pre_exec` hook registered BEFORE
/// `install`'s (the same technique `a_distant_high_target_...` above already uses), so
/// `1_000_000` is guaranteed out of range for THIS spawn regardless of the host's own ambient
/// `ulimit -n`. Without it, this would depend on the runner: on Linux, a soft limit raised past
/// `1_000_000` is entirely ordinary (see `tests/common::RestoreRlimitNofile`'s doc), so the same
/// `dup2` this test expects to fail could instead succeed.
#[test]
fn an_out_of_range_but_representable_child_fd_fails_at_spawn_not_at_install() {
    let f = file_with("x");
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c").arg("true").stdout(Stdio::piped());

    // SAFETY: `pre_exec` runs post-fork, pre-exec, in the child only; `setrlimit` is a checked,
    // non-allocating raw syscall. Registered BEFORE `install` below, since `install` documents
    // that its own hook must be registered LAST.
    unsafe {
        cmd.pre_exec(|| {
            let lim = libc::rlimit {
                rlim_cur: 256,
                rlim_max: 256,
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &lim) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    install(
        &mut cmd,
        vec![FdMapping {
            parent_fd: f.into(),
            child_fd: 1_000_000,
        }],
    )
    .expect("1_000_000 must be accepted by install (representable, just not achievable)");
    let err = cmd
        .spawn()
        .and_then(|c| c.wait_with_output())
        .expect_err("dup2 onto an unachievable fd number must fail the spawn with an Err, not abort the child");
    // EBADF (or whatever the target OS reports for an out-of-range dup2 target) — not a crash,
    // not a hang, just a normal io::Error.
    assert!(err.raw_os_error().is_some(), "expected an OS error, got {err:?}");
}

// One distant child_fd must not inflate every temporary past a tight RLIMIT_NOFILE =====

/// A single distant `child_fd` (here 255) must not push every OTHER mapping's temporary-fd
/// search above it too — even when the collision that actually needs a temporary (the A/B swap
/// below) has plenty of free numbers well below that ceiling. Under a tight `RLIMIT_NOFILE` (256,
/// so fd 255 is the highest valid number), this module's per-mapping `F_DUPFD_CLOEXEC(fd, 3)`
/// search must resolve the swap using a low temporary, independent of the numerically distant
/// 255 target.
#[test]
fn a_distant_high_target_does_not_inflate_every_other_temporary_past_a_tight_rlimit() {
    let a = file_with("AAA");
    let b = file_with("BBB");
    let c = file_with("CCC");
    let a_owned: OwnedFd = a.into();
    let b_owned: OwnedFd = b.into();
    let c_owned: OwnedFd = c.into();
    let a_raw = a_owned.as_raw_fd();
    let b_raw = b_owned.as_raw_fd();

    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg(format!("{}; {}", read_fd(b_raw), read_fd(a_raw)))
        .stdout(Stdio::piped());

    // Lower the CHILD's RLIMIT_NOFILE to 256 before `install`'s own pre_exec hook runs.
    // `pre_exec` hooks run in registration order, and `install` documents that its own hook
    // must be registered LAST — so registering this one first mirrors that same ordering
    // constraint containment hooks rely on in production.
    unsafe {
        cmd.pre_exec(|| {
            let lim = libc::rlimit {
                rlim_cur: 256,
                rlim_max: 256,
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &lim) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    install(
        &mut cmd,
        vec![
            FdMapping {
                parent_fd: a_owned,
                child_fd: b_raw,
            },
            FdMapping {
                parent_fd: b_owned,
                child_fd: a_raw,
            },
            // Numerically distant but still a valid fd under the 256 rlimit (0..255) — must not push
            // the swap's temporary search past the rlimit ceiling.
            FdMapping {
                parent_fd: c_owned,
                child_fd: 255,
            },
        ],
    )
    .expect("install");

    let out = cmd.output().expect("spawn /bin/sh");
    assert!(out.status.success(), "child failed: {out:?}");
    assert_eq!(
        out.stdout, b"AAABBB",
        "the swap must still resolve correctly even with a numerically distant child_fd \
         elsewhere in the mapping set"
    );
}

// A parent_fd below fd 3 must not be clobbered by std's own stdio dup2 =====

/// Require that this test is running alone in its own process, via
/// [`crate::containment::cgroup::test_support::alone`], before any caller closes a process-wide
/// fd. A plain `cargo test`/`cargo test --lib` run shares one process across every test thread in
/// the binary, so closing a real fd 0/1/2 there races with, and can corrupt, whatever unrelated
/// test's thread next opens something and gets handed the freed number.
///
/// The one accepted proof of isolation is `COSCA_TEST_ALONE=<name>` where this process's own argv
/// is exactly `[<name>, ALONE_ARGS...]` —
/// [`crate::containment::cgroup::test_support::alone_marker_matches`] — set by `alone` on the
/// fresh, single-test copy of this binary it re-execs. Checking argv, not just the env var's
/// presence, is load bearing: see `alone_marker_matches`'s doc for the inherited/forged-env-var
/// corruption this closes.
///
/// Deliberately does NOT also accept nextest's own `NEXTEST_EXECUTION_MODE=process-per-test`:
/// every guarded caller goes through `alone` now (itself safe under nextest too — its own
/// `alone_marker_matches` check simply never matches there, so it re-execs same as under plain
/// `cargo test`), and `NEXTEST_EXECUTION_MODE` is just as forgeable as `COSCA_TEST_ALONE` ever
/// was — accepting it would reopen a second, unnecessary escape hatch.
///
/// A copy of `tests/common/mod.rs`'s identical helper — this file is part of the lib's OWN
/// unit-test build (`#[cfg(test)]`, compiled only for `cargo test --lib`/`cargo nextest run`
/// against the lib target), a separate compilation unit from `tests/common/mod.rs` (compiled
/// once per integration-test binary in `tests/*.rs`), and cannot name that one. It DOES share
/// `alone_marker_matches`/`ALONE_ARGS` with `crate::containment::cgroup::test_support::alone`,
/// its OWN compilation unit's copy of the re-exec helper. Fails loudly and immediately, before
/// touching anything, rather than silently skipping: see cosca#196 for the long-term structural
/// fix (serializing every process-wide-fd test into one group, so this stops depending on `alone`
/// specifically).
fn require_process_per_test(what: &str) {
    use crate::containment::cgroup::test_support::alone_marker_matches;
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let alone = alone_marker_matches(std::env::var("COSCA_TEST_ALONE").ok().as_deref(), &argv);
    assert!(
        alone,
        "{what}; call this from inside crate::containment::cgroup::test_support::alone() — see \
         cosca#196"
    );
}

/// Real fd 2 to `dup2` back before the panic hook's chained write runs, if a [`RestoreFd2`] is
/// currently holding fd 2 closed — `None` when no guard has fd 2 closed. Read only by the ONE
/// process-wide hook [`ensure_stderr_panic_hook`] installs; written only by [`RestoreFd2::take`]
/// (sets) and its `Drop` (clears).
///
/// **`Drop` ONLY EVER clears this slot — it never calls [`std::panic::set_hook`] itself.**
/// Measured: calling `set_hook` from `Drop` panics ("cannot modify the panic hook from a
/// panicking thread") whenever that `Drop` runs during unwinding — which it always might, since
/// unwinding is the ordinary reason a guard drops — and a panic during unwind is not caught: the
/// process aborts (`SIGABRT`, exit 134), turning an ordinary test failure into a hard crash. That
/// is worse than the very bug this file's panic-hook mechanism exists to fix. Installing the hook
/// exactly ONCE, process-wide, and having it read this slot at panic time — rather than being
/// reinstalled and un-installed per guard — is what makes `Drop` never need to touch the hook at
/// all. A copy of `tests/common/mod.rs`'s identical mechanism on `RestoreStdio`.
static SAVED_STDERR: std::sync::Mutex<Option<libc::c_int>> = std::sync::Mutex::new(None);

/// Lock [`SAVED_STDERR`], recovering from poison rather than panicking: this mutex is read from
/// inside a panic hook and written from `Drop` during unwind, both places where panicking AGAIN
/// (on a poisoned lock) is the one outcome that must never happen — see [`SAVED_STDERR`]'s doc.
fn saved_stderr() -> std::sync::MutexGuard<'static, Option<libc::c_int>> {
    SAVED_STDERR.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Install the ONE, process-wide panic hook that restores real fd 2 from [`SAVED_STDERR`] (if
/// occupied) before chaining to whatever hook was previously installed. Idempotent via `Once`:
/// safe to call from every [`RestoreFd2::take`].
fn ensure_stderr_panic_hook() {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if let Some(real_stderr) = *saved_stderr() {
                // SAFETY: `real_stderr` is a live dup of the original fd 2, owned by whichever
                // `RestoreFd2` currently occupies `SAVED_STDERR` — its `Drop` clears the slot
                // before that dup closes, so a `Some` read here is always still valid.
                unsafe { libc::dup2(real_stderr, 2) };
            }
            previous(info);
        }));
    });
}

/// Dup fd 2 aside and close the original, so the CURRENT test process's fd 2 is free for the
/// test to reuse — restoring it on drop even if the test panics.
///
/// `take` asserts [`require_process_per_test`] before touching anything: see there for why.
///
/// **A panic while this guard is alive would otherwise lose its own message** — see
/// [`SAVED_STDERR`]/[`ensure_stderr_panic_hook`] for the mechanism that fixes this and why `Drop`
/// never touches the hook itself.
struct RestoreFd2 {
    saved: OwnedFd,
}

impl RestoreFd2 {
    fn take() -> RestoreFd2 {
        require_process_per_test("closes process-wide fd 2");
        // SAFETY: F_DUPFD_CLOEXEC(2, 3) duplicates fd 2 to a fresh number >= 3, checked below.
        let saved = unsafe { libc::fcntl(2, libc::F_DUPFD_CLOEXEC, 3) };
        assert!(saved >= 0, "dup fd 2 aside before closing it");
        // SAFETY: `saved` was just returned by a successful F_DUPFD_CLOEXEC.
        let saved = unsafe { OwnedFd::from_raw_fd(saved) };
        let saved_fd = saved.as_raw_fd();
        // See `SAVED_STDERR`'s doc for the mechanism.
        ensure_stderr_panic_hook();
        // Set the slot ONLY if it is currently unoccupied — an overlapping second guard must NOT
        // steal it from a still-live first one. Measured: overwriting here routed a later panic's
        // message into whatever the SECOND guard's own dup pointed at instead of real stderr —
        // silently worse than not fixing the message-loss bug at all. And this all happens BEFORE
        // `close(2)` below — not after: Linux frees a fd from the table even when `close` itself
        // reports failure (EINTR, EIO, ...), so if the `close` assert below panics, the slot must
        // ALREADY be armed, or the panic message is lost exactly as if `close` had silently
        // "succeeded" while this function never found out.
        //
        // NOT held across the debug_assert below, deliberately: `Mutex::lock()`'s temporary guard
        // drops at the end of ITS OWN statement, before the assert below can panic. Measured:
        // holding the guard across the assert deadlocks — the panic hook this function just armed
        // (`ensure_stderr_panic_hook`) tries to lock this SAME mutex, on this SAME thread, as the
        // FIRST thing that happens when the assert panics (a hook runs before any unwinding, so a
        // guard from `let mut slot = saved_stderr();` would still be alive) — a plain
        // `std::sync::Mutex` is not reentrant, so that second `.lock()` call blocks forever on a
        // lock its own thread already holds.
        let prev = {
            let mut slot = saved_stderr();
            let prev = *slot;
            if prev.is_none() {
                *slot = Some(saved_fd);
            }
            prev
        };
        debug_assert!(
            prev.is_none(),
            "RestoreFd2: SAVED_STDERR already occupied (by fd {prev:?}) when this guard tried to \
             set it to {saved_fd} — a previous guard's fd 2 was never cleared, or two guards \
             overlap. Reachable even from a single alone()-isolated test: e.g. opening a second \
             RestoreFd2 (or RestoreStdio) on fd 2 before the first one drops."
        );
        assert_eq!(unsafe { libc::close(2) }, 0, "close the test process' fd 2");
        RestoreFd2 { saved }
    }
}

impl Drop for RestoreFd2 {
    fn drop(&mut self) {
        // Restore fd 2 WITHOUT panicking here directly — record the failure instead — so this
        // function never panics TWICE: once here (if the `dup2` below failed) and, if this `Drop`
        // itself is already running as part of unwinding an EARLIER panic, a SECOND panic during
        // unwind is not caught — the process aborts. Reported once, below.
        //
        // SAFETY: dup2 back onto 2; `self.saved` stays valid (and is closed normally by its own
        // Drop) regardless of this call's outcome.
        //
        // Retries EINTR the same way `fd_map::dup2_onto` does, so a signal landing mid-restore
        // cannot leave fd 2 unrestored.
        let ret = loop {
            let ret = unsafe { libc::dup2(self.saved.as_raw_fd(), 2) };
            if ret != -1 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                break ret;
            }
        };
        let failure = if ret != 2 {
            Some(format!(
                "dup2({}, 2) while restoring fd 2 failed: {}",
                self.saved.as_raw_fd(),
                std::io::Error::last_os_error()
            ))
        } else {
            None
        };
        // Clear the process-wide slot only AFTER the restore above has been attempted, and only
        // if it STILL holds THIS guard's own dup — not some other, still-live guard's (one whose
        // own registration was REJECTED in `take` because a prior guard already occupied the
        // slot must NOT clear that prior guard's still-valid registration when IT drops). This
        // NEVER calls `std::panic::set_hook`: see `SAVED_STDERR`'s doc for why that would turn an
        // ordinary panic into a process abort.
        let my_fd = self.saved.as_raw_fd();
        let mut slot = saved_stderr();
        if *slot == Some(my_fd) {
            *slot = None;
        }
        drop(slot);
        if let Some(msg) = failure {
            // A NEW panic here, while this `Drop` is ALREADY running as part of unwinding an
            // earlier panic, would abort the process — worse than the failure it would be
            // reporting. Report loudly without panicking in that case; panic normally otherwise,
            // so an ordinary (non-unwind) restore failure still fails its test.
            if std::thread::panicking() {
                eprintln!("RestoreFd2::drop: {msg} (not panicking: already unwinding)");
            } else {
                panic!("RestoreFd2::drop: {msg}");
            }
        }
    }
}

/// Wait for `child` to exit, bounded by `timeout` — killing it and failing loudly if it does
/// not, rather than blocking forever. A copy of `tests/common/mod.rs`'s identical helper: this
/// file is a separate compilation unit and cannot name that one. See there for the full
/// rationale (the bound is a FAILURE SURFACE for a genuine, otherwise-unbounded hang, not a
/// synchronization mechanism) and for why `child` stays owned by THIS thread for its whole life
/// (reaped only here, never on the background thread) — an earlier version raced a background
/// thread's `wait_with_output` reap against this thread killing the bare pid number on timeout,
/// a genuine pid-reuse hazard once the child was reaped elsewhere.
fn wait_bounded(mut child: std::process::Child, timeout: std::time::Duration) -> std::process::Output {
    let pid = child.id();
    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::io::Read;
        // Drain stdout and stderr CONCURRENTLY, each on its own thread — like std's own `read2`
        // internals — not one after the other. A child that writes more than one pipe buffer
        // (commonly 64 KiB) to stderr while producing little or no stdout would otherwise
        // deadlock this function: reading stdout to EOF blocks until the child exits, but the
        // child is itself blocked writing to a stderr pipe nobody is draining. Measured with 200
        // KB of stderr.
        let stdout_thread = std::thread::spawn(move || {
            let mut stdout = Vec::new();
            if let Some(mut p) = stdout_pipe.take() {
                let _ = p.read_to_end(&mut stdout);
            }
            stdout
        });
        let mut stderr = Vec::new();
        if let Some(mut p) = stderr_pipe.take() {
            let _ = p.read_to_end(&mut stderr);
        }
        let stdout = stdout_thread.join().expect("join the stdout-draining thread");
        // Confirm the child has exited WITHOUT reaping it (`WNOWAIT`) — reaping stays on the
        // caller's thread below, the only place allowed to touch the `Child` it still owns.
        let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
        loop {
            // SAFETY: `si` is a valid, correctly-sized out-param; `pid` is our own unreaped child.
            let rc = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut si, libc::WEXITED | libc::WNOWAIT) };
            if rc == 0 {
                break;
            }
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::Interrupted {
                break;
            }
        }
        let _ = tx.send((stdout, stderr));
    });
    match rx.recv_timeout(timeout) {
        Ok((stdout, stderr)) => {
            let status = child.wait().expect("reap the child, already confirmed exited");
            std::process::Output { status, stdout, stderr }
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            // `child` is still ours, unreaped: `kill`/`wait` target the exact process the OS
            // handed us, never a recycled pid — see the doc above.
            let _ = child.kill();
            let status = child.wait().expect("reap the child after killing it");
            panic!(
                "child pid {pid} did not exit within {timeout:?} — it hung instead of exiting \
                 (cleanly or otherwise), which is itself the regression under test. Killed it \
                 and reaped exit status {status:?}."
            );
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            panic!("child pid {pid}'s wait thread died without sending a result")
        }
    }
}

/// Run `probe_name` — a `#[test]` in THIS SAME test binary — directly with the exact
/// `alone()`-isolated shape (`COSCA_TEST_ALONE` set to `probe_name`, plus the full
/// `crate::containment::cgroup::test_support::ALONE_ARGS`), with `extra_env` also set, and
/// return its captured output. A copy of `tests/common/mod.rs`'s identical helper — see there
/// for why "directly" (skipping a second `alone()` re-exec layer) is load bearing, and why the
/// wait is bounded via [`wait_bounded`].
fn run_probe_directly(probe_name: &str, extra_env: &[(&str, &str)]) -> std::process::Output {
    use crate::containment::cgroup::test_support::ALONE_ARGS;
    let mut cmd = std::process::Command::new(std::env::current_exe().expect("this test binary"));
    cmd.arg(probe_name)
        .args(ALONE_ARGS)
        .env("COSCA_TEST_ALONE", probe_name)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for &(k, v) in extra_env {
        cmd.env(k, v);
    }
    let child = {
        let _guard = crate::child::spawn::spawn_lock();
        cmd.spawn().expect("spawn the probe")
    };
    wait_bounded(child, std::time::Duration::from_secs(30))
}

/// `wait_bounded` must drain stdout and stderr CONCURRENTLY, not one after the other — the lib's
/// own copy of `tests/spawn_io.rs`'s `wait_bounded_drains_stdout_and_stderr_concurrently`. See
/// there for the deadlock this catches.
#[test]
fn wait_bounded_drains_stdout_and_stderr_concurrently() {
    const STDERR_BYTES: usize = 200_000;
    let mut cmd = std::process::Command::new("/bin/sh");
    cmd.arg("-c")
        .arg(format!("head -c {STDERR_BYTES} /dev/zero | tr '\\0' 'x' 1>&2"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = {
        let _guard = crate::child::spawn::spawn_lock();
        cmd.spawn().expect("spawn the child")
    };
    let out = wait_bounded(child, std::time::Duration::from_secs(30));
    assert!(out.status.success(), "the child must exit cleanly: {:?}", out.status);
    assert_eq!(
        out.stderr.len(),
        STDERR_BYTES,
        "must drain all of stderr, not hang or truncate it while stdout sits empty"
    );
}

/// A deliberate, always-panicking probe for `RestoreFd2`'s panic-hook fix — the lib's own copy
/// of `tests/spawn_io.rs`'s `panic_while_fd2_closed_probe`, proving the SAME mechanism
/// (`SAVED_STDERR`/`ensure_stderr_panic_hook`) on `RestoreFd2`, not just `RestoreStdio`.
/// `#[ignore]`d; see that sibling's doc for why a bare `--include-ignored` sweep still executes
/// but now fails loudly instead of no-oping (its own env-var gate below).
#[test]
#[ignore = "probe"]
fn panic_while_fd2_closed_via_restore_fd2_probe() {
    assert!(
        std::env::var_os("COSCA_TEST_TRIGGER_PANIC_WHILE_FD2_CLOSED_VIA_RESTORE_FD2_PROBE").is_some(),
        "this probe must only be invoked via \
         a_panic_while_fd2_is_closed_via_restore_fd2_still_reaches_stderr (which sets \
         COSCA_TEST_TRIGGER_PANIC_WHILE_FD2_CLOSED_VIA_RESTORE_FD2_PROBE) — a bare \
         --include-ignored sweep that reaches here without it is not exercising the probe, and \
         must not pass vacuously"
    );
    if !crate::containment::cgroup::test_support::alone(
        "child::spawn::fd_map::fd_map_tests::panic_while_fd2_closed_via_restore_fd2_probe",
    ) {
        return;
    }
    let _restore = RestoreFd2::take();
    panic!("PANIC_WHILE_FD2_CLOSED_VIA_RESTORE_FD2_PROBE_MARKER: this message must survive fd 2 being closed");
}

/// Proves `RestoreFd2`'s panic-hook fix. Without a dedicated lib prover, reverting the lib half
/// of that fix left every lib test passing — nothing exercised it. Asserts the probe's own exit
/// code is EXACTLY `101` (see `tests/spawn_io.rs`'s sibling prover's doc for why: an abort has no
/// defined exit code, commonly reported as 134/SIGABRT, and `run_probe_directly`'s "directly"
/// invocation is what stops a second `alone()` layer from masking that as an ordinary 101 one
/// level up) and that the marker reached stderr.
#[test]
fn a_panic_while_fd2_is_closed_via_restore_fd2_still_reaches_stderr() {
    const PROBE: &str = "child::spawn::fd_map::fd_map_tests::panic_while_fd2_closed_via_restore_fd2_probe";
    let out = run_probe_directly(
        PROBE,
        &[("COSCA_TEST_TRIGGER_PANIC_WHILE_FD2_CLOSED_VIA_RESTORE_FD2_PROBE", "1")],
    );
    assert_eq!(
        out.status.code(),
        Some(101),
        "the probe must fail with an ordinary libtest panic exit (101) — anything else, \
         including an abort with no exit code at all, means its own panic was not a clean test \
         failure. got {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("PANIC_WHILE_FD2_CLOSED_VIA_RESTORE_FD2_PROBE_MARKER"),
        "the probe's own panic message must survive fd 2 being closed while it panicked — got:\n{combined}"
    );
}

/// A deliberate probe for the `SAVED_STDERR` self-deadlock fix on `RestoreFd2` — the lib's own
/// copy of `tests/spawn_io.rs`'s `two_overlapping_fd2_closes_probe`. See that sibling's doc for
/// why the intervening `tempfile::tempfile()` matters.
#[test]
#[ignore = "probe"]
fn two_overlapping_fd2_closes_via_restore_fd2_probe() {
    assert!(
        std::env::var_os("COSCA_TEST_TRIGGER_TWO_OVERLAPPING_FD2_CLOSES_VIA_RESTORE_FD2_PROBE").is_some(),
        "this probe must only be invoked via \
         two_overlapping_fd2_closes_via_restore_fd2_do_not_deadlock (which sets \
         COSCA_TEST_TRIGGER_TWO_OVERLAPPING_FD2_CLOSES_VIA_RESTORE_FD2_PROBE) — a bare \
         --include-ignored sweep that reaches here without it is not exercising the probe, and \
         must not pass vacuously"
    );
    if !crate::containment::cgroup::test_support::alone(
        "child::spawn::fd_map::fd_map_tests::two_overlapping_fd2_closes_via_restore_fd2_probe",
    ) {
        return;
    }
    let _first = RestoreFd2::take();
    let _file = tempfile::tempfile().expect("open a file that lands at the freed fd 2");
    let _second = RestoreFd2::take(); // must panic cleanly, not deadlock
}

/// Proves the `SAVED_STDERR` self-deadlock fix on `RestoreFd2`. Bounded via [`wait_bounded`], so
/// a hang fails this test loudly instead of hanging the whole suite — the ONE assertion that
/// holds in every build profile, checked below regardless of debug assertions.
///
/// The overlap itself is only DIAGNOSED by a `debug_assert!` (a test-only, "two guards should
/// never overlap" internal invariant — not a release-mode API contract the way
/// `fd_map::install`'s duplicate-child-fd rejection is), so it only panics in a build with debug
/// assertions on. Measured: CI's own release lane (`--release`, debug assertions off) runs this
/// same probe and it completes normally instead — `take` never overwrites an occupied
/// `SAVED_STDERR` slot (occupied or not), so the second, overlapping guard simply never gets
/// registered there; its own `Drop` sees the slot does not hold its fd and leaves the first
/// guard's registration alone, so the mechanism stays correct either way.
#[test]
fn two_overlapping_fd2_closes_via_restore_fd2_do_not_deadlock() {
    const PROBE: &str = "child::spawn::fd_map::fd_map_tests::two_overlapping_fd2_closes_via_restore_fd2_probe";
    let out = run_probe_directly(
        PROBE,
        &[(
            "COSCA_TEST_TRIGGER_TWO_OVERLAPPING_FD2_CLOSES_VIA_RESTORE_FD2_PROBE",
            "1",
        )],
    );
    let expected = if cfg!(debug_assertions) { Some(101) } else { Some(0) };
    assert_eq!(
        out.status.code(),
        expected,
        "the second, overlapping RestoreFd2::take() must{} — got {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        if cfg!(debug_assertions) {
            " panic cleanly (exit 101), not hang or abort"
        } else {
            " complete normally (exit 0): this build has debug assertions off, so the \
             SAVED_STDERR-occupied debug_assert is a no-op"
        },
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if cfg!(debug_assertions) {
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            combined.contains("SAVED_STDERR already occupied"),
            "the overlap panic's own message must reach stderr (proving the fix routes it there \
             instead of into whatever fd the second, rejected guard's own dup pointed at) — got:\n{combined}"
        );
    }
}

/// A deliberate probe reproducing the same overlap as
/// `two_overlapping_fd2_closes_via_restore_fd2_probe`, but panicking with a MARKER right after
/// both guards exist — the lib's own copy of `tests/spawn_io.rs`'s
/// `two_overlapping_fd2_closes_then_panic_probe`. See there for why this observes, in a RELEASE
/// build, whether `SAVED_STDERR` still holds the FIRST guard's dup or the SECOND's.
#[test]
#[ignore = "probe"]
fn two_overlapping_fd2_closes_via_restore_fd2_then_panic_probe() {
    assert!(
        std::env::var_os("COSCA_TEST_TRIGGER_TWO_OVERLAPPING_FD2_CLOSES_VIA_RESTORE_FD2_THEN_PANIC_PROBE").is_some(),
        "this probe must only be invoked via \
         two_overlapping_fd2_closes_via_restore_fd2_then_panic_lands_on_the_right_stderr (which \
         sets COSCA_TEST_TRIGGER_TWO_OVERLAPPING_FD2_CLOSES_VIA_RESTORE_FD2_THEN_PANIC_PROBE) — a \
         bare --include-ignored sweep that reaches here without it is not exercising the probe, \
         and must not pass vacuously"
    );
    if !crate::containment::cgroup::test_support::alone(
        "child::spawn::fd_map::fd_map_tests::two_overlapping_fd2_closes_via_restore_fd2_then_panic_probe",
    ) {
        return;
    }
    let _first = RestoreFd2::take();
    let _file = tempfile::tempfile().expect("open a file that lands at the freed fd 2");
    let _second = RestoreFd2::take();
    panic!(
        "TWO_OVERLAPPING_FD2_CLOSES_VIA_RESTORE_FD2_THEN_PANIC_MARKER: this message must land on \
         the real, originally-captured stderr, not wherever the second guard's own dup points"
    );
}

/// Proves the "set only if empty" half of the `SAVED_STDERR` overlap fix on `RestoreFd2` by
/// OBSERVABLE behavior — the lib's own copy of `tests/spawn_io.rs`'s
/// `two_overlapping_fd2_closes_then_panic_lands_on_the_right_stderr`. See there for why the
/// marker check only applies in release builds.
#[test]
fn two_overlapping_fd2_closes_via_restore_fd2_then_panic_lands_on_the_right_stderr() {
    const PROBE: &str =
        "child::spawn::fd_map::fd_map_tests::two_overlapping_fd2_closes_via_restore_fd2_then_panic_probe";
    let out = run_probe_directly(
        PROBE,
        &[(
            "COSCA_TEST_TRIGGER_TWO_OVERLAPPING_FD2_CLOSES_VIA_RESTORE_FD2_THEN_PANIC_PROBE",
            "1",
        )],
    );
    assert_eq!(
        out.status.code(),
        Some(101),
        "the probe must fail with an ordinary libtest panic exit (101) in both build profiles — \
         got {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if !cfg!(debug_assertions) {
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            combined.contains("TWO_OVERLAPPING_FD2_CLOSES_VIA_RESTORE_FD2_THEN_PANIC_MARKER"),
            "the probe's own panic message must reach the real captured stderr, not the second \
             guard's own dup — got:\n{combined}"
        );
    }
}

/// A deliberate probe reproducing the same overlap once more, but explicitly dropping the SECOND
/// guard (and the tempfile) before panicking, with the FIRST guard still alive — the lib's own
/// copy of `tests/spawn_io.rs`'s `two_overlapping_fd2_closes_then_drop_second_then_panic_probe`.
#[test]
#[ignore = "probe"]
fn two_overlapping_fd2_closes_via_restore_fd2_then_drop_second_then_panic_probe() {
    assert!(
        std::env::var_os(
            "COSCA_TEST_TRIGGER_TWO_OVERLAPPING_FD2_CLOSES_VIA_RESTORE_FD2_THEN_DROP_SECOND_THEN_PANIC_PROBE"
        )
        .is_some(),
        "this probe must only be invoked via \
         two_overlapping_fd2_closes_via_restore_fd2_then_drop_second_then_panic_lands_on_the_right_stderr \
         (which sets \
         COSCA_TEST_TRIGGER_TWO_OVERLAPPING_FD2_CLOSES_VIA_RESTORE_FD2_THEN_DROP_SECOND_THEN_PANIC_PROBE) \
         — a bare --include-ignored sweep that reaches here without it is not exercising the \
         probe, and must not pass vacuously"
    );
    if !crate::containment::cgroup::test_support::alone(
        "child::spawn::fd_map::fd_map_tests::two_overlapping_fd2_closes_via_restore_fd2_then_drop_second_then_panic_probe",
    ) {
        return;
    }
    let _first = RestoreFd2::take();
    let file = tempfile::tempfile().expect("open a file that lands at the freed fd 2");
    let second = RestoreFd2::take();
    drop(second);
    drop(file);
    // `_first` is STILL ALIVE here — the whole point is to panic while the FIRST guard's
    // registration is the only one that should still be live in `SAVED_STDERR`.
    panic!(
        "TWO_OVERLAPPING_FD2_CLOSES_VIA_RESTORE_FD2_THEN_DROP_SECOND_THEN_PANIC_MARKER: this \
         message must land on the real, originally-captured stderr via the FIRST guard's \
         still-live registration"
    );
}

/// Proves the "clear only own dup" half of the `SAVED_STDERR` overlap fix on `RestoreFd2` by
/// OBSERVABLE behavior — the lib's own copy of `tests/spawn_io.rs`'s
/// `two_overlapping_fd2_closes_then_drop_second_then_panic_lands_on_the_right_stderr`.
#[test]
fn two_overlapping_fd2_closes_via_restore_fd2_then_drop_second_then_panic_lands_on_the_right_stderr() {
    const PROBE: &str =
        "child::spawn::fd_map::fd_map_tests::two_overlapping_fd2_closes_via_restore_fd2_then_drop_second_then_panic_probe";
    let out = run_probe_directly(
        PROBE,
        &[(
            "COSCA_TEST_TRIGGER_TWO_OVERLAPPING_FD2_CLOSES_VIA_RESTORE_FD2_THEN_DROP_SECOND_THEN_PANIC_PROBE",
            "1",
        )],
    );
    assert_eq!(
        out.status.code(),
        Some(101),
        "the probe must fail with an ordinary libtest panic exit (101) in both build profiles — \
         got {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if !cfg!(debug_assertions) {
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            combined.contains("TWO_OVERLAPPING_FD2_CLOSES_VIA_RESTORE_FD2_THEN_DROP_SECOND_THEN_PANIC_MARKER"),
            "the probe's own panic message must reach the real captured stderr via the FIRST \
             guard's still-live registration, not be lost to a wrongly-cleared slot — got:\n{combined}"
        );
    }
}

/// A deliberate probe for `require_process_per_test` itself — the lib's own copy of
/// `tests/spawn_io.rs`'s `close_without_alone_probe`: calls `RestoreFd2::take()` directly,
/// deliberately NOT wrapped in `crate::containment::cgroup::test_support::alone()` first.
/// `#[ignore]`d and env-gated exactly like the other probes above so a bare `--include-ignored`
/// sweep fails loudly instead of silently no-oping.
///
/// Its invoker, [`gate_rejects_a_non_alone_process_via_restore_fd2`] below, spawns this probe
/// directly with neither `COSCA_TEST_ALONE` set nor the `ALONE_ARGS` shape as its argv.
#[test]
#[ignore = "probe"]
fn close_without_alone_via_restore_fd2_probe() {
    assert!(
        std::env::var_os("COSCA_TEST_TRIGGER_CLOSE_WITHOUT_ALONE_VIA_RESTORE_FD2_PROBE").is_some(),
        "this probe must only be invoked via gate_rejects_a_non_alone_process_via_restore_fd2 \
         (which sets COSCA_TEST_TRIGGER_CLOSE_WITHOUT_ALONE_VIA_RESTORE_FD2_PROBE) — a bare \
         --include-ignored sweep that reaches here without it is not exercising the probe, and \
         must not pass vacuously"
    );
    let _restore = RestoreFd2::take();
}

/// Proves `require_process_per_test`'s own gate on `RestoreFd2::take` — the lib's own copy of
/// `tests/spawn_io.rs`'s `gate_rejects_a_non_alone_process`. Spawns the probe above directly —
/// not via [`run_probe_directly`], which always sets up the full `alone()` shape — with neither
/// `COSCA_TEST_ALONE` set nor `ALONE_ARGS` as its argv, so the gate itself is what is under test.
/// No cgroup needed: `require_process_per_test` is the very first thing `RestoreFd2::take` does.
#[test]
fn gate_rejects_a_non_alone_process_via_restore_fd2() {
    const PROBE: &str = "child::spawn::fd_map::fd_map_tests::close_without_alone_via_restore_fd2_probe";
    let child = {
        // Every raw spawn in this test surface takes `crate::child::spawn::spawn_lock()` —
        // matching `run_probe_directly`'s own pattern above — held only around `spawn()`, not
        // the wait.
        let _guard = crate::child::spawn::spawn_lock();
        std::process::Command::new(std::env::current_exe().expect("this test binary"))
            .args([PROBE, "--exact", "--ignored", "--nocapture", "--test-threads=1"])
            .env("COSCA_TEST_TRIGGER_CLOSE_WITHOUT_ALONE_VIA_RESTORE_FD2_PROBE", "1")
            .env_remove("COSCA_TEST_ALONE")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn the probe")
    };
    let out = wait_bounded(child, std::time::Duration::from_secs(30));
    assert_eq!(
        out.status.code(),
        Some(101),
        "a process not running under alone() must have RestoreFd2::take panic (exit 101), not \
         succeed or hang — got {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("call this from inside crate::containment::cgroup::test_support::alone() — see cosca#196"),
        "the gate's own panic message must reach stderr — got:\n{combined}"
    );
}

/// A mapping whose parent-side source starts out sitting at fd 2 — because the current process
/// just closed its own fd 2 and the source is the next thing opened — must not be silently
/// repointed to whatever std's OWN `.stderr()` setup later `dup2`s onto fd 2 in the child. Std
/// runs that dup2 in the child BEFORE any `pre_exec` hook (including `install`'s own), so
/// without a parent-side relocation, `fd_map`'s later `dup2(2, 3)` would duplicate the stderr
/// pipe (now sitting at fd 2) instead of the mapping's actual source. Reproduces the bug measured
/// on tokio: `close(2)`, `stderr(pipe())` + `fd(3, null)` delivered the stderr pipe's bytes
/// through fd 3 instead of the mapping's real source.
#[test]
fn a_source_starting_below_fd_3_is_moved_before_stdio_dup2_can_clobber_it() {
    if !crate::containment::cgroup::test_support::alone(
        "child::spawn::fd_map::fd_map_tests::a_source_starting_below_fd_3_is_moved_before_stdio_dup2_can_clobber_it",
    ) {
        return;
    }
    let _restore = RestoreFd2::take();
    // The next fd opened lands at 2 (just closed above by `RestoreFd2::take`) — this IS the
    // mapping's source, at the exact number the bug needs to reproduce.
    let owned: OwnedFd = file_with("fd3-token").into();
    assert_eq!(
        owned.as_raw_fd(),
        2,
        "test setup invariant: the source must land exactly at fd 2 to reproduce the bug"
    );

    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg(format!("{} >&1; echo unrelated-stderr >&2", read_fd(3)))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    install(
        &mut cmd,
        vec![FdMapping {
            parent_fd: owned,
            child_fd: 3,
        }],
    )
    .expect("install");

    let out = cmd.output().expect("spawn /bin/sh");
    assert!(out.status.success(), "child failed: {out:?}");
    assert_eq!(
        out.stdout, b"fd3-token",
        "fd 3 in the child must deliver the mapping's OWN source, not whatever std's stdio \
         dup2 later put at the parent-side fd 2 number"
    );
    assert_eq!(
        String::from_utf8(out.stderr).unwrap().trim(),
        "unrelated-stderr",
        "the stderr pipe must carry only the child's own stderr writes, not fd 3's bytes"
    );
}

/// A relocated low `parent_fd`'s ORIGINAL number must stay open (busy) in the parent for as long
/// as `std_cmd` holds the `pre_exec` closure — not just until `install` returns. Freeing it any
/// earlier hands that exact number back to the OS right before `std_cmd.spawn()` does its own
/// internal fd allocation (e.g. its child-to-parent error-reporting pipe, or any piped stdio),
/// which can then claim that same number in the parent and collide with a dup2 std performs in
/// the child before any `pre_exec` hook runs — so the freed number ends up serving two different
/// purposes across the fork, corrupting whichever one loses.
#[test]
fn a_relocated_low_parent_fd_stays_open_in_the_parent_until_std_cmd_drops() {
    if !crate::containment::cgroup::test_support::alone(
        "child::spawn::fd_map::fd_map_tests::a_relocated_low_parent_fd_stays_open_in_the_parent_until_std_cmd_drops",
    ) {
        return;
    }
    let _restore = RestoreFd2::take();
    // The next fd opened lands at 2 (just closed above by `RestoreFd2::take`).
    let owned: OwnedFd = file_with("kept-open").into();
    assert_eq!(
        owned.as_raw_fd(),
        2,
        "test setup invariant: the source must land exactly at fd 2 to reproduce the bug"
    );

    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c").arg("true");
    install(
        &mut cmd,
        vec![FdMapping {
            parent_fd: owned,
            child_fd: 5,
        }],
    )
    .expect("install");

    // fd 2, in THIS process, must still be a live descriptor right after `install` returns —
    // freeing it earlier is exactly the bug: it must stay open until `cmd` itself (and the
    // closure/Plan it owns) drops.
    let still_open = unsafe { libc::fcntl(2, libc::F_GETFD) } != -1;
    assert!(
        still_open,
        "the original low fd (2) must remain open across install() — it must not be freed \
         back to the OS before std_cmd's own spawn() internals have run"
    );

    drop(cmd); // only now may the retired original actually close

    // Once `cmd` (and the `Plan`/`retired` it owned) has dropped, fd 2 must actually be freed —
    // proving `_retired` isn't just leaked open for the life of the process.
    let closed_after_drop = unsafe { libc::fcntl(2, libc::F_GETFD) } == -1;
    assert!(
        closed_after_drop,
        "the retired original fd (2) must be closed once std_cmd drops, not leaked open"
    );
}
