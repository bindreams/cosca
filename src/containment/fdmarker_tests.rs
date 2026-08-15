//! Sweep tests. Every one runs against the real host process table with real descriptors —
//! nothing here is faked, because a sweep fired at a synthetic table proves nothing.
//!
//! Three rules these tests obey, because the unit suite runs in parallel in ONE process:
//! never clear `FD_CLOEXEC` on a descriptor of the test process (a concurrent fork+exec on
//! another thread would leak it into an unrelated child); never key a log assertion on the
//! shared pid alone (every test shares it) — key on the marker handle; and every test that
//! calls `install()` (opening a write-end fd this process holds, CLOEXEC or not) holds
//! `test_spawn_lock()` for its WHOLE body, WHETHER OR NOT that test itself goes on to spawn.
//! The exposure is not "this test's own fork races its own write end" — it is "ANY sibling
//! test's fork, anywhere in this shared process, can land while THIS test's write end happens
//! to be open" — so the guard is owed by every test that opens one, not only the ones that also
//! fork. Without it, a sibling test's `.spawn()` could fork WHILE this test's marker write end
//! is open, transiently inheriting it; if that sibling is mid-`hard_kill()`/`holders()` at that
//! exact moment, its sweep would find and SIGKILL the bystander child.
//!
//! `test_spawn_lock()` is `crate::child::spawn::spawn_lock()` ITSELF, not a private mutex — a
//! separate lock would only serialize these tests against each other, not against every OTHER
//! fork in the same test binary. `cosca::Command::spawn()` (used by tests throughout this
//! crate) already takes `spawn_lock()` internally, so reusing it here gets those tests'
//! serialization for free.
//!
//! **This reuse does NOT make every fork in the `--lib` test binary safe — stated plainly,
//! not implied.** `crate::test_child::spawn_a_process_that_exits` (used by unrelated tests,
//! e.g. `identity/persist_tests.rs`) is wrapped in this same lock now. But grepping the tree
//! for other unlocked `std::process::Command::spawn()`/`.output()` calls in the SAME `--lib`
//! binary finds several more this task does not touch: `src/process/graceful_tests.rs`,
//! `src/tokio/process/graceful_tests.rs`, `src/containment/unix_tests.rs`,
//! `src/wait/macos_tests.rs`, `src/containment/dispatch_tests.rs`, `src/tokio/wait_tests.rs`.
//! Each is a real, if narrow, fork-bystander exposure for exactly the reason the paragraph
//! above states: any of those forking while THIS module's tests hold a marker write end open
//! can transiently inherit it, and a concurrently-running `hard_kill()`/`holders()` scan in
//! THIS module could then find and SIGKILL that bystander. Those files are outside this
//! task's scope (owned by other in-flight work on this same crate) — this plan cannot silently
//! claim they are covered when they are not. **Open, unresolved as of this task:** either every
//! one of those call sites needs `spawn_lock()` too (a cross-cutting test-infra change spanning
//! files this task does not own), or `cargo test` for this crate needs to run with reduced
//! parallelism for the affected tests, or the risk is accepted and documented as a known,
//! narrow test-suite flake source. Surfaced as a real question, not resolved here.

use std::os::fd::{AsFd, AsRawFd};

use super::{holders, holds_marker, holds_marker_query, pipe_handle_of, MarkerQuery, PipeFdInfo, PROC_PIDFDPIPEINFO};

fn all_pids() -> Vec<crate::identity::RawPid> {
    crate::containment::enumerate::snapshot().0
}

/// See the module docs above: held for the WHOLE body of every test that both installs a
/// marker and spawns a real child, so no such test's fork can land inside another's marker
/// window in this shared, parallel-test process. Delegates to the SAME lock production code
/// uses, not a private one, so it also excludes every other cosca-originated spawn elsewhere
/// in this test binary.
fn test_spawn_lock() -> std::sync::MutexGuard<'static, ()> {
    crate::child::spawn::spawn_lock()
}

// No standalone layout test: the layout is guarded at compile time by the
// `const _: () = assert!(…)` trio in the implementation (the crate does not build if it's
// wrong), and at runtime by `a_live_pipe_has_a_nonzero_handle_distinct_per_end` plus the sweep
// tests below (the wrong struct returns `<= 0` and finds nobody — measured fact B's note). A
// test comparing hand-transcribed copies of the same measured-fact table against each other
// would not catch a transcription error either copy shared, so it adds no independent coverage.

/// A real pipe has a readable handle; the two ends are distinct kernel objects with distinct
/// handles, so matching on the write end's handle cannot match a process holding only a read end.
#[test]
fn a_live_pipe_has_a_nonzero_handle_distinct_per_end() {
    let (r, w) = std::io::pipe().expect("pipe");
    let hw = pipe_handle_of(w.as_fd()).expect("the write end is a pipe");
    let hr = pipe_handle_of(r.as_fd()).expect("the read end is a pipe");
    assert_ne!(hw, 0, "a live pipe's handle must be non-zero");
    assert_ne!(hw, hr, "the two ends of a pipe are distinct kernel objects");
}

/// The mechanism's identity claim needs more than "a released handle isn't reissued while
/// held" — it needs simultaneously-LIVE pipes to never share a handle, or `holders()` could
/// match an unrelated live process by coincidence and get it SIGKILL'd. Measured directly
/// rather than inferred from the `VM_KERNEL_ADDRHASH` name (which suggests a lossy hash): a
/// one-off measurement backing this claim used 20,000 simultaneously-live pipes (40,000
/// handles) on an unconstrained shell (see the final report). THIS test deliberately uses far
/// fewer: macOS's launchd-inherited soft `RLIMIT_NOFILE` defaults to 256 (measured on this host
/// via `launchctl limit maxfiles`), which is what a CI runner gets unless a step raises it, and
/// this suite runs every unit test in parallel in ONE process — parking thousands of
/// descriptors here would both risk this test's own `pipe()` calls panicking with `EMFILE` and
/// starve concurrently-running sibling tests' `pipe()`/`File::open` calls into spurious `EMFILE`
/// failures. `N = 50` (100 descriptors) leaves comfortable headroom under even the unraised
/// default while still meaningfully exercising "many simultaneously-live handles, checked
/// pairwise" — weaker statistical power than the one-off 20,000-pipe measurement, but a
/// regression-pinning unit test's job here is to catch a REVERSION of the property (e.g. a
/// kernel/SDK change that reintroduces collisions), not to reproduce the full-scale measurement
/// inside a shared, resource-constrained test process.
#[test]
fn many_simultaneously_live_pipes_never_share_a_handle() {
    const N: usize = 50;
    let mut pipes = Vec::with_capacity(N);
    for _ in 0..N {
        pipes.push(std::io::pipe().expect("pipe"));
    }
    let mut handles: Vec<u64> = Vec::with_capacity(N * 2);
    for (r, w) in &pipes {
        handles.push(pipe_handle_of(r.as_fd()).expect("read end handle"));
        handles.push(pipe_handle_of(w.as_fd()).expect("write end handle"));
    }
    let unique: std::collections::HashSet<u64> = handles.iter().copied().collect();
    assert_eq!(
        unique.len(),
        handles.len(),
        "{} simultaneously-live pipe handles must all be distinct; found {} unique among {}",
        N,
        unique.len(),
        handles.len()
    );
}

/// A non-pipe descriptor is reported as "not a pipe", never as handle 0.
#[test]
fn a_non_pipe_descriptor_has_no_pipe_handle() {
    let f = std::fs::File::open("/dev/null").expect("open /dev/null");
    assert!(
        pipe_handle_of(f.as_fd()).is_none(),
        "a character device is not a pipe and must not yield a pipe handle"
    );
}

/// THE MECHANISM'S CENTRAL SAFETY INVARIANT, measured rather than assumed. Once every write
/// end is closed, the kernel frees the pipe pair only if the read end is gone too — so while
/// the supervisor holds the read end, no newly created pipe on this host can ever carry the
/// marker's handle. (With BOTH ends closed the handle is re-issued to the very next pipe,
/// every time, which is why `Marker` owns the read end for its whole life.)
#[test]
fn holding_the_read_end_keeps_the_handle_from_being_reissued() {
    let (read, write) = std::io::pipe().expect("pipe");
    let handle = pipe_handle_of(write.as_fd()).expect("write end handle");
    drop(write); // the "tree drained" moment: the last write end goes away

    // Churn: allocate and free pipes, looking for the handle to come back.
    for _ in 0..2000 {
        let (r2, w2) = std::io::pipe().expect("churn pipe");
        let h2 = pipe_handle_of(w2.as_fd()).expect("churn handle");
        assert_ne!(
            h2, handle,
            "a new pipe took the marker's handle while the read end was still held — \
             the sweep could match an unrelated process"
        );
        drop((r2, w2));
    }
    drop(read);
}

/// The sweep must find this process, which really does hold the write end.
#[test]
fn the_sweep_finds_this_process_holding_the_marker() {
    let (_r, w) = std::io::pipe().expect("pipe");
    let handle = pipe_handle_of(w.as_fd()).expect("write end handle");
    let me = std::process::id();
    let found = holders(handle, &all_pids());
    assert!(
        found.iter().any(|h| h.pid == me),
        "the sweep must find pid {me}, which holds the marker; found {found:?}"
    );
    assert!(holds_marker(me, handle), "the single-pid membership check must agree with the sweep");
}

// The AND-fold in `holders()` (`all_clexec &= …`) — a one-line, directly reviewable change from
// a first-fd-wins `break` — is NOT independently unit-tested. Proving it needs a real process
// holding two descriptors for the same marker in genuinely different CLOEXEC states, and that
// state is only reachable by a live process calling `fcntl` AFTER it is already running (arming
// CLOEXEC before an exec only ever produces "closed at THIS exec", never "held past it"). Nothing
// available to a unit test can produce that: `/bin/sh` has no `fcntl` builtin, a compiled testbin
// mode is unavailable to unit tests, and creating the needed non-CLOEXEC descriptor directly in
// THIS shared test process is exactly what the "never clear FD_CLOEXEC on this process's own
// descriptors" rule forbids. A real end-to-end reproduction is possible in the Task 7 INTEGRATION
// tests (testbin allowed there) — left for that task if this coverage gap matters enough to Anna
// to add it; this task does not decide that silently by omission.

/// `PROC_PIDLISTFDS` denial is measured to return `0` with `errno == EPERM`, not a negative
/// value — pinned here (independent of `pipe_fds_of`/`clear_errno_and_call`, which this fact
/// drives) so the `<= 0` failure gate cannot silently regress to the wrong assumption. pid 1
/// (launchd, root-owned) queried directly is the oracle; this crate's CI and dev hosts run
/// unprivileged, matching every other test here that assumes pid 1 is launchd and unreachable
/// as a signal target.
#[test]
fn proc_pidlistfds_denial_returns_zero_with_eperm_not_negative() {
    // SAFETY: the sizing form takes a null buffer; `__error()` returns this thread's own errno
    // cell, which writing 0 into is always defined.
    let n = unsafe {
        *libc::__error() = 0;
        libc::proc_pidinfo(1, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0)
    };
    let e = std::io::Error::last_os_error();
    assert_eq!(
        n, 0,
        "an EPERM denial from PROC_PIDLISTFDS is measured to return 0 on this platform, not a \
         negative value — a `< 0` failure gate would silently miss it"
    );
    assert_eq!(
        e.raw_os_error(),
        Some(libc::EPERM),
        "pid 1 (launchd, root-owned) must be denied to an unprivileged caller with EPERM; got {e}"
    );
}

/// `PROC_PIDFDPIPEINFO` on an fd that is not currently a pipe on the calling process — never
/// opened, already closed, or open but a different fd type — is measured to return `0` with
/// `errno == EBADF` in every case (not `ENOENT`/`EINVAL`/a type-specific code), pinned here so
/// `fd_pipe_info`'s `Absent` classification cannot silently drift from what the kernel actually
/// reports. Measured directly on this host: a never-opened fd, a closed-then-reused-numerically
/// pipe fd, and an open regular-file fd all produced identical `(0, EBADF)`.
#[test]
fn proc_pidfdinfo_on_a_non_pipe_fd_returns_zero_with_ebadf_not_a_type_specific_code() {
    let me = std::process::id() as libc::c_int;
    let mut info: PipeFdInfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<PipeFdInfo>() as libc::c_int;

    // A regular file is open, valid, and NOT a pipe — this is the case the plan's own
    // `Absent` classification must cover, distinct from a genuinely unopened descriptor.
    let file = std::fs::File::open("/dev/null").expect("open /dev/null");
    // SAFETY: `info`'s pointer and `size` match; `file`'s fd stays valid for this call.
    let n = unsafe {
        *libc::__error() = 0;
        libc::proc_pidfdinfo(
            me,
            file.as_raw_fd(),
            PROC_PIDFDPIPEINFO,
            &mut info as *mut _ as *mut libc::c_void,
            size,
        )
    };
    let e = std::io::Error::last_os_error();
    assert_eq!(n, 0, "a non-pipe fd is measured to return 0, not a negative value; got {n}");
    assert_eq!(
        e.raw_os_error(),
        Some(libc::EBADF),
        "a non-pipe fd is measured to fail with EBADF specifically (not ENOENT/EINVAL); got {e}"
    );
}

/// `holds_marker_query` must report `Denied`, not `NotHeld`, when the WHOLE-pid fd list read
/// is refused — collapsing the two would silently reclassify "still a member, now unreachable"
/// as "no longer a member" (the exact failure `MarkerQuery` exists to prevent; see its doc
/// comment). pid 1 (launchd, root-owned) is the same real, deterministic, unprivileged-EPERM
/// oracle `proc_pidlistfds_denial_returns_zero_with_eperm_not_negative` already establishes —
/// no fault injection needed for this one, since a real, always-available denial exists. The
/// handle value passed is irrelevant: the denial happens before any per-fd handle comparison.
#[test]
fn holds_marker_query_reports_denied_not_not_held_for_an_unqueryable_pid() {
    assert_eq!(
        holds_marker_query(1, 0),
        MarkerQuery::Denied,
        "pid 1 must be unqueryable (EPERM) to an unprivileged caller; a Denied fd-list read \
         must not be reported as NotHeld"
    );
}

/// A handle naming no live pipe finds nobody, and must not panic or mis-match. `0` is never a
/// valid `pipe_handle` (established above by `a_live_pipe_has_a_nonzero_handle_distinct_per_end`)
/// and cannot become one through any amount of churn (this suite churns pipes across many tests
/// running in parallel in ONE process), so this is race-free by construction rather than by
/// timing luck.
#[test]
fn a_dead_handle_finds_no_holders() {
    assert!(
        !holds_marker(std::process::id(), 0),
        "handle 0 is never a valid pipe_handle and must not be reported as held"
    );
}
