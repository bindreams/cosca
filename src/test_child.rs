//! Test-only child processes shared across the crate's unit tests.

/// Runs the libtest fixture at fully-qualified path `fixture` (e.g.
/// `"resolve::resolve_tests::fixture_foo"`) in a FRESH re-exec of this test binary whose OS-level
/// cwd is `cwd` — proving whatever the fixture's body proves about a process's REAL cwd without
/// ever mutating THIS (shared, multithreaded) test binary's own cwd, which every other
/// concurrently running test in this binary would otherwise race. `Command::current_dir` sets the
/// CHILD's cwd before its own `exec`/`CreateProcessW`, so no window exists where this process's
/// cwd is anything other than what it always was.
///
/// `marker_env` is set to `cwd` itself in the child only, so the fixture can both (a) tell this
/// deliberate re-exec apart from being picked up by an ordinary, unfiltered suite run — where it
/// must no-op rather than assert against whatever the suite's own ambient cwd happens to be — and
/// (b) assert its OWN `std::env::current_dir()` against that same value, rather than trusting
/// that this function's `.current_dir(cwd)` call below actually took effect. Carrying the
/// directory in the marker, rather than a bare `"1"`, is what lets a fixture catch this helper's
/// OWN cwd-setting being silently dropped — a mutation that a caller checking only the fixture's
/// pass/fail outcome cannot otherwise see, since the fixture would still be asserting something
/// true about *some* directory, just not necessarily the one the parent prepared.
///
/// Spawns under `spawn_lock()`, matching every other raw `std::process::Command` re-exec of this
/// test binary (see [`spawn_a_process_that_exits`]'s doc for the macOS fd-marker hazard that
/// convention guards against).
///
/// Panics with the child's captured stdout/stderr on a non-zero exit, i.e. whenever the fixture's
/// own assertions failed — OR when the child's own libtest banner does not show that exactly the
/// one intended fixture ran. `--exact <fixture>` naming a test that does not exist (a typo, or a
/// rename on one side of the caller/fixture pair) makes libtest match ZERO tests and still exit
/// 0, which a bare `status.success()` check cannot tell apart from "the fixture ran and passed" —
/// build `fixture` with [`fixture_path!`] rather than a hand-typed string literal, so a mismatch
/// between a call site and its `#[test] fn` is a compile error instead of a silently-empty
/// filter; this stdout check is the remaining backstop for whatever that still lets through.
pub(crate) fn run_fixture_with_cwd(fixture: &str, cwd: &std::path::Path, marker_env: &str) {
    let mut cmd = fixture_command(fixture);
    cmd.env(marker_env, cwd).current_dir(cwd);
    run_fixture_command(fixture, cmd);
}

/// Runs the libtest fixture at fully-qualified path `fixture` in a FRESH re-exec of this test
/// binary, with no cwd of its own to carry — for a fixture whose body needs isolation for some
/// OTHER process-wide, irreversible state, such as [`crate::test_privilege::drop_dac_bypass`]'s
/// credentials and capability sets, rather than for the cwd `run_fixture_with_cwd` exists to
/// isolate. [`is_fixture_reexec`] is what the fixture checks, since there is no per-fixture marker
/// here to carry it instead.
///
/// Gives the fixture a scratch directory it can build its OWN tempdir under after dropping
/// privilege — a fixture that called `tempfile::tempdir()` there directly would depend on
/// `TMPDIR` naming a directory the POST-drop identity can still write to, which the caller's
/// ambient `TMPDIR` has no reason to guarantee (measured: a `--read-only` rootfs with `TMPDIR`
/// pointing at the one `rw` `tmpfs` mount — a real CI shape, not a contrived one — fails a
/// `tempdir()` call inside a fixture this function once forced onto a hardcoded `/tmp` instead,
/// which is read-only in that same container). `scratch` itself is built here, before the drop,
/// with THIS thread's still-undropped privilege, under this DRIVER's own ambient `TMPDIR` —
/// precisely what `main`'s equivalent fixtures do.
///
/// A path lookup checks EVERY ancestor component, not just the final target — `scratch` being
/// reachable does not by itself make it reachable THROUGH an ancestor that refuses the post-drop
/// identity search permission. An earlier version of this function tried to fix that by loosening
/// the AMBIENT `TMPDIR` itself with a `chmod` — measured broken: that permanently widened a THIRD
/// PARTY's directory beyond what "traversal only" could promise (a `pam_tmpdir`-style `0700`
/// directory a bare `chmod +x` turns into `0701`, at which point the dropped uid can also read
/// any file in it BY NAME, not just traverse through it), it could race a concurrent test's own
/// use of the same directory while trying to restore the original mode afterward, and it still
/// did not reach the actual bug: an ancestor ABOVE the one directly `chmod`'d (a `0700` home
/// directory two levels up, say) was never touched at all. See [`open_scratch_fd`] for what
/// replaced it on Linux, and [`assert_dropped_identity_can_traverse_tmpdir`] for why non-Linux
/// gets a loud precondition failure instead of an equivalent workaround.
///
/// See [`run_fixture_with_cwd`]'s doc for the re-exec rationale, the panic conditions, and why
/// `fixture` should come from [`fixture_path!`].
///
/// `#[cfg(unix)]`: every current caller drops DAC-bypassing privilege, a unix-only concept: gate
/// this the same way rather than carry a cross-platform no-caller-on-Windows dead-code warning.
#[cfg(unix)]
pub(crate) fn run_fixture(fixture: &str) {
    let scratch = tempfile::tempdir().expect("tempdir for fixture scratch root");
    let mut cmd = fixture_command(fixture);

    #[cfg(target_os = "linux")]
    {
        // The whole open-to-spawn window is under `spawn_lock()`, not just the spawn: `fd` is
        // opened `O_CLOEXEC` (so an ordinary `fork`+`exec` anywhere else in this process never
        // inherits it), but a BARE `fork()` from another concurrently running test — cosca's own
        // cgroup test support, `fork_running` in `containment/cgroup/test_support.rs`, does that —
        // copies the whole fd table regardless of `O_CLOEXEC`, which only takes effect at `exec`.
        // Serializing against every OTHER cosca-originated fork that ALSO takes `spawn_lock()`
        // closes the window against those. It does NOT close it against `fork_running` itself:
        // that helper does not take `spawn_lock()` today, so a cgroup test's own bare fork can
        // still race this window. Making `fork_running` take it too belongs to
        // `test_support.rs`, owned by a separate PR stack — not fixed here.
        let child = {
            let _guard = crate::child::spawn::spawn_lock();
            let fd = open_scratch_fd(scratch.path());
            cmd.env(FIXTURE_SCRATCH_FD_ENV, fd.0.to_string());
            // SAFETY: `fcntl(F_SETFD, 0)` is async-signal-safe, and runs in the CHILD after
            // `fork` and before `execve` — clearing close-on-exec here, in the child's own copy
            // of the fd, cannot race or interfere with the PARENT's copy (still `O_CLOEXEC`,
            // closed when `fd` drops below) or with any other thread's own fork.
            use std::os::unix::process::CommandExt as _;
            unsafe {
                cmd.pre_exec(move || {
                    if libc::fcntl(fd.0, libc::F_SETFD, 0) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            cmd.spawn().expect("spawn fixture child")
            // `fd` (this PARENT's own, still-`O_CLOEXEC` copy) drops here, closing it — the
            // CHILD's copy, duplicated by `fork` inside `spawn` above and un-`CLOEXEC`'d by the
            // `pre_exec` hook, stays open independently and survives the child's own `execve`.
        };
        finish_fixture_command(fixture, child);
    }

    #[cfg(not(target_os = "linux"))]
    {
        // Only a root driver's fixture actually changes uid on the drop (`drop_root_uid` is a
        // no-op otherwise, same check as that function's own) — an unprivileged driver's own
        // `tempfile::tempdir()` call just above already PROVES its ambient `TMPDIR` is usable
        // post-drop, since that identity does not change; only a root driver's does.
        let mut exe_copy = None;
        if unsafe { libc::geteuid() } == 0 {
            assert_dropped_identity_can_traverse_tmpdir();
            use std::os::unix::ffi::OsStrExt as _;
            let path = std::ffi::CString::new(scratch.path().as_os_str().as_bytes())
                .expect("scratch root path has no interior NUL");
            // SAFETY: `path` is a valid, NUL-terminated C string for a directory this call just
            // created — OUR OWN, unlike the ambient `TMPDIR` checked above; `chown` on it fails
            // closed (checked below) rather than touching anything else.
            let rc = unsafe {
                libc::chown(
                    path.as_ptr(),
                    crate::test_privilege::UNPRIVILEGED,
                    crate::test_privilege::UNPRIVILEGED,
                )
            };
            if rc != 0 {
                panic!(
                    "chown scratch root to the fixture's post-drop identity: {}",
                    std::io::Error::last_os_error()
                );
            }
            // `current_exe()`'s own path is not necessarily reachable by the dropped identity
            // either: under `cargo-nextest --archive-file` (this lane's own mechanism), it resolves
            // inside nextest's OWN archive-extraction directory — measured on the real macOS root
            // lane, `/private/tmp/nextest-archive-<...>/...` — which nextest creates and owns
            // itself, with no guarantee of a mode the post-drop uid can enter. Copying the running
            // binary to a directory THIS driver creates and chmods itself, directly under `/tmp`,
            // sidesteps trusting nextest's own directory shape at all; see
            // `copy_exe_to_traversable_scratch`'s doc.
            let (dir, exe) = copy_exe_to_traversable_scratch();
            let mut root_cmd = std::process::Command::new(&exe);
            configure_fixture_command(&mut root_cmd, fixture);
            cmd = root_cmd;
            exe_copy = Some(dir);
        }
        cmd.env(FIXTURE_SCRATCH_ROOT_ENV, scratch.path());
        let child = {
            let _guard = crate::child::spawn::spawn_lock();
            cmd.spawn().expect("spawn fixture child")
        };
        // `exe_copy` (and the scratch dir it names) must outlive the fixture process actually
        // running from it — dropped only after the fixture has exited, here, not any earlier.
        finish_fixture_command(fixture, child);
        drop(exe_copy);
    }
}

/// A raw directory fd, closed on `Drop` — including during unwind (a fixture's own assertion
/// failure panics [`run_fixture_command`]), matching `scratch`'s own `TempDir` cleanup. Closing it
/// matters beyond tidiness: `run_fixture` runs once per DRIVER `#[test]`, all inside the same
/// long-lived, shared, multi-threaded suite process, so a fd this never closed would accumulate
/// for as long as that process keeps running tests.
#[cfg(target_os = "linux")]
struct OwnedRawFd(std::os::unix::io::RawFd);

#[cfg(target_os = "linux")]
impl Drop for OwnedRawFd {
    fn drop(&mut self) {
        // SAFETY: `self.0` was opened by `open_scratch_fd`, uniquely owned by this value, and
        // this is the only place that closes it.
        unsafe {
            libc::close(self.0);
        }
    }
}

/// Opens `dir` (the scratch root [`run_fixture`] just created) `O_DIRECTORY`, WITH `O_CLOEXEC` —
/// `std::fs::File::open` would do the same, but returning a raw fd rather than a `File` here
/// keeps the caller in charge of exactly when it stops being close-on-exec (see [`run_fixture`]'s
/// `pre_exec` hook, which clears it in the FIXTURE child specifically, not here).
///
/// The fixture reads this fd's NUMBER (env-carried — see [`FIXTURE_SCRATCH_FD_ENV`]) and builds
/// its own paths under `/proc/<its own pid>/fd/<that number>/...` rather than under `dir` itself.
/// A lookup through that `/proc` magic link is resolved against the fd's OWN target directly,
/// without re-walking `dir`'s ancestor chain — so an ambient `TMPDIR` this crate does not own, and
/// must not `chmod` (see [`run_fixture`]'s doc), no longer needs to be traversable by the
/// post-drop identity AT ALL; only `dir` itself does, and this driver (never dropping its own DAC
/// bypass) already has full access to what it just created. Measured: a directory `chmod 0o000`'d
/// BELOW this fd's target (`locked_then_open`'s own precondition, in `resolve_base_tests.rs`)
/// still answers `EACCES` for the dropped identity — the ancestor-skipping is scoped to what is
/// ABOVE the fd's target, never to what a fixture builds under it for its own purposes.
///
/// The fixture's OWN pid, not always `self`: this fd — un-`CLOEXEC`'d only in the fixture child,
/// per `run_fixture`'s `pre_exec` hook — DOES survive into a grandchild the fixture itself spawns
/// (ordinary fd inheritance, unless something re-sets `O_CLOEXEC`, which nothing here does). But
/// `resolve_base_tests.rs`'s `stat_errno_via_grandchild` still cannot use `/proc/<fixture's
/// pid>/fd/<n>` from the GRANDCHILD's side: reading ANOTHER process's `/proc/<pid>/fd/<n>` entry
/// is `ptrace`-gated (`PTRACE_MODE_READ_FSCREDS`), not open to any reader merely because it holds
/// the same fd — and `capset` being per-thread means the fixture's OWN `/proc/<pid>` identity (its
/// thread-group leader, which never called `drop_dac_bypass`) still reports FULL capabilities,
/// which a now-reduced grandchild fails the ptrace check against. The grandchild instead uses its
/// OWN `/proc/self/fd/<n>` (see `grandchild_reachable_path` in `resolve_base_tests.rs`) — reading
/// one's own `/proc/self` needs no cross-process permission check — which is exactly why the fd
/// must stay inherited that far, not just into the fixture.
#[cfg(target_os = "linux")]
fn open_scratch_fd(dir: &std::path::Path) -> OwnedRawFd {
    use std::os::unix::ffi::OsStrExt as _;
    let path = std::ffi::CString::new(dir.as_os_str().as_bytes()).expect("scratch root path has no interior NUL");
    // SAFETY: `path` is a valid, NUL-terminated C string for a directory this call just created.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        panic!("open scratch root as O_DIRECTORY: {}", std::io::Error::last_os_error());
    }
    OwnedRawFd(fd)
}

/// The env var [`run_fixture`] passes the scratch directory's fd NUMBER through, on Linux — see
/// [`open_scratch_fd`]'s doc for why a fixture needing its own tempdir after dropping privilege
/// must build it under `/proc/<its own pid>/fd/<this number>/...` rather than trust an ambient
/// `TMPDIR` this crate makes no promise about.
#[cfg(target_os = "linux")]
pub(crate) const FIXTURE_SCRATCH_FD_ENV: &str = "COSCA_FIXTURE_SCRATCH_FD";

/// The env var [`run_fixture`] passes a fixture its scratch directory through, on non-Linux —
/// [`open_scratch_fd`]'s `/proc` trick has no non-Linux equivalent, so there the fixture is simply
/// handed `scratch`'s real path directly (e.g. for `tempfile::Builder::new().tempdir_in(..)`), and
/// [`assert_dropped_identity_can_traverse_tmpdir`] is what makes that safe to trust for a root
/// driver rather than a `tempfile::tempdir()` call that might silently test the wrong thing.
#[cfg(all(unix, not(target_os = "linux")))]
pub(crate) const FIXTURE_SCRATCH_ROOT_ENV: &str = "COSCA_FIXTURE_SCRATCH_ROOT";

/// Fails loudly, naming the directory, rather than trying to fix it — the owner's rule is that a
/// test declares its precondition instead of working around an environment that does not meet it
/// (see [`run_fixture`]'s doc for why loosening someone else's directory is not an option here).
/// Only called for a ROOT driver on non-Linux, where [`crate::test_privilege::drop_dac_bypass`]
/// (via its non-Linux `drop_root_uid`) changes the fixture's uid away from this driver's own — the
/// one case an already-successful `tempfile::tempdir()` call does NOT already prove the ambient
/// `TMPDIR` usable post-drop, since an unprivileged driver's own uid never changes, so ITS
/// successful call already is that proof.
#[cfg(all(unix, not(target_os = "linux")))]
fn assert_dropped_identity_can_traverse_tmpdir() {
    let tmpdir = std::env::temp_dir();
    if let Err(e) = check_path_traversable_by(&tmpdir) {
        panic!("{e}");
    }
}

/// Whether [`crate::test_privilege::UNPRIVILEGED`] can actually reach `path` on disk. Forks, drops
/// the CHILD to that uid/gid when this process is root — a no-op otherwise, mirroring
/// [`crate::test_privilege::drop_root_uid`]'s own "nothing to drop" case, so this call never fails
/// to drop; there is simply nothing to drop when the caller is not root — and `open`s `path`
/// there, asking the kernel directly rather than modelling its permission rules by hand.
///
/// **Act and fail, don't model.** An earlier version walked every ancestor's own mode/owner/group
/// bits in Rust. That missed a symlink resolved along the way: it checked the SYMLINK's own
/// (conventionally always-permissive) mode rather than its target's, since the kernel always
/// follows a symlink at an intermediate path component with no way to opt out (unlike the final
/// component's `O_NOFOLLOW`) — see `a_symlinked_ancestor_is_denied_by_the_kernel_not_modelled` in
/// `test_child_tests.rs` for the reviewer's repro shape (`/tmp/base/link` -> `/tmp/base/real/inner`,
/// `real` at `0700`). A hand-rolled model also has no way to know about any OTHER kernel-side rule
/// (ACLs, mount options, a MAC policy). Letting the kernel itself resolve `path` end to end, under
/// the real dropped identity, cannot be wrong about anything a model could miss.
///
/// `open`, not `stat`: `stat` only requires SEARCH permission on `path`'s ANCESTORS, never any
/// permission on `path` itself — which would silently pass the exact bug this precondition exists
/// to catch (a `TMPDIR` that is ITSELF `chmod 0700`, with perfectly traversable ancestors above
/// it — measured on `resolve_root_lane_macos`'s first real run). `open`'s own permission check on
/// the final component is what closes that gap.
///
/// No `spawn_lock()`: that lock exists to keep another thread's transient, still-open, non-`CLOEXEC`
/// fd (a script mid-write, an about-to-be-`exec`'d fixture's scratch fd) from being inherited into
/// a DIFFERENT thread's fork-then-exec child. This fork never execs and opens nothing but `path`
/// itself `O_RDONLY`, closed automatically at `_exit` — there is no write-fd to race and no
/// `exec`'d child for an inherited fd to matter to.
#[cfg(all(unix, not(target_os = "linux")))]
fn check_path_traversable_by(path: &std::path::Path) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt as _;
    let c_path =
        std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| format!("{path:?} has an interior NUL"))?;

    // SAFETY: a plain `fork()` from this (multithreaded) test binary. The child below touches no
    // shared mutable state the fork could have raced (`c_path` is read-only and already fully
    // built) and takes no lock another thread might be holding across the fork, because it never
    // allocates — every call past this point is a raw, async-signal-safe libc syscall — and it
    // always terminates via `_exit`, never by returning into this stack frame or running Rust's
    // normal shutdown path (which would rerun the PARENT's own destructors a second time).
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("fork: {}", std::io::Error::last_os_error()));
    }
    if pid == 0 {
        // SAFETY: async-signal-safe libc calls only, in the freshly forked child, before it
        // `_exit`s — no allocation, no Rust panic/unwind machinery.
        unsafe {
            if libc::geteuid() == 0 {
                let uid = crate::test_privilege::UNPRIVILEGED;
                if libc::setgroups(0, std::ptr::null()) != 0 || libc::setgid(uid) != 0 || libc::setuid(uid) != 0 {
                    libc::_exit(126); // distinct from any real errno below
                }
            }
            if libc::open(c_path.as_ptr(), libc::O_RDONLY) >= 0 {
                libc::_exit(0);
            }
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(125);
            libc::_exit(errno.clamp(1, 125));
        }
    }
    let mut status: libc::c_int = 0;
    // SAFETY: `pid` is this call's own freshly forked child, reaped exactly once, here.
    if unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
        return Err(format!("waitpid: {}", std::io::Error::last_os_error()));
    }
    if !libc::WIFEXITED(status) {
        return Err(format!(
            "check-traversal child for {path:?} did not exit normally (raw status {status:#x})"
        ));
    }
    match libc::WEXITSTATUS(status) {
        0 => Ok(()),
        126 => Err(format!(
            "check-traversal child for {path:?} could not drop to UNPRIVILEGED even though the parent is root"
        )),
        code => Err(format!("{path:?}: {}", std::io::Error::from_raw_os_error(code))),
    }
}

/// A directory this driver creates and `chmod`s itself, directly under `/tmp` — the one path
/// every platform this crate targets guarantees world-traversable regardless of the invoking
/// user's own `$HOME`, `$TMPDIR`, or (per `run_fixture`'s own doc) `cargo-nextest`'s own
/// archive-extraction directory. Holds a COPY of this test binary, `chmod`'d
/// world-readable+executable, for a root driver to re-exec the fixture from instead of
/// `std::env::current_exe()`'s own (possibly unreachable post-drop) path.
///
/// Returns the containing [`tempfile::TempDir`] alongside the copy's path: the caller must keep it
/// alive for exactly as long as the fixture might still be running from it — dropping it any
/// earlier deletes the very binary the fixture is executing.
#[cfg(all(unix, not(target_os = "linux")))]
fn copy_exe_to_traversable_scratch() -> (tempfile::TempDir, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::Builder::new()
        .tempdir_in("/tmp")
        .expect("tempdir directly under /tmp for a traversable fixture-exe copy");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))
        .expect("chmod the exe-copy scratch dir world-traversable");
    let src = std::env::current_exe().expect("current_exe");
    let dest = dir.path().join("fixture-exe");
    std::fs::copy(&src, &dest).expect("copy the test binary into the traversable scratch dir");
    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))
        .expect("chmod the exe copy world-readable+executable");
    if let Err(e) = check_path_traversable_by(&dest) {
        panic!("copied fixture exe is still not traversable by the post-drop identity: {e}");
    }
    (dir, dest)
}

/// The `std::process::Command` common to every fixture re-exec: this binary, filtered to exactly
/// one test, single-threaded, with both stdio streams captured for [`run_fixture_command`], and
/// [`FIXTURE_PARENT_PID_ENV`] set (see [`is_fixture_reexec`]).
///
/// No `TMPDIR` override of its own: an earlier version forced `/tmp` here for every fixture, which
/// broke under a `--read-only` rootfs whose only writable mount is an explicitly `TMPDIR`-pointed
/// `tmpfs` elsewhere — `/tmp` itself is read-only there, so overriding `TMPDIR` to name it made
/// things worse, not better, for a fixture that otherwise would have inherited a working ambient
/// value untouched. See [`run_fixture`]'s doc for how a fixture that specifically needs writable
/// scratch space after dropping privilege gets it instead.
///
/// No `"cosca_unit_tests"` placeholder in argv slot 0 (that's [`fixture_argv`]'s convention for
/// `cosca::Command`, see its doc): `std::process::Command` already supplies its own argv[0] from
/// `Command::new`'s program path.
///
/// `pub(crate)`, not just `run_fixture`/`run_fixture_with_cwd`'s private building block: a
/// bespoke launcher with its own stdio needs (`exact_posix_tests.rs`'s
/// `spawn_exact_tool_in_an_unreachable_cwd`, which pipes stdin for its own gate-byte protocol and
/// nulls stdout rather than piping it) can start from this and override just the stdio it needs
/// changed, rather than hand-rolling the argv/env setup a third time.
pub(crate) fn fixture_command(fixture: &str) -> std::process::Command {
    // On Linux, `/proc/self/exe` rather than `std::env::current_exe()`'s resolved path: this
    // binary itself can end up somewhere a POST-drop caller cannot reach by path at all — measured
    // running under `cargo-nextest --archive-file`, which extracts the archived test binaries
    // under `$TMPDIR` (a `pam_tmpdir`-style foreign-owned, `0700` `TMPDIR` then makes even a
    // FIXTURE'S OWN re-exec of itself, e.g. `stat_errno_via_grandchild`'s grandchild spawn, fail
    // with `PermissionDenied`, since it needs to traverse INTO that ambient directory to reach the
    // extracted binary). `/proc/self/exe` is a magic symlink the kernel resolves for whichever
    // process asks, granting it access to its OWN running executable image regardless of that
    // image's own directory permissions — `/proc` and `/proc/self` themselves need no special
    // permission to traverse. Correct for every caller of this function, not just the fixture: at
    // `execve` time inside a freshly forked child, `/proc/self/exe` still names the PARENT's (this
    // process's) own image, which is exactly the binary being re-exec'd either way.
    #[cfg(target_os = "linux")]
    let program = std::path::PathBuf::from("/proc/self/exe");
    #[cfg(not(target_os = "linux"))]
    let program = std::env::current_exe().expect("current_exe");
    let mut cmd = std::process::Command::new(program);
    configure_fixture_command(&mut cmd, fixture);
    cmd
}

/// The argv/env/stdio setup common to every fixture re-exec, split out from [`fixture_command`]
/// so a caller that needs a DIFFERENT program path — [`run_fixture`]'s non-Linux root branch,
/// which re-execs a COPY of this binary rather than its original (possibly unreachable, post-drop)
/// location — can build its own `Command::new(..)` and still get everything else this function
/// sets up, without duplicating it.
fn configure_fixture_command(cmd: &mut std::process::Command, fixture: &str) {
    cmd.args(["--test-threads=1", "--exact", fixture])
        .env(FIXTURE_PARENT_PID_ENV, std::process::id().to_string())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        // Every injected-failure driver reads a failing fixture's panic back from its captured
        // stdout — libtest's own default buffer-and-replay-on-failure behavior. An ambient
        // `RUST_TEST_NOCAPTURE=1` (set on the OUTER `cargo test`/`cargo nextest` invocation, not
        // this one) would otherwise be inherited here and switch the child fixture to
        // unbuffered mode, sending that panic straight to its real stderr instead — invisible to
        // a driver reading stdout. Explicitly removed, not merely left unset, so this holds
        // regardless of what the ambient environment carries.
        .env_remove("RUST_TEST_NOCAPTURE");
}

/// The env var every fixture re-exec ([`run_fixture`], [`run_fixture_with_cwd`]) sets, to its own
/// pid — see [`is_fixture_reexec`].
const FIXTURE_PARENT_PID_ENV: &str = "COSCA_FIXTURE_PARENT_PID";

/// Whether this process's real parent is the one that (deliberately) re-exec'd it via
/// [`run_fixture`]/[`run_fixture_with_cwd`] — not merely that [`FIXTURE_PARENT_PID_ENV`], or a
/// fixture-specific marker such as `run_fixture_with_cwd`'s `marker_env`, happens to be present
/// in whatever environment picked this process up.
///
/// Presence alone does not prove a deliberate re-exec: a marker env var can be inherited by the
/// shared, unfiltered suite process too — a stray shell `export`, a copy-pasted CI `env:` block —
/// which would then run a fixture's body, [`crate::test_privilege::drop_dac_bypass`] for one,
/// inside the process every other concurrently running test depends on. A real parent-pid match
/// is not spoofable by an inherited or coincidentally-named var.
///
/// On `true`, also writes [`FIXTURE_GATE_PASSED_LINE`] to this process's real stderr (see that
/// constant's doc for why): a mutant that makes this function always return `false` would
/// otherwise make every fixture silently no-op and every driver test still pass, since "the
/// fixture did nothing" and "the fixture ran and asserted nothing false" look identical from the
/// outside.
///
/// A caller with more to check before it is really safe to treat this as "gate passed" — a
/// `marker_env` still to read, a cwd still to assert, as [`expected_cwd`] has — must NOT call
/// this: writing the line here would happen before that caller's own checks run, so a fixture
/// whose `marker_env` turns out to be unset would still have the line written, and would still
/// look like it ran, before its own early return. Such a caller uses [`parent_pid_matches`]
/// instead, and writes the line itself only once every one of ITS checks has passed.
#[cfg(unix)]
pub(crate) fn is_fixture_reexec() -> bool {
    let reexec = parent_pid_matches();
    if reexec {
        write_gate_passed();
    }
    reexec
}

/// The check [`is_fixture_reexec`] makes, without its side effect — see that function's doc for
/// why a caller with more of its own gate left to check (namely [`expected_cwd`]) must use this
/// instead. Also `pub(crate)`: [`crate::test_privilege::drop_dac_bypass`]'s own contract assert
/// uses it directly — it needs the check without the write, same as `expected_cwd` does.
#[cfg(unix)]
pub(crate) fn parent_pid_matches() -> bool {
    std::env::var(FIXTURE_PARENT_PID_ENV)
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .is_some_and(|pid| pid == std::os::unix::process::parent_id())
}

/// The line a fixture's own re-exec gate ([`is_fixture_reexec`], or [`expected_cwd`] for a
/// `run_fixture_with_cwd` fixture) writes to this process's REAL stderr once it passes — bypassing
/// libtest's capture the same way `exact_posix_tests.rs`'s `report()` does, since a fixture that
/// gates out via an early `return` exits 0 with nothing further to distinguish it from one that
/// genuinely ran and passed. [`run_fixture_command`] asserts this line is present, so a mutant
/// that makes the gate always refuse is caught there instead of looking like a passing suite.
pub(crate) const FIXTURE_GATE_PASSED_LINE: &str = "COSCA_FIXTURE_GATE_PASSED";

fn write_gate_passed() {
    use std::io::Write;
    let _ = writeln!(std::io::stderr(), "{FIXTURE_GATE_PASSED_LINE}");
}

/// Spawns `cmd` (built from [`fixture_command`], possibly with more set on it) under
/// `spawn_lock()`, matching every other raw `std::process::Command` re-exec of this test binary
/// (see [`spawn_a_process_that_exits`]'s doc for the macOS fd-marker hazard that convention
/// guards against), and waits for it.
///
/// Panics with the child's captured stdout/stderr on a non-zero exit, i.e. whenever the fixture's
/// own assertions failed — OR when the child's own libtest banner does not show that exactly the
/// one intended fixture ran. `--exact <fixture>` naming a test that does not exist (a typo, or a
/// rename on one side of the caller/fixture pair) makes libtest match ZERO tests and still exit
/// 0, which a bare `status.success()` check cannot tell apart from "the fixture ran and passed" —
/// build `fixture` with [`fixture_path!`] rather than a hand-typed string literal, so a mismatch
/// between a call site and its `#[test] fn` is a compile error instead of a silently-empty
/// filter; this stdout check is the remaining backstop for whatever that still lets through.
fn run_fixture_command(fixture: &str, mut cmd: std::process::Command) {
    let child = {
        let _guard = crate::child::spawn::spawn_lock();
        cmd.spawn().expect("spawn fixture child")
    };
    finish_fixture_command(fixture, child);
}

/// The post-spawn half of [`run_fixture_command`], split out so [`run_fixture`]'s Linux branch —
/// which needs its OWN `spawn_lock()`-held region spanning both opening the scratch fd and
/// spawning the fixture, not just the spawn alone — can provide the already-spawned `Child`
/// itself rather than going through this function's own (separately locked, and therefore
/// deadlocking if nested) spawn step.
fn finish_fixture_command(fixture: &str, child: std::process::Child) {
    let output = child.wait_with_output().expect("wait for fixture child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "fixture {fixture} failed (status {:?}):\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        output.status,
    );
    assert!(
        stdout.contains("running 1 test") && stdout.contains("test result: ok. 1 passed;"),
        "fixture {fixture} exited 0 but its libtest banner shows something other than exactly \
         one test run and passed — most likely `--exact {fixture}` matched ZERO tests (a stale \
         name on one side of a caller/fixture pair), which libtest also exits 0 for:\n\
         --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
    );
    assert!(
        stderr.contains(FIXTURE_GATE_PASSED_LINE),
        "fixture {fixture} exited 0 and reported 1 test passed, but never wrote \
         {FIXTURE_GATE_PASSED_LINE:?} to its real stderr — its re-exec gate let it return early \
         without running its own body at all, which a passing libtest banner alone cannot tell \
         apart from a fixture that ran and found nothing wrong:\n\
         --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
    );
}

/// Reads `marker_env`'s value as the directory [`run_fixture_with_cwd`]'s caller prepared, and
/// returns `None` when it is unset, or (on unix) when [`parent_pid_matches`] says this is not
/// really a deliberate re-exec — either way, a fixture is picked up by an ordinary, unfiltered
/// suite run too, where it must no-op rather than assert against whatever the suite's own ambient
/// cwd happens to be, or against a `marker_env` some unrelated process happened to leave behind.
///
/// When set, also asserts this fixture's OWN `std::env::current_dir()` actually IS that
/// directory: `run_fixture_with_cwd`'s `.current_dir(cwd)` call is what is supposed to guarantee
/// that, but a fixture that never checks it would keep passing even if that call were silently
/// dropped — an assertion the fixture's OWN body happened to still satisfy in whatever the
/// process's REAL ambient cwd was, for reasons that have nothing to do with the directory under
/// test. Every fixture in this file that takes a `marker_env` argument calls this instead of
/// reading `std::env::current_dir()` directly, so that check is never skippable by omission.
pub(crate) fn expected_cwd(marker_env: &str) -> Option<std::path::PathBuf> {
    #[cfg(unix)]
    if !parent_pid_matches() {
        return None;
    }
    let expected = std::path::PathBuf::from(std::env::var_os(marker_env)?);
    let actual = std::env::current_dir().expect("current_dir");
    assert_eq!(
        actual.canonicalize().expect("canonicalize actual cwd"),
        expected.canonicalize().expect("canonicalize expected cwd"),
        "this fixture's OS-level cwd must be the directory run_fixture_with_cwd's caller prepared",
    );
    // The only write on any platform: `parent_pid_matches` (unlike `is_fixture_reexec`) has no
    // side effect of its own, precisely so this line stays unwritten until the marker read and
    // the cwd assert above have BOTH succeeded — see `parent_pid_matches`'s doc for why that
    // order matters.
    write_gate_passed();
    Some(expected)
}

/// Builds the fully-qualified libtest `--exact` path of the `#[test] fn` named `$name`, for
/// [`run_fixture_with_cwd`]'s `fixture` argument. Two things tie the call site to the fixture
/// instead of letting them drift apart as two independently hand-typed strings:
///
/// - `let _: fn() = $name;` forces the compiler to resolve `$name` as an item in scope — a typo
///   or a stale name after a rename is a compile error here, not a filter that silently matches
///   zero tests at runtime (see [`run_fixture_with_cwd`]'s doc for why that is exactly the bug
///   this macro exists to rule out).
/// - `module_path!()` derives the module portion at compile time, so it can never fall out of
///   sync with a file move or a module rename; libtest's `--exact` filter never includes the
///   crate-name component `module_path!()` always carries as its own first segment, hence the
///   [`strip_crate_prefix`] call.
macro_rules! fixture_path {
    ($name:ident) => {{
        let _: fn() = $name;
        crate::test_child::strip_crate_prefix(concat!(module_path!(), "::", stringify!($name)))
    }};
}
pub(crate) use fixture_path;

/// Strips the crate-name segment `module_path!()` always carries as its own first component
/// (e.g. `"cosca::resolve::resolve_tests"`), since libtest's `--exact` filter never includes it
/// (e.g. `"resolve::resolve_tests"`). Panics if `path` does not start with that segment, which
/// would mean `module_path!()`'s documented contract no longer holds.
pub(crate) fn strip_crate_prefix(path: &'static str) -> &'static str {
    let prefix = concat!(env!("CARGO_PKG_NAME"), "::");
    path.strip_prefix(prefix)
        .unwrap_or_else(|| panic!("{path:?} does not start with {prefix:?} — module_path!()'s contract changed"))
}

/// A child that exits promptly and needs no external binary: this same test binary, run
/// with a filter that matches nothing, so libtest runs zero tests and exits 0.
///
/// The libtest filter is mandatory, and is why this lives in exactly one place: re-execing
/// the test binary with NO arguments runs the whole suite — including whichever test called
/// this — which then re-execs again, unboundedly.
///
/// Spawns under `spawn_lock()`: on macOS, a fork here that lands while another test's fd
/// marker write end happens to be open would transiently inherit it, and a concurrently
/// running sweep could then find and signal this bystander child. `spawn_lock()` is the same
/// lock every cosca-originated spawn in this test binary already takes.
pub(crate) fn spawn_a_process_that_exits() -> std::process::Child {
    let _guard = crate::child::spawn::spawn_lock();
    std::process::Command::new(std::env::current_exe().expect("current_exe"))
        .args(["--exact", "__cosca_no_such_test__"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn")
}

/// The argv for re-executing this test binary against one fixture through `cosca::Command`,
/// whose `args` is the **full** argv — libtest drops slot 0 as the binary name, so a filter or
/// option placed there is silently eaten and `--exact` degrades to substring matching.
/// `--test-threads=1` keeps a future filter that matches more than one test from running them
/// concurrently inside a process the caller is about to signal.
#[cfg(any(windows, feature = "tokio"))]
pub(crate) fn fixture_argv(test: &str) -> [&str; 4] {
    ["cosca_unit_tests", "--test-threads=1", "--exact", test]
}

/// The fully-qualified libtest path of [`fixture_survives_group_signal`], for callers that
/// re-exec this binary against it directly (`current_exe() --exact <this>`) rather than through
/// [`spawn_a_process_that_exits`]'s own filter.
#[cfg(windows)]
pub(crate) const FIXTURE_SURVIVES_GROUP_SIGNAL_TEST: &str = "test_child::fixture_survives_group_signal";

/// The env var carrying the `127.0.0.1:<port>` address [`fixture_survives_group_signal`] connects
/// back to and tags once the grandchild survivor exists in its own process group. Its mere
/// presence also tells the fixture it was re-exec'd deliberately rather than picked up by an
/// ordinary, unfiltered suite run — one var serves both roles, since the fixture needs the
/// address either way.
#[cfg(windows)]
pub(crate) const FIXTURE_SURVIVES_GROUP_SIGNAL_ADDR_ENV: &str = "COSCA_FIXTURE_SURVIVES_GROUP_SIGNAL_ADDR";

/// Windows-only fixture for the `root_exited`-on-`MembersRemain` regression (sync and async
/// twins): a no-op when picked up by an ordinary, unfiltered suite run —
/// [`FIXTURE_SURVIVES_GROUP_SIGNAL_ADDR_ENV`] is unset there. Re-executed via `current_exe()
/// --exact` [`FIXTURE_SURVIVES_GROUP_SIGNAL_TEST`] with that var set, it instead spawns a
/// grandchild a group `CTRL_BREAK` can never reach — `CREATE_NEW_PROCESS_GROUP` puts it in its
/// own process group, the same isolation `graceful_shutdown_tree`'s own doc describes for a
/// nested contained descendant — then connects to the caller's listener at that address and
/// writes a single tag byte, proving the grandchild already exists (and is already in its own
/// group) before the caller proceeds to call `graceful_shutdown_tree`. The tag goes out over a
/// real TCP socket, not `print!`/`io::stdout()`: libtest captures the latter per-test and
/// discards it for a passing test, so a stdout-based readiness byte never reaches the caller's
/// piped reader at all — this is the same control-channel shape `tests/common`'s
/// `spawn_tree`/`spawn_tree_async` tag handshake already uses for exactly this reason, not a
/// Windows-specific mechanism. The job object still tracks the grandchild as a tree member
/// despite its own process group (job membership and process group are independent Win32
/// concepts), so it shows up as a `MembersRemain` survivor even though the signal itself never
/// reaches it. Mirrors [`spawn_a_process_that_exits`]'s filtered-re-exec idiom (see its own doc
/// for why the filter is mandatory) put to a second use.
#[cfg(windows)]
#[test]
fn fixture_survives_group_signal() {
    let Some(addr) = std::env::var_os(FIXTURE_SURVIVES_GROUP_SIGNAL_ADDR_ENV) else {
        return; // picked up by an ordinary suite run — deliberately inert
    };
    use std::io::Write;
    use std::os::windows::process::CommandExt;

    // CREATE_NEW_PROCESS_GROUP (winbase.h). A scalar flag, so a raw constant needs no
    // `windows`-crate import: `std::os::windows::process::CommandExt::creation_flags` takes it
    // as a plain `u32`.
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    #[allow(clippy::zombie_processes)] // intentional: the grandchild must outlive us; containment kills it
    let _survivor = std::process::Command::new("ping")
        .args(["-n", "30", "127.0.0.1"])
        .creation_flags(CREATE_NEW_PROCESS_GROUP)
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("spawn a grandchild the group signal cannot reach");
    let mut sock = std::net::TcpStream::connect(addr.to_str().expect("utf8 addr")).expect("connect readiness socket");
    sock.write_all(b"R").expect("write readiness tag");
}

/// The fully-qualified libtest path of [`fixture_registers_then_blocks`], for callers that
/// re-exec this binary against it directly (`current_exe() --exact <this>`).
// Gated with its consumers: the sync caller uses it only under `cfg(windows)`, the other two are
// behind the `tokio` feature, so a default-feature Unix build has none and `-D warnings` rejects it.
#[cfg(any(windows, feature = "tokio"))]
pub(crate) const FIXTURE_REGISTERS_THEN_BLOCKS_TEST: &str = "test_child::fixture_registers_then_blocks";

/// The env var carrying the `127.0.0.1:<port>` address [`fixture_registers_then_blocks`] tags.
/// Its mere presence also tells the fixture it was re-exec'd deliberately rather than picked up
/// by an ordinary, unfiltered suite run.
pub(crate) const FIXTURE_REGISTERS_THEN_BLOCKS_ADDR_ENV: &str = "COSCA_FIXTURE_REGISTERS_THEN_BLOCKS_ADDR";

/// Bind a rendezvous listener for [`fixture_registers_then_blocks`]; returns it and its
/// `127.0.0.1:<port>` address.
#[cfg(any(windows, feature = "tokio"))]
pub(crate) fn registration_rendezvous() -> (std::net::TcpListener, String) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind rendezvous listener");
    let addr = listener.local_addr().expect("local_addr").to_string();
    (listener, addr)
}

/// Fixture supplying a happens-before edge on a live child: a no-op when picked up by an
/// ordinary, unfiltered suite run ([`FIXTURE_REGISTERS_THEN_BLOCKS_ADDR_ENV`] is unset there).
/// Re-executed via `current_exe() --exact` [`FIXTURE_REGISTERS_THEN_BLOCKS_TEST`] with that var
/// set, it connects to the caller's listener, writes one tag byte, then blocks on a 1-byte read
/// of that same socket. The caller unblocks it by writing a byte back, and it then exits 0 of
/// its own accord — an exit code no forced kill can produce.
///
/// The tag is the edge: the fixture cannot write it until it is executing its own code. On
/// Windows that is also after the console has registered it — a child signalled before that
/// point dies during loader init instead of to the console event, which is a different exit code
/// and a different thing under test.
///
/// It installs no console-control handler, so `CTRL_BREAK`'s default disposition terminates it.
/// Blocking on the socket rather than parking means a panicking or aborted caller closes the
/// socket and the fixture exits on EOF instead of orphaning.
#[test]
fn fixture_registers_then_blocks() {
    let Some(addr) = std::env::var_os(FIXTURE_REGISTERS_THEN_BLOCKS_ADDR_ENV) else {
        return; // picked up by an ordinary suite run — deliberately inert
    };
    use std::io::{Read, Write};

    let mut sock = std::net::TcpStream::connect(addr.to_str().expect("utf8 addr")).expect("connect rendezvous socket");
    sock.write_all(b"R").expect("write registration tag");
    sock.flush().expect("flush registration tag");
    let mut sink = [0u8; 1];
    let _ = sock.read(&mut sink);
}

/// The fully-qualified libtest path of [`fixture_control_block`].
#[cfg(feature = "tokio")]
pub(crate) const FIXTURE_CONTROL_BLOCK_TEST: &str = "test_child::fixture_control_block";

/// The env var carrying the `127.0.0.1:<port>` address [`fixture_control_block`] tags. Its mere
/// presence also tells the fixture it was re-exec'd deliberately rather than picked up by an
/// ordinary, unfiltered suite run.
#[cfg(feature = "tokio")]
pub(crate) const FIXTURE_CONTROL_BLOCK_ADDR_ENV: &str = "COSCA_FIXTURE_CONTROL_BLOCK_ADDR";

/// A child that reports readiness and then blocks until the caller releases or kills it: a no-op
/// when picked up by an ordinary, unfiltered suite run ([`FIXTURE_CONTROL_BLOCK_ADDR_ENV`] is
/// unset there). Re-executed via `current_exe() --exact` [`FIXTURE_CONTROL_BLOCK_TEST`] with that
/// var set, it connects to the caller's listener, writes one tag byte, then blocks on a 1-byte
/// read of that same socket and RETURNS as soon as the read returns — so a caller that writes a
/// byte gets a clean voluntary exit, and a caller that kills it gets the socket's EOF.
///
/// Mirrors [`fixture_registers_then_blocks`]'s filtered-re-exec idiom (see
/// [`spawn_a_process_that_exits`] for why the filter is mandatory), and deliberately takes NO
/// `spawn_lock()`: see [`spawn_async_blocker`].
#[cfg(feature = "tokio")]
#[test]
fn fixture_control_block() {
    let Some(addr) = std::env::var_os(FIXTURE_CONTROL_BLOCK_ADDR_ENV) else {
        return; // picked up by an ordinary suite run — deliberately inert
    };
    use std::io::{Read, Write};

    let mut sock = std::net::TcpStream::connect(addr.to_str().expect("utf8 addr")).expect("connect control socket");
    sock.write_all(b"R").expect("write readiness tag");
    sock.flush().expect("flush readiness tag");
    let mut sink = [0u8; 1];
    let _ = sock.read(&mut sink);
}

/// Spawn [`fixture_control_block`] through `cosca::tokio` and return its handle plus the control
/// socket, already past the readiness tag — so the child is provably executing its own code.
///
/// **Takes no `spawn_lock()`, deliberately.** That lock is a plain non-reentrant mutex and
/// cosca's own async spawn takes it internally, so a helper holding it across a cosca spawn
/// deadlocks on its own thread. Every existing helper that takes it spawns via
/// `std::process::Command`; the cosca-spawning helpers do not.
///
/// Uncontained (so the tree teardown is a verified no-op) and stdin INHERITED (so closing the
/// parent's stdio cannot make the child exit on its own). Spawned via `executable()`, which puts
/// Windows on the raw `CreateProcessW` backend.
#[cfg(feature = "tokio")]
pub(crate) fn spawn_async_blocker() -> (crate::tokio::Child, std::net::TcpStream) {
    use std::io::Read as _;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind control listener");
    let addr = listener.local_addr().expect("local_addr").to_string();
    let exe = std::env::current_exe().expect("current_exe");
    let mut cmd = crate::tokio::Command::new();
    cmd.executable(&exe)
        .args(fixture_argv(FIXTURE_CONTROL_BLOCK_TEST))
        .env(FIXTURE_CONTROL_BLOCK_ADDR_ENV, &addr);
    // The child runs a full libtest harness, which writes its `running 1 test` / `test result:`
    // banner to fd 1 directly — libtest's capture wraps the Rust print machinery, not the
    // descriptor, so an inherited fd 1 lands that banner raw (and mid-line) in THIS binary's
    // output. Both are nulled; stdin stays inherited, per this helper's contract.
    cmd.stdout(crate::stdio::Stdio::null()).expect("stdout null");
    cmd.stderr(crate::stdio::Stdio::null()).expect("stderr null");
    let child = cmd.spawn().expect("spawn the control-block fixture");
    let (mut sock, _) = listener.accept().expect("accept the control socket");
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("read the readiness tag");
    assert_eq!(&tag, b"R", "unexpected control tag");
    (child, sock)
}

/// Exit code of the `tool` in [`cwd_and_path_tools`]'s first directory.
#[cfg(unix)]
pub(crate) const CWD_TOOL_EXIT: i32 = 11;
/// Exit code of the `tool` in [`cwd_and_path_tools`]'s second directory.
#[cfg(unix)]
pub(crate) const PATH_TOOL_EXIT: i32 = 22;

/// Two directories, each holding an executable script named `tool` that exits with its own code
/// ([`CWD_TOOL_EXIT`], [`PATH_TOOL_EXIT`]), so a child's exit status says which one was loaded.
/// Meant as the child's working directory and its `PATH`, respectively.
///
/// Each write is serialized against every other spawn's `fork` and the guard dropped before the
/// caller's spawn: a `fork` while a script's writable descriptor is open leaves the forked child
/// holding it until it execs, and `execve` of that script then fails with `ETXTBSY`. The lock is
/// not reentrant, so holding it across a `spawn()` would deadlock.
#[cfg(unix)]
pub(crate) fn cwd_and_path_tools() -> (tempfile::TempDir, tempfile::TempDir) {
    use std::os::unix::fs::PermissionsExt;
    let dirs = (
        tempfile::tempdir().expect("tempdir"),
        tempfile::tempdir().expect("tempdir"),
    );
    for (dir, code) in [(&dirs.0, CWD_TOOL_EXIT), (&dirs.1, PATH_TOOL_EXIT)] {
        let tool = dir.path().join("tool");
        let _guard = crate::child::spawn::spawn_lock();
        std::fs::write(&tool, format!("#!/bin/sh\nexit {code}\n")).expect("write tool");
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).expect("chmod tool");
    }
    dirs
}

#[cfg(test)]
#[path = "test_child_tests.rs"]
mod test_child_tests;
