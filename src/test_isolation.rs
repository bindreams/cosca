//! Test isolation for a test that mutates process-wide state (closes fd 0/1/2, lowers
//! `RLIMIT_NOFILE`): the mutation and its restore must run alone in a process, or a concurrently
//! running, unrelated test thread can be corrupted by it. This is ONE file, included by both of
//! this crate's separate compilation units:
//! - `src/lib.rs`: a normal `mod test_isolation;` (this file lives under `src/`, so no `#[path]`
//!   or crate self-alias is needed — `crate::` already means `cosca` here). Its own unit tests
//!   live separately, in `src/test_isolation_tests.rs` (a lib-only, ordinary sibling module — see
//!   its own doc for why it is NOT nested inside this file).
//! - `tests/common/mod.rs`: `#[path = "../../src/test_isolation.rs"] mod isolation;`, for every
//!   integration test binary. `super::test_spawn_lock` is how this file reaches
//!   `cosca::test_spawn_lock` from that mount point — `tests/common/mod.rs` re-exports it under
//!   that name for exactly this.
//!
//! `crate::` is NOT used anywhere below for that reason: it resolves to `cosca` at the lib mount
//! point but to whichever integration test binary is compiling at the other, and this file cannot
//! know which. `super::` is: at the lib mount point, `super::test_spawn_lock` is `crate::
//! test_spawn_lock` (defined right there in `src/lib.rs`); at the integration mount point, it is
//! `common::test_spawn_lock`, the re-export.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub(crate) const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Builds the fully-qualified libtest `--exact` path of the `#[test] fn` named `$name`, the same
/// way `crate::test_child::fixture_path!` does (that macro cannot be reused directly: it names
/// `crate::test_child`, a lib-only module invisible to the integration-test mount point). Ties the
/// call site to the fixture so they cannot drift into two independently hand-typed strings.
///
/// `unused_macros` is allowed here, not fixed by using it below: nothing in THIS file invokes it
/// any more (its only caller, `isolation_tests`, moved out to the lib-only `src/
/// test_isolation_tests.rs` — see that file's own doc for why it could not stay nested here). At
/// the lib mount point that invocation is enough to mark it used; at every integration-test mount
/// point (a SEPARATE compilation of this same file, which that lib-only caller never reaches) it
/// genuinely is not, since no integration test currently calls `common::fixture_path!` either.
#[allow(unused_macros)]
macro_rules! fixture_path {
    ($name:ident) => {{
        let _: fn() = $name;
        // Strips the crate-name segment `module_path!()` always carries as its own first
        // component (e.g. `"cosca::test_isolation_tests"` or `"spawn_io::common::isolation"`),
        // since libtest's `--exact` filter never includes it. Inlined rather than a named helper
        // function: this macro is used from `src/test_isolation_tests.rs`, a module at a
        // DIFFERENT location than where it is defined here, and macro hygiene does not resolve a
        // bare function call across that gap the way a fully local expression does.
        let path: &'static str = concat!(module_path!(), "::", stringify!($name));
        match path.split_once("::") {
            Some((_, rest)) => rest,
            None => path,
        }
    }};
}
pub(crate) use fixture_path;

/// The re-exec args [`alone`]/[`alone_capturing`] pass after the test name; [`alone_marker_matches`]
/// demands this process's own argv match this shape before trusting a `COSCA_TEST_ALONE` env var.
pub const ALONE_ARGS: [&str; 4] = ["--exact", "--include-ignored", "--nocapture", "--test-threads=1"];

/// True only if `value` is `Some` AND this process's own argv (skipping argv[0], the binary path)
/// is exactly `[value, ALONE_ARGS...]` — proof that libtest was invoked to run exactly one named
/// test, not merely that some env var happens to be set.
///
/// `COSCA_TEST_ALONE` alone is not proof: it is inherited by children and can leak from a shell or
/// outer re-exec into an ordinary many-threads run. Argv is set by whoever invoked this process,
/// so a genuine isolated child (invoked by [`alone`]) is the only one that matches.
pub(crate) fn alone_marker_matches(value: Option<&str>, argv: &[String]) -> bool {
    let Some(value) = value else { return false };
    argv.len() == ALONE_ARGS.len() + 1
        && argv[0] == value
        && argv[1..].iter().map(String::as_str).eq(ALONE_ARGS.iter().copied())
}

/// A completion token a re-exec'd child writes to an inherited pipe right before its own test body
/// returns normally — proof the body ran to completion, not merely that the process exited zero
/// (which a premature, silent `std::process::exit` could also produce — see [`Completion`]).
/// [`alone`]/[`alone_capturing`] decide pass/fail from this token plus the exit status, never by
/// scanning libtest's own stdout banner for human text like `"1 passed"` — this repo's own
/// convention against parsing human text applies to reading OUR OWN child's output just as much as
/// any external tool's.
///
/// The write end's `CLOEXEC` flag is cleared so it survives into the child at the SAME fd number,
/// which the child is told via [`TOKEN_FD_ENV`] — clearing it happens while this process holds
/// `test_spawn_lock()`, the same lock that already serializes every raw fork here, so no
/// concurrent, unrelated spawn can observe the momentarily-inheritable fd. "Momentarily" on the
/// child's own side too: [`reclaim_cloexec_on_inherited_fds`] sets `CLOEXEC` back the instant the
/// child recognizes itself, before its real body runs — this process's own later write
/// ([`write_completion_token_if_child`]) happens directly, by fd number, never across a further
/// exec, so nothing about that write needs the fd to stay inheritable one moment longer. Left
/// cleared, it would leak into every further child the test body itself spawns instead.
pub(crate) const TOKEN_FD_ENV: &str = "COSCA_TEST_ALONE_TOKEN_FD";

/// The pid `spawn_alone` recorded as this child's own immediate parent, set alongside
/// [`TOKEN_FD_ENV`] — the ONLY thing [`write_completion_token_if_child`] trusts before writing.
///
/// A caller that fans out its OWN further `ALONE_ARGS`-shaped children (like the closed-std-slots
/// sweep in `tests/spawn_io.rs`) has each one inherit `TOKEN_FD_ENV` from ITS parent too — an
/// ordinary env var, unaffected by that parent's own copy of the pipe fd having already closed —
/// naming a fd number that means nothing in the grandchild's own, freshly-forked fd table.
/// Trusting the fd number alone, even after confirming it happens to BE a pipe right now, is only
/// probabilistic: a fan-out that itself spawns enough children can make that number alias one of
/// ITS OWN, entirely unrelated pipes. `getppid()` is not: a grandchild's real immediate parent is
/// always the process that actually forked it, never the original `spawn_alone` caller further up
/// — so comparing it against the pid `spawn_alone` recorded for THIS specific pipe refuses every
/// such grandchild deterministically, regardless of what the leaked fd number happens to alias.
pub(crate) const TOKEN_PARENT_ENV: &str = "COSCA_TEST_ALONE_TOKEN_PARENT";

/// The read end of a pipe only `spawn_alone`'s own caller holds the write end of — inherited by
/// the re-exec'd child, whose [`install_lifeline_watcher`] blocks a background thread reading it.
///
/// `spawn_alone` already puts the child in its OWN, fresh process group (`setpgid(0, 0)`) so a
/// bounded wait THIS process detects (a hung child) can kill the whole group, reaching any
/// grandchildren the child spawned into it. That same separate group is exactly what makes the
/// child UNREACHABLE by a signal sent to the group of whatever process ran `spawn_alone` — measured
/// with a real nextest TIMEOUT (nextest runs each test in its own process): nextest kills only the
/// ONE process it manages and waits on, not a process group, and that process's own group is not
/// the re-exec'd child's — so the child survived as an orphan (parent pid 1), immune to the kill
/// that ended the run.
///
/// This closes that gap from the other end: the lifeline's write end lives only in the process
/// `spawn_alone` calls from, and is deliberately kept open for exactly as long as that process is
/// still around to wait for the child — closing early (an explicit drop before the wait, "tidying
/// up") would kill a child that is still legitimately running, so nothing does that. Whether that
/// process exits cleanly (its own last reference to the write end closes as part of ordinary
/// process teardown) or is itself killed out from under the child (a SIGKILL closes every fd a
/// process holds, same as any other exit), the child's watcher thread observes EOF and
/// self-destructs its own process group — reaching itself and anything it spawned into that group,
/// exactly like the bounded-wait kill path does for a hang THIS process detects itself. The two
/// mechanisms are complementary: one covers a hang this process notices; this one covers the
/// hanging (or promptly killed) process itself disappearing before it gets the chance to notice
/// anything.
pub(crate) const LIFELINE_FD_ENV: &str = "COSCA_TEST_ALONE_LIFELINE_FD";

/// True if THIS process's real, immediate parent (`getppid()`) matches the pid `spawn_alone`
/// recorded in [`TOKEN_PARENT_ENV`] when it launched this exact process — proof of a genuine,
/// direct `spawn_alone` child, never merely that the fd numbers and env vars are present (see
/// [`TOKEN_PARENT_ENV`]'s own doc for why a fan-out grandchild can inherit both without being
/// one).
fn is_genuine_spawn_alone_child() -> bool {
    let Some(expected_parent) = std::env::var_os(TOKEN_PARENT_ENV) else {
        return false;
    };
    let Some(expected_parent) = expected_parent.to_str().and_then(|s| s.parse::<libc::pid_t>().ok()) else {
        return false;
    };
    // SAFETY: getppid() takes no arguments and cannot fail.
    unsafe { libc::getppid() == expected_parent }
}

/// Write the completion token to the fd [`TOKEN_FD_ENV`] names, if this process is a genuine,
/// direct `spawn_alone` child (see [`is_genuine_spawn_alone_child`]). Called once, by
/// [`Completion`]'s own `Drop`, when it is not unwinding a panic — see there for why that, and not
/// the moment [`alone`]/[`alone_capturing`] recognize the child, is when this must run.
fn write_completion_token_if_child() {
    if !is_genuine_spawn_alone_child() {
        return;
    }
    let Some(fd) = std::env::var_os(TOKEN_FD_ENV) else {
        return;
    };
    let fd: i32 = fd.to_str().and_then(|s| s.parse().ok()).expect("valid fd number");
    // Defense in depth beyond the ppid check above, in case some OTHER bug ever lets a fd number
    // reach here that a genuine spawn_alone child was never actually given: refuse anything that
    // is not a pipe. Nothing this process opens before this point (libtest's own startup, argv/env
    // parsing) is one, so a real, intended token fd always passes this too.
    // SAFETY: `fstat` on a caller-supplied fd number; reads only, never touches ownership.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0 || stat.st_mode & libc::S_IFMT != libc::S_IFIFO {
        return;
    }
    // SAFETY: `fd` was made inheritable by this exact process's own parent (confirmed above),
    // specifically for this write; confirmed a pipe just above; owned exclusively from here.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    use std::io::Write;
    let _ = file.write_all(b"1");
}

/// Set `FD_CLOEXEC` back on [`TOKEN_FD_ENV`]'s and [`LIFELINE_FD_ENV`]'s own fds, for the
/// re-exec'd child itself. `spawn_alone` clears it on both so they survive ITS OWN exec into this
/// process — nothing needs them inheritable beyond that: this process's own later completion-token
/// write ([`write_completion_token_if_child`]) and lifeline read ([`install_lifeline_watcher`])
/// both happen directly, by fd number, from THIS SAME process, never across a further exec.
///
/// Left cleared, both fds leak into EVERY further child the test body itself spawns (measured,
/// round 7 review: a `sh -c "ls -l /proc/self/fd"` grandchild showed both open, at fd numbers
/// named by `TOKEN_FD_ENV`/`LIFELINE_FD_ENV` themselves). Two concrete costs, not just a
/// hygiene concern: `spawn_alone`'s own `token_read.read_to_end` (see there) blocks until EVERY
/// copy of the write end closes, so a grandchild that outlives the test body's own return (e.g.
/// `Stdio::null()`'d and detached, as a real cosca child under test often is) delays — measured: a
/// `sleep 45` grandchild made the whole `alone()` call take 45s — or, if it never exits at all,
/// hangs the outer call forever, not just this one test. A grandchild holding the lifeline read
/// end open the same way would additionally defeat N2's own mechanism for it specifically.
///
/// Called once, by the child branch of both [`alone`] and [`alone_capturing`], right after this
/// process recognizes itself — before either function returns control to the real test body, so
/// nothing the body runs (including its own very first `Command::spawn`) can ever observe either
/// fd as inheritable.
///
/// For a genuine `spawn_alone` child (`is_genuine_spawn_alone_child()`), both fds are guaranteed
/// present and valid — an `fcntl` failure there is a real, unreachable-in-practice bug, not a
/// tolerated outcome, so it is `debug_assert!`ed (principle 7). A fan-out GRANDCHILD's own
/// inherited env vars, by contrast, may legitimately name a fd that means nothing in its own fd
/// table (see [`TOKEN_PARENT_ENV`]'s own doc) — an `fcntl` failure there is expected and silently
/// tolerated, same as today.
fn reclaim_cloexec_on_inherited_fds() {
    let genuine = is_genuine_spawn_alone_child();
    for env in [TOKEN_FD_ENV, LIFELINE_FD_ENV] {
        let Some(fd) = std::env::var_os(env) else { continue };
        let Some(fd) = fd.to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        // SAFETY: `fd` was made inheritable by `spawn_alone` specifically for this child;
        // restoring FD_CLOEXEC does not close it or otherwise affect this process's OWN direct
        // use of it (write_completion_token_if_child, install_lifeline_watcher both read/write it
        // by raw fd number, unaffected by CLOEXEC, which only ever applies across an exec).
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            debug_assert!(
                !genuine || flags != -1,
                "fcntl(F_GETFD) on a genuine spawn_alone child's own {env} fd {fd} failed: {}",
                std::io::Error::last_os_error()
            );
            if flags != -1 {
                let ret = libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
                debug_assert!(
                    !genuine || ret == 0,
                    "fcntl(F_SETFD) to reclaim CLOEXEC on a genuine spawn_alone child's own {env} \
                     fd {fd} failed: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
    }
}

/// Close this process's own inherited [`TOKEN_FD_ENV`] fd without writing to it — for a child
/// spawned via [`alone_capturing`], whose caller inspects the re-exec'd child's raw `Output`
/// directly and never reads the completion token. Unlike [`alone`]'s child (see [`Completion`]),
/// there is nothing to defer: closing immediately, rather than leaving it open for the rest of
/// this process's life (or leaking it into anything this body itself forks), is strictly better
/// hygiene with nothing to trade it against.
fn close_inherited_completion_token() {
    let Some(fd) = std::env::var_os(TOKEN_FD_ENV) else {
        return;
    };
    let Some(fd) = fd.to_str().and_then(|s| s.parse::<i32>().ok()) else {
        return;
    };
    // SAFETY: `fd` was made inheritable by `spawn_alone` specifically for this child; an
    // `alone_capturing` child never uses it for anything else.
    unsafe {
        libc::close(fd);
    }
}

/// Spawn the background thread that blocks reading [`LIFELINE_FD_ENV`], and on EOF (or any read
/// error) self-destructs this process's own group — see that const's own doc for the full
/// scenario. Called once, by the child branch of both [`alone`] and [`alone_capturing`], right
/// after this process recognizes itself as a `spawn_alone`-launched child. A no-op if
/// `LIFELINE_FD_ENV` is unset (an ordinary suite run was not re-exec'd by `spawn_alone` at all).
fn install_lifeline_watcher() {
    let Some(fd) = std::env::var_os(LIFELINE_FD_ENV) else {
        return;
    };
    let fd: i32 = fd.to_str().and_then(|s| s.parse().ok()).expect("valid fd number");
    std::thread::spawn(move || {
        // SAFETY: `fd` was made inheritable by `spawn_alone` specifically for this read, and is
        // owned exclusively by this thread from here on.
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut buf = [0u8; 1];
        use std::io::Read;
        // Blocks until the parent's own write end closes — a clean drop once it is done waiting
        // for us (harmless: we will already have exited normally by then too, so nothing is left
        // for the SIGKILL below to reach), or that whole process dying instead (the scenario this
        // exists for). Either way, whoever launched us is gone or done with us.
        let _ = file.read(&mut buf);
        // SAFETY: pid 0 means "this process's own process group" — every process this child
        // itself has spawned into that SAME group (it is the leader, from `spawn_alone`'s own
        // `setpgid(0, 0)`), never any unrelated process.
        unsafe {
            libc::kill(0, libc::SIGKILL);
        }
    });
}

/// An RAII marker [`alone`]/[`alone_capturing`] return to the re-exec'd child — bind it to a
/// NAMED variable, such as `_completion`, and hold that across the real test body. Its `Drop` is
/// the ONLY place that calls [`write_completion_token_if_child`], and only when the current
/// thread is not unwinding from a panic (`std::thread::panicking()`).
///
/// NEVER bind it to the bare wildcard `_` (directly, as `let _ = alone(name);`, or nested, as
/// `let Some(_) = alone(name) else { ... };`) — `_` is not a binding at all; the matched value is
/// a temporary that drops at the end of THAT STATEMENT, immediately, before the real body runs.
/// This reintroduces the exact bug this whole type exists to fix (see below), just one call site
/// away from `alone()`'s own recognition instead of inside it — confirmed on `rustc` 1.90 (round 7
/// review). `_completion` (a real, if underscore-PREFIXED, identifier) is a completely different,
/// safe thing: it silences the "unused variable" lint the SAME way `_` appears to, but binds
/// normally and drops at the END OF ITS ENCLOSING SCOPE, same as any other named variable.
///
/// This is what makes "the token arrived" prove "the body ran to completion", not merely "the
/// process exited zero": writing the token at the moment [`alone`] first recognizes the child
/// (before the real body has even started) would let a body that calls `std::process::exit(0)`
/// partway through — which skips every live value's `Drop`, this one included — report as a full
/// pass despite never reaching whatever it was still supposed to do. Measured: it did, before this
/// fix (see [`a_body_that_exits_early_produces_no_token`] in `src/test_isolation_tests.rs`).
pub struct Completion {
    _private: (),
}

impl Drop for Completion {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            write_completion_token_if_child();
        }
    }
}

/// Read `reader` to EOF on a background thread, bounded by `timeout`. `Ok(bytes)` once the read
/// genuinely reaches EOF within the bound — including a genuine, immediate EOF-with-no-bytes,
/// which is `Ok(vec![])`, indistinguishable from (and correctly treated the same as) a slow one.
/// `Err(ReadBoundedTimeout)` if `timeout` elapses first: expiry is never proof of anything (never
/// mapped to "no bytes", "empty", or any other verdict) — principle 8, and see the caller for why
/// silently folding a timeout into an empty read is a real bug, not a hypothetical one, for this
/// specific caller.
///
/// The background thread itself is not joined or otherwise waited on beyond `timeout`: on a
/// timeout it is abandoned (still blocked in its own read, if whatever holds `reader`'s write end
/// open never closes it) — a caller-visible bound instead of a caller-visible hang, at the cost of
/// one outstanding thread for the rest of THIS process's own life in the timeout case specifically
/// (never in the ordinary case, where the read completes and the thread exits normally well
/// within the bound).
struct ReadBoundedTimeout;

fn read_bounded(
    mut reader: impl std::io::Read + Send + 'static,
    timeout: std::time::Duration,
) -> Result<Vec<u8>, ReadBoundedTimeout> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = reader.read_to_end(&mut buf);
        let _ = tx.send(buf);
    });
    rx.recv_timeout(timeout).map_err(|_| ReadBoundedTimeout)
}

/// Spawn a fresh copy of this test binary against `name` with the isolated `alone()` shape
/// (`COSCA_TEST_ALONE=name`, argv [`ALONE_ARGS`]) plus `extra_env`, give it a token pipe (see
/// [`TOKEN_FD_ENV`]) and a lifeline pipe (see [`LIFELINE_FD_ENV`]), and wait for it — the shared
/// spawn machinery [`alone`], [`alone_capturing`] and [`alone_with_env`] all build on. Returns the
/// captured `Output` plus whether the completion token arrived.
///
/// `inherit`: further fds a caller wants the child to inherit too (e.g. a prover's own canary
/// pipe) — `spawn_alone` takes OWNERSHIP of them (not just a borrow) specifically so it can also
/// be what DROPS the caller's own copy, right after `cmd.spawn()`, STILL under the same locked
/// block the token/lifeline fds are already handled in. `CLOEXEC` is cleared on all of them
/// inside that SAME lock too, not by the caller beforehand: clearing it outside this lock, even
/// briefly, is exactly the round-6 N4 bug class (a concurrent, unrelated spawn on another thread
/// could observe the momentarily-inheritable fd) — measured again, round 8 review, on a test that
/// got this wrong by clearing CLOEXEC in its own, separate, already-released lock scope.
pub(crate) fn spawn_alone(
    name: &str,
    extra_env: &[(&str, &str)],
    inherit: Vec<std::os::fd::OwnedFd>,
) -> (std::process::Output, bool) {
    let (token_read, token_write) = std::io::pipe().expect("open completion-token pipe");
    let token_write_fd = token_write.as_raw_fd();
    let (lifeline_read, lifeline_write) = std::io::pipe().expect("open lifeline pipe");
    let lifeline_read_fd = lifeline_read.as_raw_fd();
    let this_pid = std::process::id();
    let child = {
        let _guard = super::test_spawn_lock();
        // SAFETY: clears FD_CLOEXEC on our own token pipe's write end, lifeline pipe's read end,
        // and every caller-supplied `inherit` fd, so all of them survive into the child at the
        // same fd numbers; held under `test_spawn_lock()`, so no concurrent, unrelated spawn in
        // this process can observe any of them momentarily-inheritable.
        for fd in [token_write_fd, lifeline_read_fd]
            .into_iter()
            .chain(inherit.iter().map(|f| f.as_raw_fd()))
        {
            unsafe {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                assert_ne!(
                    flags,
                    -1,
                    "fcntl(F_GETFD) on fd {fd}: {}",
                    std::io::Error::last_os_error()
                );
                assert_eq!(
                    libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC),
                    0,
                    "fcntl(F_SETFD) to make fd {fd} inheritable: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
        let mut cmd = std::process::Command::new(std::env::current_exe().expect("this test binary"));
        cmd.args(std::iter::once(name).chain(ALONE_ARGS))
            .env("COSCA_TEST_ALONE", name)
            .env(TOKEN_FD_ENV, token_write_fd.to_string())
            .env(TOKEN_PARENT_ENV, this_pid.to_string())
            .env(LIFELINE_FD_ENV, lifeline_read_fd.to_string())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        for &(k, v) in extra_env {
            cmd.env(k, v);
        }
        // SAFETY: async-signal-safe; puts the child in its OWN new process group (pgid == its own
        // pid) before it execs, so a later bounded-wait timeout (`wait_bounded` below) can kill
        // that WHOLE group — not just this direct child — reaching any grandchildren it spawned
        // into that same group before hanging. This same separate group is what makes the
        // lifeline pipe above necessary in the first place — see [`LIFELINE_FD_ENV`]'s own doc for
        // why the two are complementary, not redundant.
        unsafe {
            use std::os::unix::process::CommandExt;
            cmd.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn().expect("spawn the test alone");
        // Both of OUR OWN copies must close HERE, before `test_spawn_lock()` releases below — not
        // merely before this function returns. Dropping them any later would extend the window
        // these exact fd numbers stay inheritable past what the lock actually serializes, so a
        // concurrent, unrelated spawn racing right after this block released the lock could still
        // observe one of them (this was exactly the token pipe's own bug, previously).
        //
        // `lifeline_write` (the OTHER end of the lifeline pipe) is deliberately NOT touched here —
        // it must stay open all the way past the wait below; see its own comment there.
        drop(token_write);
        drop(lifeline_read);
        // Same reasoning, for every `inherit`ed fd: this drops the CALLER's own copy (the only
        // one this function was ever given — `inherit`'s ownership, not a borrow, see this
        // function's own doc), while still under the same lock.
        drop(inherit);
        child
    };
    let out = wait_bounded(child, PROBE_TIMEOUT, true);
    // Bounded the same way `wait_bounded` itself is, not a bare blocking read: by the time
    // `wait_bounded` has returned, the CHILD has already exited, so ordinarily every copy of the
    // token write end is already gone too — but `reclaim_cloexec_on_inherited_fds` is what makes
    // that actually true (a leaked copy in a still-running grandchild would otherwise hold this
    // open indefinitely, hanging this read forever regardless of the child's own exit). A timeout
    // here is NEVER folded into "no token" (principle 8: expiry is never proof) — that would make
    // `alone()`'s own "no completion token: the body did not return normally" message state a
    // false cause whenever this read merely ran out of time, and could make
    // `a_body_that_exits_early_produces_no_token` pass for the wrong reason. It is instead a loud,
    // distinct failure of its own: a leaked fd is a real, upstream regression in its own right,
    // not something this call should quietly absorb.
    let token = read_bounded(token_read, PROBE_TIMEOUT).unwrap_or_else(|ReadBoundedTimeout| {
        panic!(
            "the token pipe's write end was still held after the child exited — some process \
             still holds a copy open {PROBE_TIMEOUT:?} after wait_bounded returned, which \
             reclaim_cloexec_on_inherited_fds should have made impossible for anything this \
             child itself spawned"
        )
    });
    // `lifeline_write` drops here, at the end of this function — deliberately kept alive across
    // the whole wait above. The child's own watcher thread self-destructs the instant it sees
    // THIS fd close, so closing it any earlier (even a "tidy" explicit drop right after spawning)
    // would kill a child that is still legitimately running. Dropping it here, after the child has
    // already exited, is a no-op for a child that finished normally — which it always has, by this
    // point, in the ordinary case `wait_bounded` returning at all represents.
    drop(lifeline_write);
    (out, token == b"1")
}

/// Run the test `name` (its full path, as libtest reports it) alone, in a fresh copy of this test
/// binary, and assert it passed. `Some(Completion)` in the copy — bind it to a NAMED variable
/// (e.g. `_completion`, NEVER the bare `_` — see [`Completion`]'s own doc for why) and hold that
/// across the test's real body, whose normal return is what makes its `Drop` report completion
/// (see [`Completion`]'s own doc for why that, not the moment of recognition, is when it must
/// run); `None` in the original caller, which must return immediately — the real work already
/// ran, in isolation, in the re-exec'd child.
///
/// Pass/fail is decided from the re-exec'd child's exit status AND its completion token, never by
/// scanning its stdout for libtest's own banner text.
#[must_use = "the caller must return immediately when this is None — the real work already ran, \
              in isolation, in the re-exec'd child. Bind the Some(Completion) to a NAMED variable \
              and hold it alive across the real body — NEVER the bare `_`, which drops it \
              immediately, before the real body runs; see Completion's own doc."]
pub fn alone(name: &str) -> Option<Completion> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if alone_marker_matches(Some(name), &argv) {
        reclaim_cloexec_on_inherited_fds();
        install_lifeline_watcher();
        return Some(Completion { _private: () });
    }
    let (out, completed) = spawn_alone(name, &[], vec![]);
    assert!(
        out.status.success() && completed,
        "{}{}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        out.status,
        if completed {
            ""
        } else {
            " (no completion token: the body did not return normally — it may have panicked, \
              called std::process::exit early, or otherwise never reached the point where the \
              Completion guard alone() returned to it would have dropped)"
        },
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    None
}

/// Like [`alone`], but the parent gets the re-exec'd child's captured `Output` instead of a
/// pass/fail assertion — for a prover whose body must inspect the child's exit code and stderr
/// content (e.g. a fixture that is SUPPOSED to panic), not just "did it pass."
///
/// Returns `None` in the child (proceed with the real body — there is nothing to hold: this
/// caller never reads the completion token, so its inherited copy of the token fd is closed
/// immediately instead, see [`close_inherited_completion_token`]); `Some(output)` in the parent.
/// Unlike `alone`, does not itself assert anything about `output` — the caller decides what it
/// means.
pub fn alone_capturing(name: &str) -> Option<std::process::Output> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if alone_marker_matches(Some(name), &argv) {
        reclaim_cloexec_on_inherited_fds();
        install_lifeline_watcher();
        close_inherited_completion_token();
        return None;
    }
    let (out, _completed) = spawn_alone(name, &[], vec![]);
    Some(out)
}

/// Like [`alone`], but for a caller that must pass its OWN further env vars into the re-exec'd
/// child — e.g. one case of a larger sweep, such as the closed-std-slots fan-out in
/// `tests/spawn_io.rs`, which needs a different `COSCA_TEST_CLOSED_SLOTS` per re-exec on top of
/// the ordinary `alone()` shape.
///
/// Always called from the SAME side `alone()`'s own parent branch is: this is not itself a
/// dispatch point. A caller reaches it only after ITS OWN, earlier `alone(name)` call already
/// recognized this process as the child for the surrounding, outer test — so there is no "am I
/// the child" question left to ask here; this always spawns and waits.
///
/// Returns the re-exec'd child's `Output` plus whether its completion token arrived — the same
/// pass/fail proof `alone()` asserts on internally, left here to the caller (e.g. to collect
/// several cases' failures before asserting once), never libtest's own stdout banner text.
pub fn alone_with_env(name: &str, extra_env: &[(&str, &str)]) -> (std::process::Output, bool) {
    spawn_alone(name, extra_env, vec![])
}

/// Require that this test is running alone in its own process, via [`alone`], before any caller
/// touches a process-wide resource. Fails loudly and immediately, before touching anything.
pub fn require_process_per_test(what: &str) {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let alone = alone_marker_matches(std::env::var("COSCA_TEST_ALONE").ok().as_deref(), &argv);
    assert!(alone, "{what}; call this from inside alone()");
}

/// Real fd 2 to `dup2` back before the panic hook's chained write runs, if a [`RestoreStdio`] is
/// currently holding fd 2 closed — `None` otherwise. Read only by the ONE process-wide hook
/// [`ensure_stderr_panic_hook`] installs; written only by [`RestoreStdio::close`] (sets) and its
/// `Drop` (clears). Only one `RestoreStdio` may hold fd 2 at a time — `close`'s own `assert!`
/// enforces that before the dup, the push, or the slot are ever touched, so a REJECTED guard never
/// has an entry for fd 2 in its own `saved` at all, and its `Drop` has nothing to restore or clear.
///
/// `Drop` only ever clears this slot and never calls [`std::panic::set_hook`]: calling it while
/// unwinding panics, and a panic during unwind aborts the process (`SIGABRT`). The hook is
/// installed once, process-wide, and reads this slot at panic time instead.
static SAVED_STDERR: std::sync::Mutex<Option<libc::c_int>> = std::sync::Mutex::new(None);

/// Lock [`SAVED_STDERR`], recovering from poison rather than panicking: read from inside a panic
/// hook and written from `Drop` during unwind, both places where panicking again must never happen.
fn saved_stderr() -> std::sync::MutexGuard<'static, Option<libc::c_int>> {
    SAVED_STDERR.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Install the ONE, process-wide panic hook that restores real fd 2 from [`SAVED_STDERR`] (if
/// occupied) before chaining to whatever hook was previously installed — so a panic while a
/// [`RestoreStdio`] holds fd 2 closed still reaches somewhere readable. Idempotent via `Once`.
fn ensure_stderr_panic_hook() {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if let Some(real_stderr) = *saved_stderr() {
                // SAFETY: `real_stderr` is a live dup of the original fd 2, owned by whichever
                // `RestoreStdio` currently occupies `SAVED_STDERR` — its `Drop` clears the slot
                // before that dup closes, so a `Some` read here is always still valid.
                unsafe { libc::dup2(real_stderr, 2) };
            }
            previous(info);
        }));
    });
}

/// Duplicate each of `fds` aside and close it, restoring all of them on drop (even if the test
/// panics), so the CURRENT process's own low-numbered descriptors are free for a test to reuse.
///
/// `close` asserts [`require_process_per_test`] before touching anything, and — for fd 2 — that no
/// other `RestoreStdio` already holds it, BEFORE duplicating fd 2 aside or pushing into the guard:
/// a violation this way leaves the first guard's registration completely untouched (nothing to
/// restore, nothing to clear) and its own panic message reaching real stderr — see [`SAVED_STDERR`]'s
/// doc for why an earlier version that checked only after the push let a rejected second guard's
/// own `Drop` clear the first guard's still-live registration.
pub struct RestoreStdio {
    saved: Vec<(libc::c_int, OwnedFd)>,
}

impl RestoreStdio {
    pub fn close(fds: &[libc::c_int]) -> RestoreStdio {
        let listed = fds.iter().map(|f| f.to_string()).collect::<Vec<_>>().join(", ");
        require_process_per_test(&format!(
            "closes process-wide fd{} {listed}",
            if fds.len() == 1 { "" } else { "s" }
        ));
        // A repeated fd (e.g. `&[2, 2]`) would dup an already-closed fd on the second pass.
        debug_assert!(
            {
                let mut sorted: Vec<libc::c_int> = fds.to_vec();
                sorted.sort_unstable();
                sorted.dedup();
                sorted.len() == fds.len()
            },
            "RestoreStdio::close: fds must be distinct, got {fds:?}"
        );
        let mut guard = RestoreStdio {
            saved: Vec::with_capacity(fds.len()),
        };
        for &fd in fds {
            if fd == 2 {
                ensure_stderr_panic_hook();
                // Checked BEFORE the dup-aside and the push below: a rejected guard must end up
                // with NO entry for fd 2 in `saved` at all, so its own `Drop` later has nothing to
                // restore or clear. NOT held across the assert: the temporary guard from
                // `*saved_stderr()` drops at the end of ITS OWN statement — holding it across the
                // assert would self-deadlock (the panic hook this scope is about to arm locks this
                // SAME mutex, on this SAME thread, as the first thing it does when the assert
                // panics, and a plain `Mutex` is not reentrant).
                let prev = *saved_stderr();
                assert!(
                    prev.is_none(),
                    "RestoreStdio::close: SAVED_STDERR already occupied (by fd {prev:?}) — two \
                     guards overlap on fd 2"
                );
            }
            // SAFETY: F_DUPFD_CLOEXEC(fd, 3) duplicates fd to a fresh number >= 3, checked below.
            let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
            assert!(
                dup >= 0,
                "dup fd {fd} aside before closing it: {}",
                std::io::Error::last_os_error()
            );
            // SAFETY: `dup` was just returned by a successful F_DUPFD_CLOEXEC.
            let dup = unsafe { OwnedFd::from_raw_fd(dup) };
            let dup_fd = dup.as_raw_fd();
            // Push into the guard, and (for fd 2) publish to `SAVED_STDERR`, BEFORE `close` below:
            // Linux frees a fd from the table even when `close` itself reports failure (EINTR,
            // EIO, ...), so a panic from the `close` assert below must find the guard and the
            // slot already armed.
            guard.saved.push((fd, dup));
            if fd == 2 {
                *saved_stderr() = Some(dup_fd);
            }
            assert_eq!(
                unsafe { libc::close(fd) },
                0,
                "close the test process' fd {fd}: {}",
                std::io::Error::last_os_error()
            );
        }
        guard
    }
}

impl Drop for RestoreStdio {
    fn drop(&mut self) {
        // Restore every fd WITHOUT panicking mid-loop — collecting failures instead — so this
        // function never panics TWICE: once here, and (if this `Drop` runs as part of unwinding an
        // earlier panic) a second panic during unwind is not caught — the process aborts. Reported
        // once, below.
        let mut failures: Vec<String> = Vec::new();
        for (fd, dup) in &self.saved {
            // SAFETY: dup2 back onto `fd`; `dup` stays valid (closed normally by its own Drop,
            // right after) regardless of this call's outcome. Retries EINTR the same way
            // `fd_map::dup2_onto` does.
            let ret = loop {
                let ret = unsafe { libc::dup2(dup.as_raw_fd(), *fd) };
                if ret != -1 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                    break ret;
                }
            };
            if ret != *fd {
                failures.push(format!(
                    "dup2({}, {fd}) while restoring a guarded fd failed: {}",
                    dup.as_raw_fd(),
                    std::io::Error::last_os_error()
                ));
            }
        }
        if !failures.is_empty() {
            let msg = format!("RestoreStdio::drop: {}", failures.join("; "));
            // Write the report DIRECTLY to this guard's own saved fd-2 dup, if it has one — not to
            // real fd 2 (via the panic hook or a plain `eprintln!`), which is exactly what a fd-2
            // restore failure calls into question. The dup is a copy of this process's REAL
            // stderr from before this guard closed it, so a direct write reaches it (the same
            // underlying pipe/file a caller captures as this process's stderr) regardless of what
            // real fd 2 currently holds.
            if let Some((_, dup)) = self.saved.iter().find(|(fd, _)| *fd == 2) {
                let line = format!("{msg}\n");
                // SAFETY: `dup` is a valid, still-open fd this guard owns exclusively until it
                // drops just below.
                unsafe { libc::write(dup.as_raw_fd(), line.as_ptr().cast(), line.len()) };
            }
            // Clear the slot only if it still holds THIS guard's own dup — a guard whose own
            // registration was rejected in `close` never has an fd-2 entry to reach this branch
            // at all, but the check costs nothing and documents the invariant directly.
            if let Some((_, dup)) = self.saved.iter().find(|(fd, _)| *fd == 2) {
                let my_fd = dup.as_raw_fd();
                let mut slot = saved_stderr();
                if *slot == Some(my_fd) {
                    *slot = None;
                }
            }
            // A NEW panic here, while this `Drop` is ALREADY unwinding an earlier panic, would
            // abort the process — worse than the failure it reports. Report without panicking in
            // that case; panic normally otherwise, so an ordinary restore failure still fails its
            // test.
            if std::thread::panicking() {
                eprintln!("{msg} (not panicking: already unwinding)");
            } else {
                panic!("{msg}");
            }
        } else if let Some((_, dup)) = self.saved.iter().find(|(fd, _)| *fd == 2) {
            let my_fd = dup.as_raw_fd();
            let mut slot = saved_stderr();
            if *slot == Some(my_fd) {
                *slot = None;
            }
        }
    }
}

/// Lower this process' own `RLIMIT_NOFILE` soft limit to `to`, for the life of the guard,
/// restoring the original soft limit on drop (even if the test panics).
///
/// A forked child inherits its parent's rlimits at fork time, before any `pre_exec` hook runs — so
/// lowering the limit HERE, in the process that calls `spawn()`, makes an ordinary child fd number
/// deterministically exceed the CHILD's own limit and fail its `dup2` with `EBADF`, regardless of
/// the host's real `ulimit -n`.
///
/// `lower_to` asserts [`require_process_per_test`] before touching anything: this is exactly as
/// process-wide, and exactly as unsafe outside a call wrapped in [`alone`], as `RestoreStdio::close`.
pub struct RestoreRlimitNofile {
    original: libc::rlimit,
}

impl RestoreRlimitNofile {
    pub fn lower_to(to: libc::rlim_t) -> RestoreRlimitNofile {
        require_process_per_test("lowers this process's own RLIMIT_NOFILE, process-wide");
        let mut original: libc::rlimit = unsafe { std::mem::zeroed() };
        // SAFETY: `original` is a valid, correctly-sized out-param.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut original) },
            0,
            "getrlimit(RLIMIT_NOFILE): {}",
            std::io::Error::last_os_error()
        );
        let lowered = libc::rlimit {
            rlim_cur: to,
            rlim_max: original.rlim_max,
        };
        // SAFETY: `lowered` only ever lowers `rlim_cur`; `rlim_max` is passed through unchanged,
        // so this cannot raise the process' hard ceiling.
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lowered) },
            0,
            "setrlimit(RLIMIT_NOFILE, {{cur: {to}, max: {}}}): {}",
            original.rlim_max,
            std::io::Error::last_os_error()
        );
        RestoreRlimitNofile { original }
    }
}

impl Drop for RestoreRlimitNofile {
    fn drop(&mut self) {
        // SAFETY: restores exactly the limit `getrlimit` reported before this guard lowered it.
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &self.original) };
        if ret != 0 {
            let msg = format!(
                "RestoreRlimitNofile::drop: setrlimit(RLIMIT_NOFILE, restore to {{cur: {}, max: {}}}) failed: {}",
                self.original.rlim_cur,
                self.original.rlim_max,
                std::io::Error::last_os_error()
            );
            // Same collect-and-report convention as `RestoreStdio::drop`: a second panic during
            // an unwind already in progress would abort the process instead of failing a test.
            if std::thread::panicking() {
                eprintln!("{msg} (not panicking: already unwinding)");
            } else {
                panic!("{msg}");
            }
        }
    }
}

pub(crate) type DrainResult = Result<(Vec<u8>, Vec<u8>), String>;

std::thread_local! {
    /// Test-only seam (see [`TimeoutSeam`]): while `Some`, the very next [`wait_on_channel`] call
    /// THIS THREAD makes has its own `Timeout` arm driven by an event instead of the real
    /// `Duration` it was passed. `None` in every production build/run — nothing outside this
    /// file's own tests ever installs one, so [`recv_or_seam`]'s fallback (a plain, unchanged
    /// `rx.recv_timeout(timeout)`) is the ENTIRE behavior everywhere else, unconditionally.
    static TIMEOUT_SEAM: std::cell::RefCell<Option<std::sync::mpsc::Receiver<()>>> = const { std::cell::RefCell::new(None) };
}

/// RAII seam, installed on the CURRENT thread, that makes the next [`wait_on_channel`] call THAT
/// SAME thread makes fire its own `Timeout` arm the instant [`TimeoutSeam::fire`] is called,
/// instead of waiting out the real `Duration` it was given. The code that runs once fired is
/// IDENTICAL either way — see [`recv_or_seam`] — so this changes only when the arm fires, never
/// what it does; nothing about wait_on_channel's own production behavior is touched by this
/// existing (a seam only a test installs).
///
/// Exists so a prover of a real, hardcoded, multi-second bound (like `spawn_alone`'s own
/// `PROBE_TIMEOUT`) can wait for the SPECIFIC event it actually cares about (here: its own
/// fixture's readiness byte arriving) rather than the real duration — turning a genuinely
/// 30-second test into a millisecond one without losing any coverage of the post-Timeout path
/// itself, which stays exactly as exercised as it always was.
pub(crate) struct TimeoutSeam {
    fire_tx: std::sync::mpsc::Sender<()>,
}

impl TimeoutSeam {
    /// Install a seam for the NEXT `wait_on_channel` call on this thread. Installing a second one
    /// before the first is consumed (i.e. before that first `wait_on_channel` call happens)
    /// replaces it — one seam is good for exactly one such call.
    pub(crate) fn install() -> TimeoutSeam {
        let (fire_tx, fire_rx) = std::sync::mpsc::channel();
        TIMEOUT_SEAM.with(|cell| *cell.borrow_mut() = Some(fire_rx));
        TimeoutSeam { fire_tx }
    }

    /// Fire the seam: the `wait_on_channel` call it was installed for treats this exactly like
    /// its real `Duration` elapsing — including the kill-and-reap the real `Timeout` arm performs.
    pub(crate) fn fire(&self) {
        let _ = self.fire_tx.send(());
    }
}

impl Drop for TimeoutSeam {
    fn drop(&mut self) {
        // If `recv_or_seam` never consumed this seam (this test's own `wait_on_channel` call
        // never happened, or a later-installed seam already replaced it), clear the slot so a
        // LATER, wholly unrelated `wait_on_channel` call on this same thread never picks up a
        // stale receiver whose sender (this one) is about to disappear — which would make ITS OWN
        // `seam_rx.recv()` return `Err` immediately, firing ITS Timeout arm instantly instead of
        // honoring its own real Duration.
        TIMEOUT_SEAM.with(|cell| *cell.borrow_mut() = None);
    }
}

/// `rx.recv_timeout(timeout)`, unless a [`TimeoutSeam`] is installed on this thread — then races
/// the real drain result against the seam's own event instead of the real `Duration`, using two
/// threads that each feed the SAME local, single-purpose channel (the first message wins; the
/// other's is simply never read, harmless — an unbounded `mpsc::Sender::send` never blocks).
/// The `Result` half is the identical type `recv_timeout` itself returns, so every arm downstream
/// (`wait_on_channel`'s own match) is completely unaffected by which path produced it — this is
/// what makes the post-Timeout code path IDENTICAL either way, not merely similar.
///
/// Also returns `rx` back, wrapped in `Some`, WHEN POSSIBLE — the no-seam path never actually
/// consumes it (`recv_timeout` only borrows), so it costs nothing to hand back there; a caller
/// that needs to wait on the SAME channel again afterward (`wait_on_channel`'s own `Timeout` arm,
/// D6) can. The seam path genuinely consumes `rx` (moved into its own forwarding thread, which
/// must keep running past this function's own return to eventually deliver the real result) —
/// `None` there; that caller does the best it still safely can (kill first, reap right after,
/// same as always) without the extra wait, which is acceptable: the seam is test-only and rare,
/// and its own specific caller does not depend on that ordering for ITS OWN correctness.
fn recv_or_seam(
    rx: std::sync::mpsc::Receiver<DrainResult>,
    timeout: std::time::Duration,
) -> (
    Result<DrainResult, std::sync::mpsc::RecvTimeoutError>,
    Option<std::sync::mpsc::Receiver<DrainResult>>,
) {
    let Some(seam_rx) = TIMEOUT_SEAM.with(|cell| cell.borrow_mut().take()) else {
        let result = rx.recv_timeout(timeout);
        return (result, Some(rx));
    };
    enum Event {
        Drained(DrainResult),
        Disconnected,
        TimedOut,
    }
    let (etx, erx) = std::sync::mpsc::channel::<Event>();
    let drain_tx = etx.clone();
    std::thread::spawn(move || {
        let _ = drain_tx.send(match rx.recv() {
            Ok(result) => Event::Drained(result),
            Err(_) => Event::Disconnected,
        });
    });
    std::thread::spawn(move || {
        // Blocks until the test's own TimeoutSeam fires (or its Sender is simply dropped without
        // ever firing, e.g. the test itself panicked first — either way, `recv()` returning at
        // all is this thread's whole job).
        let _ = seam_rx.recv();
        let _ = etx.send(Event::TimedOut);
    });
    let result = match erx.recv() {
        Ok(Event::Drained(result)) => Ok(result),
        Ok(Event::Disconnected) => Err(std::sync::mpsc::RecvTimeoutError::Disconnected),
        Ok(Event::TimedOut) => Err(std::sync::mpsc::RecvTimeoutError::Timeout),
        // Unreachable in practice: both producer threads above always send exactly once before
        // exiting. Treated as Disconnected rather than unwrapped, so a future change to either
        // thread that somehow skips its send fails loudly as an ordinary panic downstream,
        // instead of via a bare `.expect()` here that would name neither producer.
        Err(_) => Err(std::sync::mpsc::RecvTimeoutError::Disconnected),
    };
    (result, None)
}

/// Kill `child` — by process GROUP if `own_process_group` (negative pid), else just its own pid —
/// WITHOUT reaping it. Killing the group while the leader is still an unreaped zombie (the OS has
/// not yet let its pid, and so its pgid, be recycled) reaches any grandchildren the leader may
/// have spawned into its own group before it hung — e.g. a three-level tree under one of #210's
/// cgroup-lane tests, run as root.
fn kill_only(child: &std::process::Child, own_process_group: bool) {
    let pid = child.id() as libc::pid_t;
    if own_process_group {
        // SAFETY: a plain signal to this process's own re-exec'd child's group; the child is still
        // unreaped (owned exclusively by the caller until it reaps), so its pid — and this pgid,
        // which the leader set to equal its own pid — cannot yet have been recycled.
        assert_eq!(
            unsafe { libc::kill(-pid, libc::SIGKILL) },
            0,
            "kill(-{pid}, SIGKILL) (own process group): {}",
            std::io::Error::last_os_error()
        );
    } else {
        // SAFETY: a plain signal to this process's own re-exec'd child, still unreaped, same
        // reasoning as above; a failure (e.g. ESRCH, if it raced its own natural exit) is ignored
        // the same way `Child::kill()`'s own discarded `Result` already was.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
    }
}

/// [`kill_only`] then reap, returning the resulting `ExitStatus`. Safe to call whenever nothing
/// ELSE still needs `child`'s own pid to stay meaningful — in particular, NOT while a background
/// thread might still be about to `waitid` on it non-reapingly (see [`wait_on_channel`]'s own
/// `Timeout` arm, the one caller that cannot use this directly).
pub(crate) fn kill_and_reap(mut child: std::process::Child, own_process_group: bool) -> std::process::ExitStatus {
    kill_only(&child, own_process_group);
    child.wait().expect("reap the child after killing it")
}

/// The post-drain half of [`wait_bounded`]: given `child` and a channel some drain mechanism will
/// eventually send a [`DrainResult`] to, wait bounded by `timeout` and turn every outcome into
/// either an `Output` or a loud, kill-and-reap-first panic. Split out from `wait_bounded` as a
/// seam: a test can drive this directly with a synthetic channel, to prove the `Timeout` and
/// `Disconnected` arms without needing a real drain thread to fail.
///
/// `own_process_group`: see [`kill_and_reap`]. The caller — not this function — is responsible for
/// having put `child` in its own group before spawning it, if it passes `true` here.
pub(crate) fn wait_on_channel(
    child: std::process::Child,
    timeout: std::time::Duration,
    rx: std::sync::mpsc::Receiver<DrainResult>,
    own_process_group: bool,
) -> std::process::Output {
    let pid = child.id();
    let (outcome, remaining_rx) = recv_or_seam(rx, timeout);
    match outcome {
        Ok(Ok((stdout, stderr))) => {
            let mut child = child;
            let status = child.wait().expect("reap the child, already confirmed exited");
            std::process::Output { status, stdout, stderr }
        }
        Ok(Err(msg)) => {
            let status = kill_and_reap(child, own_process_group);
            panic!(
                "waiting for child pid {pid} failed: {msg}; killed and reaped, exit status \
                 {status:?} (signal {:?})",
                std::os::unix::process::ExitStatusExt::signal(&status)
            );
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            let mut child = child;
            // Signal only — NOT `kill_and_reap` — because the drain thread (see `wait_bounded`)
            // may still be mid-flight: reading `child`'s stdout/stderr pipes, about to call its
            // own non-reaping `waitid(P_PID, pid, WNOWAIT)`. Reaping HERE, before that call runs,
            // would let the OS recycle `pid` first, so that `waitid` could then target an
            // entirely different, unrelated process born with the same number in between
            // (principle 4) — worse, one that is still genuinely alive would make that call BLOCK
            // on IT, not merely misreport. The kill below makes this resolve promptly regardless:
            // it makes the real child exit, which unblocks whatever the drain thread was still
            // doing and lets it reach its own `waitid` and send its result. `remaining_rx` is
            // `None` only via a `TimeoutSeam` (test-only, rare) — that caller does not depend on
            // this exact ordering for its own correctness; see `recv_or_seam`'s own doc.
            kill_only(&child, own_process_group);
            if let Some(remaining_rx) = remaining_rx {
                let _ = remaining_rx.recv();
            }
            let status = child.wait().expect("reap the child after killing it");
            panic!(
                "child pid {pid} did not exit within {timeout:?} — it hung instead of exiting, \
                 which is itself a regression somewhere upstream of this wait. Killed it and \
                 reaped exit status {status:?} (signal {:?}).",
                std::os::unix::process::ExitStatusExt::signal(&status)
            );
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            // The drain thread died (e.g. its own panic) without sending a result: kill and reap
            // exactly like the other failure arms, so the child is never left running unreaped.
            let status = kill_and_reap(child, own_process_group);
            panic!(
                "child pid {pid}'s wait thread died without sending a result; killed and reaped, \
                 exit status {status:?} (signal {:?}).",
                std::os::unix::process::ExitStatusExt::signal(&status)
            );
        }
    }
}

/// Wait for `child` to exit, bounded by `timeout` — killing it and failing loudly if it does not,
/// rather than blocking forever. A failure bound for a child that may hang forever (e.g. a
/// self-deadlock), not synchronization: the wait itself is a blocking read on another thread, woken
/// the instant the child exits.
///
/// `child` stays owned by the caller's thread and is reaped only there ([`wait_on_channel`]). The
/// background thread gets only the pipes, plus a non-reaping `waitid(WEXITED | WNOWAIT)` to learn
/// of exit; an unreaped child's pid cannot be recycled, so `kill`/`wait` on timeout or drain
/// failure are race-free regardless of which branch runs.
///
/// Drains stdout and stderr CONCURRENTLY, each on its own thread, not one after the other: a child
/// that writes more than one pipe buffer to stderr while producing little or no stdout would
/// otherwise deadlock this function, since reading stdout to EOF blocks until the child exits while
/// the child is itself blocked writing to the undrained stderr pipe.
///
/// `own_process_group`: see [`kill_and_reap`].
pub(crate) fn wait_bounded(
    mut child: std::process::Child,
    timeout: std::time::Duration,
    own_process_group: bool,
) -> std::process::Output {
    let pid = child.id();
    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::io::Read;
        let stdout_thread = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let result = stdout_pipe.take().map_or(Ok(0), |mut p| p.read_to_end(&mut buf));
            (buf, result)
        });
        let mut stderr = Vec::new();
        let stderr_result = stderr_pipe.take().map_or(Ok(0), |mut p| p.read_to_end(&mut stderr));
        let (stdout, stdout_result) = stdout_thread.join().expect("join the stdout-draining thread");
        // Surface a read failure instead of returning silently-truncated output, which the
        // caller's assertions would otherwise run against as if it were complete.
        if let Err(e) = stdout_result {
            let _ = tx.send(Err(format!("reading the child's stdout failed: {e}")));
            return;
        }
        if let Err(e) = stderr_result {
            let _ = tx.send(Err(format!("reading the child's stderr failed: {e}")));
            return;
        }
        // Confirm the child has exited WITHOUT reaping it (`WNOWAIT`) — reaping stays on the
        // caller's thread below, the only place allowed to touch the `Child` it still owns.
        let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
        loop {
            // SAFETY: `si` is a valid, correctly-sized out-param; `pid` is our own unreaped child.
            let rc = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut si, libc::WEXITED | libc::WNOWAIT) };
            if rc == 0 {
                break;
            }
            // Any other error (e.g. already reaped after a timeout): nothing left to confirm.
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                break;
            }
        }
        let _ = tx.send(Ok((stdout, stderr)));
    });
    wait_on_channel(child, timeout, rx, own_process_group)
}

/// Spawn a fresh copy of this test binary directly against `fixture` — WITHOUT `alone()`'s own
/// isolated shape (`COSCA_TEST_ALONE` per `alone_env`, argv NOT [`ALONE_ARGS`]) — with `extra_env`
/// also set, and return its captured output. Shared by every prover of a gate that must reject
/// exactly this non-isolated shape, not the isolated one every other caller uses (both in this
/// file's own tests and in #210's `spawn_with_std_slots_closed` provers).
pub fn spawn_without_alone_shape(
    fixture: &str,
    alone_env: Option<&str>,
    extra_env: &[(&str, &str)],
) -> std::process::Output {
    let child = {
        let _guard = super::test_spawn_lock();
        let mut cmd = std::process::Command::new(std::env::current_exe().expect("this test binary"));
        cmd.args([fixture, "--exact", "--nocapture", "--test-threads=1"]);
        match alone_env {
            Some(name) => {
                cmd.env("COSCA_TEST_ALONE", name);
            }
            None => {
                cmd.env_remove("COSCA_TEST_ALONE");
            }
        }
        for &(k, v) in extra_env {
            cmd.env(k, v);
        }
        cmd.stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn the probe")
    };
    wait_bounded(child, PROBE_TIMEOUT, false)
}

#[cfg(test)]
mod alone_marker_tests {
    use super::{alone_marker_matches, ALONE_ARGS};

    fn genuine_argv(name: &str) -> Vec<String> {
        std::iter::once(name.to_string())
            .chain(ALONE_ARGS.iter().map(|s| s.to_string()))
            .collect()
    }

    #[test]
    fn the_genuine_re_exec_shape_matches() {
        assert!(alone_marker_matches(Some("some_test"), &genuine_argv("some_test")));
    }

    #[test]
    fn no_env_value_never_matches() {
        assert!(!alone_marker_matches(None, &genuine_argv("some_test")));
    }

    #[test]
    fn an_inherited_env_value_with_the_ordinary_suites_own_argv_does_not_match() {
        // The exact corruption measured: `COSCA_TEST_ALONE` set (e.g. leaked from an outer shell
        // or re-exec) to some real test's name, but THIS process's own argv is whatever an
        // ordinary `cargo test` run passes — never the isolated one-test-exact shape.
        assert!(!alone_marker_matches(Some("some_test"), &[]));
        assert!(!alone_marker_matches(Some("some_test"), &["some_test".to_string()]));
    }

    #[test]
    fn a_name_mismatch_does_not_match_even_with_the_right_shape() {
        let mut argv = genuine_argv("some_test");
        argv[0] = "other_test".to_string();
        assert!(!alone_marker_matches(Some("some_test"), &argv));
    }

    #[test]
    fn a_trailing_extra_argument_does_not_match() {
        let mut argv = genuine_argv("some_test");
        argv.push("--extra".to_string());
        assert!(!alone_marker_matches(Some("some_test"), &argv));
    }
}
