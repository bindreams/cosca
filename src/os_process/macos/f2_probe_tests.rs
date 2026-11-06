//! F2 measurement (throwaway, never merged): does `MacChild::exited`, the never-drained exit kqueue,
//! wake for (a) a child reaped by someone else, (b) a child whose tracer died after the child's exit,
//! (c) a child whose tracer died while the child was still exiting (the one route the code names for
//! launchd to hold a zombie of a child this process forked), and (d) the same as (c) when the tracer
//! attaches only after a wait on the child is already blocked, for a `MacChild` (d) and for a
//! `MacProcess` opened by identity (d')?
//!
//! Each test arms a `MacChild` while the child runs, parks a waiter thread in
//! `drive::exited_until` (the kqueue wait `await_reapable` is compared against), drives the case
//! on the test thread, and records a timeline. Each test ends with `panic!("{timeline}")` so the
//! CI log shows it (nextest's ci profile hides a passing test's output). Nothing else is asserted
//! on the result: the waiter's own deadline is the failure bound surfaced to a human.

use std::fmt::Write as _;
use std::io::Write as _;
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd as _;
use std::os::unix::process::CommandExt as _;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::MacChild;
use crate::error::Error;
use crate::identity::{uniq_info, ProcessId, ReadPurpose, UniqRead};
use crate::os_process::drive::{exited_held, exited_until};
use crate::os_process::{Exit, OsProcess};
use crate::test_child::reaped_elsewhere::reap_behind;
use crate::test_child::wait_until_zombie;
use crate::test_groups::{tracer_group, Group};
use crate::test_support::tracer::{self, Mode, Report};

/// How long the waiter waits before the probe reports "no wake". A bound for a human, not proof.
const WAKE_BOUND: Duration = Duration::from_secs(30);

fn unique_of(pid: u32) -> u64 {
    match uniq_info(pid, ReadPurpose::Adopt) {
        UniqRead::Found(info) => info.unique_id,
        other => panic!("the unique id of {pid}: {other:?}"),
    }
}

/// Stdout of `program args`, trimmed.
fn run(program: &str, args: &[&str]) -> String {
    let mut cmd = std::process::Command::new(program);
    cmd.args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    let out = crate::test_spawn::spawn(&mut cmd)
        .unwrap_or_else(|e| panic!("spawn {program}: {e}"))
        .wait_with_output()
        .unwrap_or_else(|e| panic!("wait {program}: {e}"));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Appends one line to the timeline (and echoes it to stderr).
macro_rules! note {
    ($tl:expr, $($arg:tt)*) => {{
        let line = format!($($arg)*);
        eprintln!("{line}");
        write!($tl, "\n{line}").unwrap();
    }};
}

fn banner(label: &str, tl: &mut String) {
    note!(tl, "{label}: sw_vers = {:?}", run("sw_vers", &[]));
    note!(tl, "{label}: uname -m = {:?}", run("uname", &["-m"]));
}

/// One zero-timeout look at the exit kqueue.
fn look(mac: &MacChild) -> &'static str {
    look_os(mac)
}

/// [`look`] through the [`OsProcess`] trait.
fn look_os(process: &dyn OsProcess) -> &'static str {
    match process.exited() {
        Ok(Exit::Exited) => "Exited",
        Ok(Exit::Running(_)) => "Running",
        Err(_) => "Err",
    }
}

fn ms(t0: Instant, t: Instant) -> u128 {
    t.duration_since(t0).as_millis()
}

/// `ps`'s state flags and parent pid of `pid`, whitespace-normalised ("" once no process has it).
fn ps_state(pid: u32) -> String {
    let out = run("ps", &["-o", "stat=,ppid=", "-p", &pid.to_string()]);
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The parent pid in a [`ps_state`] sample.
fn ppid_of(sample: &str) -> Option<&str> {
    let mut words = sample.split_whitespace();
    words.next()?;
    words.next()
}

/// Who holds `pid` according to a [`ps_state`] sample, once it is neither the dead tracer nor
/// unreadable: `None` while `ps` still names the tracer.
fn holder_verdict(sample: &str, me: u32, tracer: u32) -> Option<String> {
    if sample.is_empty() {
        return Some("no process has the pid (reaped by someone)".to_string());
    }
    let ppid = ppid_of(sample)?;
    if ppid == tracer.to_string() {
        None
    } else if ppid == me.to_string() {
        Some(format!("ppid {ppid} = the TEST process (the real parent got it back)"))
    } else if ppid == "1" {
        Some("ppid 1 = LAUNCHD holds it".to_string())
    } else {
        Some(format!("ppid {ppid} = someone else"))
    }
}

/// Samples `ps` for `pid`, noting each change, until `done` answers or [`WAKE_BOUND`] passes. The
/// bound is the failure bound surfaced to a human; the loop re-checks the real condition.
fn watch(
    tl: &mut String,
    label: &str,
    t0: Instant,
    pid: u32,
    mut done: impl FnMut(&str) -> Option<String>,
) -> Option<String> {
    let from = Instant::now();
    let mut last: Option<String> = None;
    loop {
        let sample = ps_state(pid);
        if last.as_deref() != Some(sample.as_str()) {
            note!(
                tl,
                "{label}: at {} ms, ps stat+ppid of {pid} = {sample:?}",
                ms(t0, Instant::now())
            );
            last = Some(sample.clone());
        }
        if let Some(verdict) = done(&sample) {
            note!(tl, "{label}: at {} ms, verdict: {verdict}", ms(t0, Instant::now()));
            return Some(verdict);
        }
        if from.elapsed() > WAKE_BOUND {
            note!(tl, "{label}: no verdict within {} s", WAKE_BOUND.as_secs());
            return None;
        }
        std::thread::yield_now();
    }
}

/// The waiter's verdict: how it ended, and when.
struct Woke {
    result: Result<bool, String>,
    at: Instant,
}

/// Parks a waiter in `exited_until` on `mac` and returns the channel its verdict arrives on.
fn park_waiter<'s>(scope: &'s std::thread::Scope<'s, '_>, mac: &'s MacChild) -> mpsc::Receiver<Woke> {
    let (tx, rx) = mpsc::channel();
    scope.spawn(move || {
        let result = exited_until(mac, Some(Instant::now() + WAKE_BOUND)).map_err(|e| e.to_string());
        _ = tx.send(Woke {
            result,
            at: Instant::now(),
        });
    });
    rx
}

fn report(label: &str, tl: &mut String, t0: Instant, woke: &Woke) {
    match &woke.result {
        Ok(true) => note!(tl, "{label}: woke after {} ms (exited_until = true)", ms(t0, woke.at)),
        Ok(false) => note!(tl, "{label}: no wake within {} s", WAKE_BOUND.as_secs()),
        Err(e) => note!(tl, "{label}: wait failed after {} ms: {e}", ms(t0, woke.at)),
    }
}

/// (a) The child exits and someone else (the test, by `waitpid`) reaps it.
#[skuld::test]
fn f2_probe_reaped_elsewhere() {
    let mut tl = String::from("F2 TIMELINE:");
    banner("F2(a)", &mut tl);
    let mut cmd = crate::test_child::held_std_killable_blocker();
    let mut child = crate::test_spawn::spawn(&mut cmd).expect("spawn the blocker");
    let stdin = child.stdin.take().expect("piped stdin");
    let pid = child.id();
    let mac = MacChild::new(pid, unique_of(pid)).expect("arm the child");
    note!(tl, "F2(a): look while running = {}", look(&mac));

    let t0 = Instant::now();
    std::thread::scope(|s| {
        let rx = park_waiter(s, &mac);
        drop(stdin);
        wait_until_zombie(pid);
        let t_zombie = Instant::now();
        note!(tl, "F2(a): zombie at {} ms, look = {}", ms(t0, t_zombie), look(&mac));
        reap_behind(pid);
        let t_reaped = Instant::now();
        note!(
            tl,
            "F2(a): reaped by waitpid at {} ms, look = {}",
            ms(t0, t_reaped),
            look(&mac)
        );
        let woke = rx.recv().expect("the waiter reports");
        report("F2(a)", &mut tl, t0, &woke);
    });
    note!(tl, "F2(a): final look = {}", look(&mac));
    drop(child);
    panic!("{tl}");
}

/// (b) A tracer holds the child's zombie, then dies. Where does the zombie go: back to the test (its
/// real parent), or to launchd? The timeline prints the test's own pid next to every ppid it reads.
#[skuld::test]
fn f2_probe_launchd_held_zombie(#[fixture(tracer_group)] _group: &Group) {
    let mut tl = String::from("F2 TIMELINE:");
    banner("F2(b)", &mut tl);
    let me = std::process::id();
    let (mut tracee, _) = tracer::spawn_tracee(tracer::Tracee::Plain);
    let stdin = tracee.stdin().expect("the tracee's stdin is piped");
    let pid = tracee.id().pid();
    let mac = MacChild::new(pid, unique_of(pid)).expect("arm the child");
    let mut helper = tracer::start(Mode::Hold).attach(&mut tracee);
    assert_eq!(helper.recv(), Report::Attached);
    let tracer_pid = helper.helper_pid();
    note!(
        tl,
        "F2(b): test pid = {me}, tracer helper pid = {tracer_pid}, tracee pid = {pid}"
    );
    note!(tl, "F2(b): look while traced and running = {}", look(&mac));

    let t0 = Instant::now();
    std::thread::scope(|s| {
        let rx = park_waiter(s, &mac);
        drop(stdin);
        assert_eq!(helper.recv(), Report::Exited);
        let t_exit = Instant::now();
        note!(
            tl,
            "F2(b): zombie on the tracer's list at {} ms, look = {}, ps = {:?}",
            ms(t0, t_exit),
            look(&mac),
            ps_state(pid)
        );

        // SAFETY: the helper is this test's own unreaped child.
        let sent = unsafe { libc::kill(tracer_pid as libc::pid_t, libc::SIGKILL) };
        assert_eq!(sent, 0, "{}", std::io::Error::last_os_error());
        note!(tl, "F2(b): tracer killed at {} ms", ms(t0, Instant::now()));

        // Until ps names a holder other than the dead tracer, or the bound passes.
        watch(&mut tl, "F2(b)", t0, pid, |sample| {
            holder_verdict(sample, me, tracer_pid)
        });
        let woke = rx.recv().expect("the waiter reports");
        report("F2(b)", &mut tl, t0, &woke);
    });
    note!(tl, "F2(b): final look = {}, ps = {:?}", look(&mac), ps_state(pid));
    // The killed helper fails `Session`'s clean-exit check, so its teardown is skipped.
    std::mem::forget(helper);
    drop(tracee);
    panic!("{tl}");
}

/// A loopback TCP pair `(held, peer)`: `held`'s send queue is full, the peer never reads, and `held`
/// lingers 60 s on close. Whoever closes the last descriptor of `held` blocks in `close` until the
/// peer goes away, because the FIN cannot be sent behind the queued data. Blocking mode, as
/// `SS_NBIO` makes `close` skip the linger.
fn lingering_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback listener");
    let held = TcpStream::connect(listener.local_addr().expect("listener address")).expect("connect");
    let (peer, _) = listener.accept().expect("accept");
    held.set_nonblocking(true).expect("set nonblocking");
    let chunk = [0u8; 65536];
    loop {
        match (&held).write(&chunk) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("fill the send queue: {e}"),
        }
    }
    held.set_nonblocking(false).expect("set blocking");
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 60,
    };
    // SAFETY: `linger` is a valid `struct linger` of the length given, and the descriptor is open.
    let set = unsafe {
        libc::setsockopt(
            held.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER_SEC,
            (&raw const linger).cast(),
            size_of::<libc::linger>() as libc::socklen_t,
        )
    };
    assert_eq!(set, 0, "SO_LINGER_SEC: {}", std::io::Error::last_os_error());
    (held, peer)
}

/// A child whose exit is stuck closing a lingering socket (see [`lingering_pair`]): `(child, stdin,
/// peer)`. The child exits when `stdin` is dropped, then hangs, not yet a zombie, until `peer` is
/// dropped.
fn spawn_lingering_exit() -> (std::process::Child, std::process::ChildStdin, TcpStream) {
    let (held, peer) = lingering_pair();
    let mut cmd = crate::test_child::held_std_killable_blocker();
    let fd = held.as_raw_fd();
    // SAFETY: between fork and exec, only `fcntl`, which is async-signal-safe and allocates nothing.
    unsafe {
        cmd.pre_exec(move || {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = crate::test_spawn::spawn(&mut cmd).expect("spawn the tracee");
    // The child is now the only holder of `held`, so its exit is the last close.
    drop(held);
    let stdin = child.stdin.take().expect("piped stdin");
    (child, stdin, peer)
}

/// (c) The tracee is still EXITING (its exit is stuck closing a lingering socket, so it is not yet a
/// zombie) when its tracer dies. The code (`wait::macos::tracer_watch`) says XNU then gives it to
/// launchd with `p_oppid` still the test, and withholds its `NOTE_EXIT` from the test. Measured:
/// the state `ps` shows before and after, who holds it, whether the exit kqueue wakes.
#[skuld::test]
fn f2_probe_tracee_exiting_when_tracer_dies(#[fixture(tracer_group)] _group: &Group) {
    let mut tl = String::from("F2 TIMELINE:");
    banner("F2(c)", &mut tl);
    let me = std::process::id();
    let (child, stdin, peer) = spawn_lingering_exit();
    let pid = child.id();
    let mac = MacChild::new(pid, unique_of(pid)).expect("arm the child");
    let mut helper = tracer::start(Mode::Hold).attach_unheld(pid);
    assert_eq!(helper.recv(), Report::Attached);
    let tracer_pid = helper.helper_pid();
    note!(
        tl,
        "F2(c): test pid = {me}, tracer helper pid = {tracer_pid}, tracee pid = {pid}"
    );
    note!(tl, "F2(c): look while traced and running = {}", look(&mac));

    let t0 = Instant::now();
    let mut peer = Some(peer);
    std::thread::scope(|s| {
        let rx = park_waiter(s, &mac);
        drop(stdin);
        // Until the tracee reads as exiting (E) or already a zombie (Z): the exit has begun.
        let began = watch(&mut tl, "F2(c) exit", t0, pid, |sample| {
            let stat = sample.split_whitespace().next().unwrap_or("");
            (stat.contains('E') || stat.contains('Z')).then(|| format!("stat {stat:?}: the exit has begun"))
        });
        note!(
            tl,
            "F2(c): exit begun = {}, look = {}, ps = {:?}",
            began.is_some(),
            look(&mac),
            ps_state(pid)
        );

        // SAFETY: the helper is this test's own unreaped child.
        let sent = unsafe { libc::kill(tracer_pid as libc::pid_t, libc::SIGKILL) };
        assert_eq!(sent, 0, "{}", std::io::Error::last_os_error());
        note!(tl, "F2(c): tracer killed at {} ms", ms(t0, Instant::now()));

        // Until ps names a holder other than the dead tracer, or the bound passes.
        watch(&mut tl, "F2(c) holder", t0, pid, |sample| {
            holder_verdict(sample, me, tracer_pid)
        });
        note!(tl, "F2(c): look after the tracer's death = {}", look(&mac));

        // Let the exit finish: the peer goes away with unread data, which resets the connection.
        drop(peer.take());
        note!(tl, "F2(c): peer closed at {} ms", ms(t0, Instant::now()));
        // Until no process has the pid (launchd reaped it), or the zombie reads as the test's.
        watch(&mut tl, "F2(c) end", t0, pid, |sample| {
            if sample.is_empty() {
                return Some("no process has the pid (reaped by someone)".to_string());
            }
            let stat = sample.split_whitespace().next().unwrap_or("");
            (stat.contains('Z') && ppid_of(sample) == Some(me.to_string().as_str()))
                .then(|| "a zombie the test holds".to_string())
        });
        let woke = rx.recv().expect("the waiter reports");
        report("F2(c)", &mut tl, t0, &woke);
    });
    note!(tl, "F2(c): final look = {}, ps = {:?}", look(&mac), ps_state(pid));
    drop(peer);
    // The killed helper fails `Session`'s clean-exit check, so its teardown is skipped.
    std::mem::forget(helper);
    drop(child);
    panic!("{tl}");
}

/// How (d) and (d') block on the process: the real wait, bounded by [`WAKE_BOUND`] as the failure
/// report. `OwnedChild::exited_by` is `exited_until` over its `OsProcess`, so (d) calls that.
type WaitFn = fn(&dyn OsProcess) -> Result<bool, Error>;

/// Drives case (d) on `process`, a look at the child `pid`: `stdin` ends the child, whose exit then
/// hangs until `peer` is dropped. A waiter blocks in `wait`; only once its first look has run
/// (`block_probe::on_blocking` fires just before its blocking `poll`) does a tracer attach; then the
/// child begins to exit, and the tracer is killed while it is mid-exit. Ends in `panic!` with the
/// timeline.
fn late_attach_case(
    label: &'static str,
    mut tl: String,
    process: &dyn OsProcess,
    wait: WaitFn,
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    peer: TcpStream,
) -> ! {
    let me = std::process::id();
    let pid = child.id();
    let pending = tracer::start(Mode::Hold);
    note!(tl, "{label}: test pid = {me}, tracee pid = {pid}, no tracer yet");
    note!(
        tl,
        "{label}: look before the wait = {}, ps = {:?}",
        look_os(process),
        ps_state(pid)
    );

    let t0 = Instant::now();
    let mut peer = Some(peer);
    let mut helper_slot = None;
    std::thread::scope(|s| {
        let (blocked_tx, blocked_rx) = mpsc::channel();
        let (tx, rx) = mpsc::channel();
        s.spawn(move || {
            // Fires on this thread, after the wait's first look and just before its blocking `poll`.
            // If the wait returns without blocking, the hook never runs and the channel closes.
            let _armed = crate::wait::block_probe::on_blocking(move || _ = blocked_tx.send(()));
            let result = wait(process).map_err(|e| e.to_string());
            _ = tx.send(Woke {
                result,
                at: Instant::now(),
            });
        });
        match blocked_rx.recv() {
            Ok(()) => note!(
                tl,
                "{label}: the wait is about to block at {} ms, look = {}, ps = {:?}",
                ms(t0, Instant::now()),
                look_os(process),
                ps_state(pid)
            ),
            Err(_) => note!(
                tl,
                "{label}: the wait returned without blocking, at {} ms",
                ms(t0, Instant::now())
            ),
        }

        let mut helper = pending.attach_unheld(pid);
        assert_eq!(helper.recv(), Report::Attached);
        let tracer_pid = helper.helper_pid();
        note!(
            tl,
            "{label}: tracer helper pid = {tracer_pid} attached at {} ms, look = {}, ps = {:?}",
            ms(t0, Instant::now()),
            look_os(process),
            ps_state(pid)
        );
        helper_slot = Some(helper);

        drop(stdin);
        // Until the tracee reads as exiting (E) or already a zombie (Z): the exit has begun.
        let began = watch(&mut tl, &format!("{label} exit"), t0, pid, |sample| {
            let stat = sample.split_whitespace().next().unwrap_or("");
            (stat.contains('E') || stat.contains('Z')).then(|| format!("stat {stat:?}: the exit has begun"))
        });
        note!(
            tl,
            "{label}: exit begun = {}, look = {}, ps = {:?}",
            began.is_some(),
            look_os(process),
            ps_state(pid)
        );

        // SAFETY: the helper is this test's own unreaped child.
        let sent = unsafe { libc::kill(tracer_pid as libc::pid_t, libc::SIGKILL) };
        assert_eq!(sent, 0, "{}", std::io::Error::last_os_error());
        note!(tl, "{label}: tracer killed at {} ms", ms(t0, Instant::now()));

        // Until ps names a holder other than the dead tracer, or the bound passes.
        watch(&mut tl, &format!("{label} holder"), t0, pid, |sample| {
            holder_verdict(sample, me, tracer_pid)
        });
        note!(tl, "{label}: look after the tracer's death = {}", look_os(process));

        // Let the exit finish: the peer goes away with unread data, which resets the connection.
        drop(peer.take());
        note!(tl, "{label}: peer closed at {} ms", ms(t0, Instant::now()));
        // Until no process has the pid (launchd reaped it), or the zombie reads as the test's.
        watch(&mut tl, &format!("{label} end"), t0, pid, |sample| {
            if sample.is_empty() {
                return Some("no process has the pid (reaped by someone)".to_string());
            }
            let stat = sample.split_whitespace().next().unwrap_or("");
            (stat.contains('Z') && ppid_of(sample) == Some(me.to_string().as_str()))
                .then(|| "a zombie the test holds".to_string())
        });
        let woke = rx.recv().expect("the waiter reports");
        report(label, &mut tl, t0, &woke);
    });
    note!(
        tl,
        "{label}: final look = {}, ps = {:?}",
        look_os(process),
        ps_state(pid)
    );
    drop(peer);
    // The killed helper fails `Session`'s clean-exit check, so its teardown is skipped.
    std::mem::forget(helper_slot);
    drop(child);
    panic!("{tl}");
}

/// (d) A tracer attaches to the child only after a wait on its `MacChild` has blocked, then dies
/// while the child is mid-exit. The deputy deduces a hang (XNU withholds the `NOTE_EXIT`, and the
/// exit kqueue is not armed for the attach); this measures it.
#[skuld::test]
fn f2_probe_attach_after_wait_started(#[fixture(tracer_group)] _group: &Group) {
    let mut tl = String::from("F2 TIMELINE:");
    banner("F2(d)", &mut tl);
    let (child, stdin, peer) = spawn_lingering_exit();
    let pid = child.id();
    let mac = MacChild::new(pid, unique_of(pid)).expect("arm the child");
    late_attach_case(
        "F2(d)",
        tl,
        &mac,
        |p| exited_until(p, Some(Instant::now() + WAKE_BOUND)),
        child,
        stdin,
        peer,
    )
}

/// (d') The same against a `MacProcess` opened by identity (`os_process::open`), waited on through
/// `drive::exited_held`. The test is still the child's parent, so this is not a non-parent look.
#[skuld::test]
fn f2_probe_attach_after_wait_started_held(#[fixture(tracer_group)] _group: &Group) {
    let mut tl = String::from("F2 TIMELINE:");
    banner("F2(d')", &mut tl);
    let (child, stdin, peer) = spawn_lingering_exit();
    let pid = child.id();
    let id = ProcessId::of(pid).found().expect("identity of the live child");
    let process = crate::os_process::open(id)
        .expect("open the child by identity")
        .expect("the child is alive");
    late_attach_case(
        "F2(d')",
        tl,
        &*process,
        |p| exited_held(p, Some(WAKE_BOUND)),
        child,
        stdin,
        peer,
    )
}
