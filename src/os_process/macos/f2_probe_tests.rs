//! F2 measurement (throwaway, never merged): does `MacChild::exited`, the never-drained exit kqueue,
//! wake for (a) a child reaped by someone else, (b) a child whose zombie launchd holds?
//!
//! Each test arms a `MacChild` while the child runs, parks a waiter thread in
//! `drive::exited_until` (the kqueue wait `await_reapable` is compared against), drives the case
//! on the test thread, and prints a timeline with `eprintln!`. Nothing is asserted on the result:
//! the waiter's own deadline is the failure bound surfaced to a human.

use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::MacChild;
use crate::identity::{uniq_info, ReadPurpose, UniqRead};
use crate::os_process::drive::exited_until;
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

fn banner(label: &str) {
    eprintln!("{label}: sw_vers = {:?}", run("sw_vers", &[]));
    eprintln!("{label}: uname -m = {:?}", run("uname", &["-m"]));
}

/// One zero-timeout look at the exit kqueue.
fn look(mac: &MacChild) -> &'static str {
    match mac.exited() {
        Ok(Exit::Exited) => "Exited",
        Ok(Exit::Running(_)) => "Running",
        Err(_) => "Err",
    }
}

fn ms(t0: Instant, t: Instant) -> u128 {
    t.duration_since(t0).as_millis()
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

fn report(label: &str, t0: Instant, woke: &Woke) {
    match &woke.result {
        Ok(true) => eprintln!("{label}: woke after {} ms (exited_until = true)", ms(t0, woke.at)),
        Ok(false) => eprintln!("{label}: no wake within {} s", WAKE_BOUND.as_secs()),
        Err(e) => eprintln!("{label}: wait failed after {} ms: {e}", ms(t0, woke.at)),
    }
}

/// (a) The child exits and someone else (the test, by `waitpid`) reaps it.
#[skuld::test]
fn f2_probe_reaped_elsewhere() {
    banner("F2(a)");
    let mut cmd = crate::test_child::held_std_killable_blocker();
    let mut child = crate::test_spawn::spawn(&mut cmd).expect("spawn the blocker");
    let stdin = child.stdin.take().expect("piped stdin");
    let pid = child.id();
    let mac = MacChild::new(pid, unique_of(pid)).expect("arm the child");
    eprintln!("F2(a): look while running = {}", look(&mac));

    let t0 = Instant::now();
    std::thread::scope(|s| {
        let rx = park_waiter(s, &mac);
        drop(stdin);
        wait_until_zombie(pid);
        let t_zombie = Instant::now();
        eprintln!("F2(a): zombie at {} ms, look = {}", ms(t0, t_zombie), look(&mac));
        reap_behind(pid);
        let t_reaped = Instant::now();
        eprintln!(
            "F2(a): reaped by waitpid at {} ms, look = {}",
            ms(t0, t_reaped),
            look(&mac)
        );
        let woke = rx.recv().expect("the waiter reports");
        report("F2(a)", t0, &woke);
    });
    eprintln!("F2(a): final look = {}", look(&mac));
    drop(child);
}

/// (b) A tracer holds the child's zombie, then dies; XNU gives the zombie to launchd.
#[skuld::test]
fn f2_probe_launchd_held_zombie(#[fixture(tracer_group)] _group: &Group) {
    banner("F2(b)");
    let (mut tracee, _) = tracer::spawn_tracee(tracer::Tracee::Plain);
    let stdin = tracee.stdin().expect("the tracee's stdin is piped");
    let pid = tracee.id().pid();
    let mac = MacChild::new(pid, unique_of(pid)).expect("arm the child");
    let mut helper = tracer::start(Mode::Hold).attach(&mut tracee);
    assert_eq!(helper.recv(), Report::Attached);
    eprintln!("F2(b): look while traced and running = {}", look(&mac));

    let t0 = Instant::now();
    std::thread::scope(|s| {
        let rx = park_waiter(s, &mac);
        drop(stdin);
        assert_eq!(helper.recv(), Report::Exited);
        let t_exit = Instant::now();
        eprintln!(
            "F2(b): zombie on the tracer's list at {} ms, look = {}, ppid = {:?}",
            ms(t0, t_exit),
            look(&mac),
            run("ps", &["-o", "ppid=", "-p", &pid.to_string()])
        );

        // SAFETY: the helper is this test's own unreaped child.
        let sent = unsafe { libc::kill(helper.helper_pid() as libc::pid_t, libc::SIGKILL) };
        assert_eq!(sent, 0, "{}", std::io::Error::last_os_error());
        let t_killed = Instant::now();
        eprintln!("F2(b): tracer killed at {} ms", ms(t0, t_killed));

        // Until the zombie reads as launchd's (ppid 1), or the bound passes.
        let launchd_at = loop {
            let ppid = run("ps", &["-o", "ppid=", "-p", &pid.to_string()]);
            if ppid == "1" {
                break Some(Instant::now());
            }
            if t_killed.elapsed() > WAKE_BOUND {
                eprintln!(
                    "F2(b): the zombie never read ppid 1 within {} s (last ppid {ppid:?})",
                    WAKE_BOUND.as_secs()
                );
                break None;
            }
            std::thread::yield_now();
        };
        if let Some(t) = launchd_at {
            eprintln!(
                "F2(b): launchd holds the zombie at {} ms, look = {}",
                ms(t0, t),
                look(&mac)
            );
        }
        let woke = rx.recv().expect("the waiter reports");
        report("F2(b)", t0, &woke);
    });
    eprintln!("F2(b): final look = {}", look(&mac));
    // The killed helper fails `Session`'s clean-exit check, so its teardown is skipped.
    std::mem::forget(helper);
    drop(tracee);
}
