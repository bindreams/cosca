//! Windows: `Command::spawn_suspended`, measured from outside the crate.
//!
//! The lib's own tests (`src/child/suspended_tests.rs`) hold everything that needs a fault seam.
//! What lives here needs real helper processes: a parent that dies while its child is frozen, and
//! a resumed child that must behave like an ordinary one.
//!
//! Every child is windowless (`no_window`), so no test opens a console on a developer's desktop.
//! Each spawn runs on both sync backends: argv (std) and `executable()` (raw `CreateProcessW`).
//!
//! The death tests are named `death_watch_*`: their waits are on a process handle with no timeout
//! of their own, and `.config/nextest.toml` bounds that name pattern, so a guard that stops
//! working fails the test instead of hanging the job.

#[cfg(windows)]
use std::io::Write;
#[cfg(windows)]
use std::net::TcpStream;

#[cfg(windows)]
#[path = "common/mod.rs"]
mod common;

#[cfg(windows)]
use common::{accept_or_die, bind_report, read_report_line, report_field, silence, testbin, ACK_ENV};

#[cfg(windows)]
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
#[cfg(windows)]
use windows::Win32::System::Threading::{OpenProcess, WaitForSingleObject, INFINITE, PROCESS_SYNCHRONIZE};

#[cfg(windows)]
const BACKENDS: [&str; 2] = ["argv", "executable"];

#[cfg(windows)]
/// A windowless testbin command running `mode <addr> extra...` through `backend`.
fn testbin_command(backend: &str, mode: &str, addr: &str, extra: &[&str]) -> cosca::Command {
    let mut cmd = cosca::Command::new();
    match backend {
        "argv" => {
            cmd.args([testbin(), mode, addr]);
        }
        "executable" => {
            cmd.executable(testbin()).args(["cosca_testbin", mode, addr]);
        }
        other => panic!("unknown backend {other}"),
    }
    cmd.args(extra);
    cmd.env(ACK_ENV, "1");
    silence(&mut cmd);
    cmd.no_window();
    cmd
}

#[cfg(windows)]
/// An owned `SYNCHRONIZE` handle on a process, opened while something pins its pid.
struct Watch(HANDLE);

#[cfg(windows)]
impl Watch {
    fn open(pid: u32) -> Watch {
        // SAFETY: plain Win32 call; the handle is closed on drop.
        Watch(unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid) }.expect("open the frozen child"))
    }

    /// Block until the process is gone. The process object signals; nothing here is a timer.
    fn wait_for_death(&self) {
        // SAFETY: `self.0` is a live handle.
        let r = unsafe { WaitForSingleObject(self.0, INFINITE) };
        assert_eq!(r, WAIT_OBJECT_0, "waiting for the frozen child to die");
    }
}

#[cfg(windows)]
impl Drop for Watch {
    fn drop(&mut self) {
        // SAFETY: owned, closed once.
        unsafe { _ = CloseHandle(self.0) };
    }
}

#[cfg(windows)]
/// A helper parent holds a frozen child, then is killed (the root only, through its `Child`, which
/// the test keeps alive until the frozen child is observed dead). The helper's own containment
/// cannot be what kills the frozen child: when it is contained at all, the test never tears the
/// tree down. What is left is the frozen child's own guard.
fn frozen_child_dies_with_its_parent(backend: &str, shape: &str, helper_contained: bool, job: &str, guard: &str) {
    let (listener, addr) = bind_report();
    let mut cmd = testbin_command(backend, "spawn-frozen-report", &addr, &[shape, backend]);
    if helper_contained {
        cmd.contain();
    }
    let mut helper = cmd.spawn().expect("spawn the helper parent");
    let mut sock: TcpStream = accept_or_die(&listener, &mut helper);
    let report = read_report_line(&sock);

    assert_eq!(report_field(&report, "job"), job, "{backend}/{shape}: {report}");
    assert_eq!(report_field(&report, "guard"), guard, "{backend}/{shape}: {report}");
    let pid: u32 = report_field(&report, "pid").parse().expect("the frozen child's pid");
    // The helper holds the frozen child until the go byte, so this pid cannot be anyone else's.
    let watch = Watch::open(pid);
    sock.write_all(b"g").expect("send go");

    helper.kill().expect("kill the helper parent, root only");
    watch.wait_for_death();
    drop(helper);
}

#[cfg(windows)]
#[skuld::test]
fn death_watch_uncontained_frozen_child_dies_with_its_parent() {
    for backend in BACKENDS {
        frozen_child_dies_with_its_parent(backend, "uncontained", false, "0", "1");
    }
}

#[cfg(windows)]
#[skuld::test]
fn death_watch_contained_frozen_child_dies_with_its_parent() {
    for backend in BACKENDS {
        frozen_child_dies_with_its_parent(backend, "contained", false, "1", "0");
    }
}

#[cfg(windows)]
/// The frozen child is a nested member of the helper's tree, so the ancestor's job holds it and
/// the test holds that job: only the guard can end it.
#[skuld::test]
fn death_watch_frozen_spawn_inside_a_contained_tree_dies_with_the_nested_parent() {
    for backend in BACKENDS {
        frozen_child_dies_with_its_parent(backend, "uncontained", true, "0", "1");
    }
}

#[cfg(windows)]
/// A resumed uncontained child outlives the guard handle's close: the guard has no kill left.
#[skuld::test]
fn resumed_child_is_alive_after_the_guard_closes() {
    for backend in BACKENDS {
        let (listener, addr) = bind_report();
        let mut cmd = testbin_command(backend, "control-echo-pid", &addr, &["C"]);

        let frozen = cmd.spawn_suspended().expect("spawn suspended");
        let mut child = frozen.resume().expect("resume");

        let mut sock = accept_or_die(&listener, &mut child);
        let (tag, pid) = common::read_tag_and_pid(&mut sock);
        assert_eq!((tag, pid), (b'C', child.id().pid()), "{backend}");
        common::assert_echoes(&mut sock, "the resumed child");
        child.kill().expect("kill");
        child.wait().expect("reap");
    }
}

#[cfg(windows)]
/// The guard permits breakaway. A descendant's `CREATE_BREAKAWAY_FROM_JOB` is a no-op outside a job
/// and `ACCESS_DENIED` inside one that forbids it, so an ordinary spawn is the control: if it is
/// refused too, the environment forbids breakaway and this test says so instead of blaming the guard.
#[skuld::test]
fn a_resumed_uncontained_child_can_still_break_away() {
    for backend in BACKENDS {
        let verdict = |frozen: bool| -> String {
            let (listener, addr) = bind_report();
            let mut cmd = testbin_command(backend, "spawn-breakaway-report", &addr, &[]);
            let mut child = if frozen {
                cmd.spawn_suspended()
                    .expect("spawn suspended")
                    .resume()
                    .expect("resume")
            } else {
                cmd.spawn().expect("spawn")
            };
            let sock = accept_or_die(&listener, &mut child);
            let line = read_report_line(&sock);
            drop(sock);
            child.kill().expect("kill");
            child.wait().expect("reap");
            line.trim().to_owned()
        };

        let control = verdict(false);
        assert_eq!(
            control, "breakaway:ok",
            "{backend}: precondition: an ordinary uncontained child must be able to break away from this \
             environment's job, or this test measures the environment and not the guard"
        );
        assert_eq!(
            verdict(true),
            "breakaway:ok",
            "{backend}: the guard must not forbid breakaway"
        );
    }
}

#[path = "../src/test_harness.rs"]
mod test_harness;

fn main() {
    let mut runner = skuld::TestRunner::new();
    runner.libtest_names();
    runner.require_known_labels();
    runner.run()
}
