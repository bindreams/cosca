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
use windows::Win32::System::Threading::{
    OpenProcess, TerminateProcess, WaitForSingleObject, INFINITE, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
};

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

    /// [`open`](Self::open) that can also end the process, for a test that detaches it.
    fn open_terminable(pid: u32) -> Watch {
        // SAFETY: as in `open`.
        let access = PROCESS_SYNCHRONIZE | PROCESS_TERMINATE;
        Watch(unsafe { OpenProcess(access, false, pid) }.expect("open the child to clean it up"))
    }

    /// End the process, and block until it is gone.
    fn terminate_and_wait(&self) {
        // SAFETY: `self.0` is a live handle with `PROCESS_TERMINATE`.
        unsafe { TerminateProcess(self.0, 1) }.expect("terminate the detached child");
        self.wait_for_death();
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
fn frozen_child_dies_with_its_parent(
    backend: &str,
    shape: &str,
    helper_contained: bool,
    containment: &str,
    job: &str,
    guard: &str,
) {
    let (listener, addr) = bind_report();
    let mut cmd = testbin_command(backend, "spawn-frozen-report", &addr, &[shape, backend]);
    if helper_contained {
        cmd.contain();
    }
    let mut helper = cmd.spawn().expect("spawn the helper parent");
    let mut sock: TcpStream = accept_or_die(&listener, &mut helper);
    let report = read_report_line(&sock);

    assert_eq!(
        report_field(&report, "containment"),
        containment,
        "{backend}/{shape}: {report}"
    );
    assert_eq!(report_field(&report, "job"), job, "{backend}/{shape}: {report}");
    assert_eq!(report_field(&report, "guard"), guard, "{backend}/{shape}: {report}");
    let pid: u32 = report_field(&report, "pid").parse().expect("the frozen child's pid");
    if helper_contained {
        assert!(
            helper.test_job_handle_contains(pid),
            "{backend}/{shape}: the frozen child is in the helper's job, which the test holds"
        );
    }
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
        frozen_child_dies_with_its_parent(backend, "uncontained", false, "None", "0", "1");
    }
}

#[cfg(windows)]
#[skuld::test]
fn death_watch_contained_frozen_child_dies_with_its_parent() {
    for backend in BACKENDS {
        frozen_child_dies_with_its_parent(backend, "contained", false, "JobObject", "1", "0");
    }
}

#[cfg(windows)]
/// The frozen child is a nested member (`Delegated`) of the helper's tree, so the ancestor's job
/// holds it and the test holds that job: only the guard can end it. The helper's report names the
/// containment, so a nested spawn that lost its marker (and would be `None`) fails here.
#[skuld::test]
fn death_watch_frozen_spawn_inside_a_contained_tree_dies_with_the_nested_parent() {
    for backend in BACKENDS {
        frozen_child_dies_with_its_parent(backend, "contained", true, "Delegated", "0", "1");
    }
}

/// As above for a child that asked for no containment but sits in the helper's tree: it has no
/// containment of its own (`None`), the ancestor's job holds it, and only the guard can end it.
#[cfg(windows)]
#[skuld::test]
fn death_watch_uncontained_frozen_spawn_inside_a_contained_tree_dies_with_its_parent() {
    for backend in BACKENDS {
        frozen_child_dies_with_its_parent(backend, "uncontained", true, "None", "0", "1");
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

#[cfg(windows)]
/// What `CREATE_BREAKAWAY_FROM_JOB` gets from a child (frozen and resumed, or `ordinary`) of `shape`
/// that sits in the ambient job `ambient` names, inside a helper that `helper_contained` puts in a
/// job the test holds.
fn breakaway_verdict(backend: &str, shape: &str, how: &str, helper_contained: bool, ambient: &str) -> String {
    let (listener, addr) = bind_report();
    let mut cmd = testbin_command(backend, "spawn-breakaway-child", &addr, &[backend, shape, how, ambient]);
    if helper_contained {
        cmd.contain();
    }
    let mut helper = cmd.spawn().expect("spawn the helper");
    let sock = accept_or_die(&listener, &mut helper);
    let line = read_report_line(&sock);
    drop(sock);
    helper.wait().expect("reap the helper");
    line.trim().to_owned()
}

#[cfg(windows)]
/// A resumed child may break away exactly when an ordinary child in its place may: the guard
/// permits breakaway only if the job the child is in does (or it is in none). `expected` pins the
/// ordinary verdict, so the comparison is not between two measurements of the wrong environment.
fn assert_breakaway_matches_an_ordinary_spawn(shape: &str, helper_contained: bool, ambient: &str, expected: &str) {
    for backend in BACKENDS {
        let ordinary = breakaway_verdict(backend, shape, "ordinary", helper_contained, ambient);
        let frozen = breakaway_verdict(backend, shape, "frozen", helper_contained, ambient);

        assert!(
            ordinary.starts_with(expected),
            "{backend}/{shape}/{ambient}: precondition: the ordinary spawn's verdict is {ordinary:?}, not {expected:?}"
        );
        assert_eq!(
            frozen, ordinary,
            "{backend}/{shape}/{ambient}: the resumed child must get the verdict an ordinary child gets"
        );
    }
}

#[cfg(windows)]
/// An ambient job without `BREAKAWAY_OK`: breakaway is refused, so a resumed child must be refused
/// too. A guard that permitted it would hand the child an escape no ordinary child has.
#[skuld::test]
fn a_resumed_uncontained_child_cannot_break_away_from_an_ambient_job_that_forbids_it() {
    assert_breakaway_matches_an_ordinary_spawn("uncontained", false, "j0", "breakaway:err");
}

#[cfg(windows)]
/// The ancestor's containment job forbids breakaway (`KILL_ON_JOB_CLOSE` alone), and the nested
/// member's guard must not lift that.
#[skuld::test]
fn a_resumed_nested_child_cannot_break_away_from_its_ancestors_containment() {
    assert_breakaway_matches_an_ordinary_spawn("contained", true, "inherited", "breakaway:err");
}

#[cfg(windows)]
#[skuld::test]
fn a_resumed_uncontained_child_in_a_contained_tree_cannot_break_away_from_it() {
    assert_breakaway_matches_an_ordinary_spawn("uncontained", true, "inherited", "breakaway:err");
}

#[cfg(windows)]
#[skuld::test]
fn a_resumed_treewalk_child_cannot_break_away_from_an_ambient_job_that_forbids_it() {
    assert_breakaway_matches_an_ordinary_spawn("treewalk", false, "j0", "breakaway:err");
}

#[cfg(windows)]
/// An ambient job that permits breakaway: the resumed child may break away, as an ordinary one may.
#[skuld::test]
fn a_resumed_child_can_break_away_from_an_ambient_job_that_permits_it() {
    assert_breakaway_matches_an_ordinary_spawn("uncontained", false, "jbreak", "breakaway:ok");
    assert_breakaway_matches_an_ordinary_spawn("treewalk", false, "jbreak", "breakaway:ok");
}

#[cfg(windows)]
/// The detach flow a supervisor uses: resume, then `detach()`, then every handle on the child is
/// gone. The child must still be alive, which its echo proves. A guard that stayed armed, or a job
/// that kept its kill, would end it here.
fn resumed_then_detached_child_is_alive(backend: &str, shape: &str) {
    let (listener, addr) = bind_report();
    let mut cmd = testbin_command(backend, "control-echo-pid", &addr, &["C"]);
    match shape {
        "uncontained" => {}
        "contained" => {
            cmd.contain();
        }
        "treewalk" => {
            cmd.contain_with(cosca::ContainMode::TreeWalk);
        }
        other => panic!("unknown shape {other}"),
    }
    let mut child = cmd
        .spawn_suspended()
        .expect("spawn suspended")
        .resume()
        .expect("resume");
    let mut sock = accept_or_die(&listener, &mut child);
    let (tag, pid) = common::read_tag_and_pid(&mut sock);
    assert_eq!((tag, pid), (b'C', child.id().pid()), "{backend}/{shape}");
    // While the `Child` pins the pid: the handle that ends the child once the test is done.
    let cleanup = Watch::open_terminable(pid);

    child.detach();

    common::assert_echoes(&mut sock, &format!("the detached {backend}/{shape} child"));
    cleanup.terminate_and_wait();
}

#[cfg(windows)]
#[skuld::test]
fn resumed_then_detached_child_outlives_its_handles() {
    for backend in BACKENDS {
        for shape in ["uncontained", "contained", "treewalk"] {
            resumed_then_detached_child_is_alive(backend, shape);
        }
    }
}

#[cfg(windows)]
/// One `spawn-measured-child` run, after the helper and the plain grandchild of its child have both
/// reported. Both sockets stay open, so everything stays blocked and alive until [`finish`](Self::finish).
struct Measured {
    helper: cosca::Child,
    helper_line: String,
    grandchild_line: String,
    socks: [TcpStream; 2],
}

#[cfg(windows)]
impl Measured {
    /// The containment the helper's child ended up with.
    fn containment(&self) -> &str {
        report_field(&self.helper_line, "containment")
    }

    fn grandchild_pid(&self) -> u32 {
        report_field(&self.grandchild_line, "pid")
            .parse()
            .expect("the grandchild pid")
    }

    /// The limit flags of the grandchild's innermost job.
    fn job_flags(&self) -> &str {
        report_field(&self.grandchild_line, "job_flags")
    }

    /// Close both sockets, which lets everything exit, and reap the helper.
    fn finish(self) {
        let Measured { helper, socks, .. } = self;
        drop(socks);
        helper.wait().expect("reap the helper");
    }
}

#[cfg(windows)]
/// Run the helper that spawns a child of `shape` (frozen and resumed, or `ordinary`), which spawns
/// a plain grandchild once the child is running. `helper_contained` puts the helper in a job the
/// test holds. `ambient` is `j0` (the helper makes a job of its own first) or `inherited`.
fn measure(backend: &str, shape: &str, how: &str, helper_contained: bool, ambient: &str) -> Measured {
    let (listener, addr) = bind_report();
    let mut cmd = testbin_command(backend, "spawn-measured-child", &addr, &[backend, shape, how, ambient]);
    if helper_contained {
        cmd.contain();
    }
    let mut helper = cmd.spawn().expect("spawn the helper");
    // The helper reports before it tells its child to go, so the grandchild connects second.
    let helper_sock = accept_or_die(&listener, &mut helper);
    let helper_line = read_report_line(&helper_sock);
    let grandchild_sock = accept_or_die(&listener, &mut helper);
    let grandchild_line = read_report_line(&grandchild_sock);
    Measured {
        helper,
        helper_line,
        grandchild_line,
        socks: [helper_sock, grandchild_sock],
    }
}

#[cfg(windows)]
/// The flags of the job a helper makes for itself (`DIE_ON_UNHANDLED_EXCEPTION`, which no other job
/// in these tests carries) and of the test-held containment job (`KILL_ON_JOB_CLOSE`).
const AMBIENT_JOB_FLAGS: &str = "0x400";
#[cfg(windows)]
const CONTAINMENT_JOB_FLAGS: &str = "0x2000";

#[cfg(windows)]
/// A plain grandchild of a resumed frozen child sits in the job a grandchild of an ordinary
/// spawn's child sits in. The guard is gone from its ancestry, and it has not left a job it would
/// have stayed in. `expected_flags` pins what the ordinary spawn shows, so the comparison cannot be
/// between two measurements of the wrong job.
fn assert_grandchild_job_matches_an_ordinary_spawn(
    shape: &str,
    helper_contained: bool,
    ambient: &str,
    containment: &str,
    expected_flags: &str,
) {
    for backend in BACKENDS {
        let ordinary = measure(backend, shape, "ordinary", helper_contained, ambient);
        let frozen = measure(backend, shape, "frozen", helper_contained, ambient);

        let case = format!("{backend}/{shape}");
        assert_eq!(
            ordinary.containment(),
            containment,
            "{case}: the ordinary spawn's shape"
        );
        assert_eq!(frozen.containment(), containment, "{case}: the frozen spawn's shape");
        assert_eq!(
            ordinary.job_flags(),
            expected_flags,
            "{case}: precondition: the ordinary spawn's grandchild must sit in the job this test built"
        );
        assert_eq!(
            frozen.job_flags(),
            ordinary.job_flags(),
            "{case}: the grandchild of a resumed child must be in the same job as after an ordinary spawn"
        );
        if helper_contained {
            assert!(
                frozen.helper.test_job_handle_contains(frozen.grandchild_pid()),
                "{case}: the grandchild must still be in the helper's job, which the test holds"
            );
        }
        ordinary.finish();
        frozen.finish();
    }
}

#[cfg(windows)]
#[skuld::test]
fn death_watch_grandchild_of_a_resumed_uncontained_child_is_in_the_same_job_as_after_an_ordinary_spawn() {
    assert_grandchild_job_matches_an_ordinary_spawn("uncontained", false, "j0", "None", AMBIENT_JOB_FLAGS);
}

#[cfg(windows)]
#[skuld::test]
fn death_watch_grandchild_of_a_resumed_treewalk_child_is_in_the_same_job_as_after_an_ordinary_spawn() {
    assert_grandchild_job_matches_an_ordinary_spawn("treewalk", false, "j0", "TreeWalk", AMBIENT_JOB_FLAGS);
}

#[cfg(windows)]
#[skuld::test]
fn death_watch_grandchild_of_a_resumed_nested_child_is_in_the_same_job_as_after_an_ordinary_spawn() {
    assert_grandchild_job_matches_an_ordinary_spawn("contained", true, "inherited", "Delegated", CONTAINMENT_JOB_FLAGS);
}

#[cfg(windows)]
/// A plain grandchild of a resumed nested child must not escape the ancestor's job through the
/// guard's silent breakaway: `kill_tree` on the helper (the ancestor's root) has to end it. The wait
/// is on a handle opened while the child holds the grandchild, with no timer; if the grandchild
/// escaped, it never returns and nextest's `death_watch_` bound fails the test.
#[skuld::test]
fn death_watch_kill_tree_of_the_ancestor_ends_the_grandchild_of_a_resumed_nested_child() {
    for backend in BACKENDS {
        for shape in ["contained", "uncontained"] {
            let measured = measure(backend, shape, "frozen", true, "inherited");
            let watch = Watch::open(measured.grandchild_pid());

            measured.helper.kill_tree().expect("kill the helper's tree");

            watch.wait_for_death();
            measured.finish();
        }
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
