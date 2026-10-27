//! Windows: `Command::spawn_suspended`, measured from outside the crate.
//!
//! The lib's own tests (`src/child/suspended_tests.rs`) hold everything that needs a fault seam.
//! What lives here needs real helper processes: a parent that dies while its contained child is
//! frozen, and a resumed child that must behave like an ordinary one.
//!
//! Every child is windowless (`no_window`), so no test opens a console on a developer's desktop.
//! Each spawn runs on both backends: argv (std) and `executable()` (raw `CreateProcessW`). With the
//! `tokio` feature, the async API gets the same two legs where a helper process matters.
//!
//! The death tests are named `death_watch_*`: their waits are on a process handle with no timeout
//! of their own, and `.config/nextest.toml` bounds that name pattern, so a containment that stops
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
#[cfg(all(windows, feature = "tokio"))]
use common::{accept_or_die_async, bind_async_listener, silence_async};

#[cfg(windows)]
use windows::core::{BOOL, PCWSTR};
#[cfg(windows)]
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
#[cfg(windows)]
use windows::Win32::System::JobObjects::{IsProcessInJob, OpenJobObjectW};
#[cfg(windows)]
use windows::Win32::System::Threading::{
    OpenProcess, TerminateProcess, WaitForSingleObject, INFINITE, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
};

/// `JOB_OBJECT_QUERY`, which the `windows` crate does not export as a constant.
#[cfg(windows)]
const JOB_OBJECT_QUERY: u32 = 0x0004;

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

#[cfg(all(windows, feature = "tokio"))]
/// [`testbin_command`] for the async builder.
fn testbin_command_async(backend: &str, mode: &str, addr: &str, extra: &[&str]) -> cosca::tokio::Command {
    let mut cmd = cosca::tokio::Command::new();
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
    silence_async(&mut cmd);
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
/// A helper parent (`mode`: the sync or the async API) holds a contained frozen child, then is
/// killed (the helper alone, through its `Child`). The helper is not contained, so nothing but the
/// frozen child's own containment job, closed with the helper's handle table, can end the child.
fn contained_frozen_child_dies_with_its_parent(mode: &str, backend: &str) {
    let (listener, addr) = bind_report();
    let mut cmd = testbin_command(backend, mode, &addr, &[backend]);
    let mut helper = cmd.spawn().expect("spawn the helper parent");
    let mut sock: TcpStream = accept_or_die(&listener, &mut helper);
    let report = read_report_line(&sock);

    assert_eq!(report_field(&report, "containment"), "JobObject", "{backend}: {report}");
    assert_eq!(report_field(&report, "job"), "1", "{backend}: {report}");
    // The frozen child never runs, so only the job's kill on close can end it. Without the flag the
    // wait below would never return: fail on the flag instead.
    assert_eq!(report_field(&report, "kill_on_close"), "1", "{backend}: {report}");
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
fn death_watch_contained_frozen_child_dies_with_its_parent() {
    for backend in BACKENDS {
        contained_frozen_child_dies_with_its_parent("spawn-frozen-report", backend);
    }
}

#[cfg(all(windows, feature = "tokio"))]
#[skuld::test]
fn death_watch_async_contained_frozen_child_dies_with_its_parent() {
    for backend in BACKENDS {
        contained_frozen_child_dies_with_its_parent("spawn-frozen-report-async", backend);
    }
}

#[cfg(windows)]
/// A resumed child runs.
#[skuld::test]
fn a_resumed_child_runs() {
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

#[cfg(all(windows, feature = "tokio"))]
#[skuld::test]
async fn an_async_resumed_child_runs() {
    for backend in BACKENDS {
        let (listener, addr) = bind_async_listener();
        let mut cmd = testbin_command_async(backend, "control-echo-pid", &addr, &["C"]);

        let frozen = cmd.spawn_suspended().expect("spawn suspended");
        let mut child = frozen.resume().expect("resume");

        let mut sock = accept_or_die_async(&listener, &mut child).await;
        let (tag, pid) = common::read_tag_and_pid(&mut sock);
        assert_eq!((tag, pid), (b'C', child.id().pid()), "{backend}");
        common::assert_echoes(&mut sock, "the resumed child");
        child.kill().expect("kill");
        child.wait().await.expect("reap");
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
/// The helper's `how` for an ordinary child and for a frozen-then-resumed one, through the sync API.
const SYNC_API: (&str, &str) = ("ordinary", "frozen");

#[cfg(all(windows, feature = "tokio"))]
/// [`SYNC_API`] through the async API, whose spawn is a separate path.
const ASYNC_API: (&str, &str) = ("ordinary-async", "frozen-async");

#[cfg(windows)]
/// A resumed child may break away exactly when an ordinary child in its place may. `expected` pins
/// the ordinary verdict, so the comparison is not between two measurements of the wrong
/// environment.
fn assert_breakaway_matches_an_ordinary_spawn(
    (ordinary_how, frozen_how): (&str, &str),
    shape: &str,
    helper_contained: bool,
    ambient: &str,
    expected: &str,
) {
    for backend in BACKENDS {
        let ordinary = breakaway_verdict(backend, shape, ordinary_how, helper_contained, ambient);
        let frozen = breakaway_verdict(backend, shape, frozen_how, helper_contained, ambient);

        assert!(
            ordinary.starts_with(expected),
            "{backend}/{shape}/{ambient}: precondition: the {ordinary_how} spawn's verdict is {ordinary:?}, not {expected:?}"
        );
        assert_eq!(
            frozen, ordinary,
            "{backend}/{shape}/{ambient}: the {frozen_how} child must get the verdict an {ordinary_how} child gets"
        );
    }
}

#[cfg(windows)]
/// An ambient job without `BREAKAWAY_OK`: breakaway is refused, so a resumed child must be refused
/// too.
#[skuld::test]
fn a_resumed_child_cannot_break_away_from_an_ambient_job_that_forbids_it() {
    assert_breakaway_matches_an_ordinary_spawn(SYNC_API, "uncontained", false, "j0", "breakaway:err");
    assert_breakaway_matches_an_ordinary_spawn(SYNC_API, "treewalk", false, "j0", "breakaway:err");
}

#[cfg(all(windows, feature = "tokio"))]
#[skuld::test]
fn an_async_resumed_child_cannot_break_away_from_an_ambient_job_that_forbids_it() {
    assert_breakaway_matches_an_ordinary_spawn(ASYNC_API, "uncontained", false, "j0", "breakaway:err");
    assert_breakaway_matches_an_ordinary_spawn(ASYNC_API, "treewalk", false, "j0", "breakaway:err");
}

#[cfg(windows)]
/// The ancestor's containment job forbids breakaway (`KILL_ON_JOB_CLOSE` alone), and a resumed
/// nested member must not lift that.
#[skuld::test]
fn a_resumed_nested_child_cannot_break_away_from_its_ancestors_containment() {
    assert_breakaway_matches_an_ordinary_spawn(SYNC_API, "contained", true, "inherited", "breakaway:err");
}

#[cfg(all(windows, feature = "tokio"))]
#[skuld::test]
fn an_async_resumed_nested_child_cannot_break_away_from_its_ancestors_containment() {
    assert_breakaway_matches_an_ordinary_spawn(ASYNC_API, "contained", true, "inherited", "breakaway:err");
}

#[cfg(windows)]
/// An ambient job that permits breakaway: the resumed child may break away, as an ordinary one may.
#[skuld::test]
fn a_resumed_child_can_break_away_from_an_ambient_job_that_permits_it() {
    assert_breakaway_matches_an_ordinary_spawn(SYNC_API, "uncontained", false, "jbreak", "breakaway:ok");
}

#[cfg(all(windows, feature = "tokio"))]
#[skuld::test]
fn an_async_resumed_child_can_break_away_from_an_ambient_job_that_permits_it() {
    assert_breakaway_matches_an_ordinary_spawn(ASYNC_API, "uncontained", false, "jbreak", "breakaway:ok");
}

#[cfg(windows)]
/// The detach flow a supervisor uses: resume, then `detach()`, then every handle on the child is
/// gone. The child must still be alive, which its echo proves. A job that kept its kill would end
/// it here.
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

#[cfg(all(windows, feature = "tokio"))]
/// [`resumed_then_detached_child_is_alive`] through the async API.
async fn async_resumed_then_detached_child_is_alive(backend: &str, shape: &str) {
    let (listener, addr) = bind_async_listener();
    let mut cmd = testbin_command_async(backend, "control-echo-pid", &addr, &["C"]);
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
    let mut sock = accept_or_die_async(&listener, &mut child).await;
    let (tag, pid) = common::read_tag_and_pid(&mut sock);
    assert_eq!((tag, pid), (b'C', child.id().pid()), "{backend}/{shape}");
    // While the `Child` pins the pid: the handle that ends the child once the test is done.
    let cleanup = Watch::open_terminable(pid);

    child.detach();
    drop(child);

    common::assert_echoes(&mut sock, &format!("the detached async {backend}/{shape} child"));
    cleanup.terminate_and_wait();
}

#[cfg(all(windows, feature = "tokio"))]
#[skuld::test]
async fn an_async_resumed_then_detached_child_outlives_its_handles() {
    for backend in BACKENDS {
        for shape in ["uncontained", "contained", "treewalk"] {
            async_resumed_then_detached_child_is_alive(backend, shape).await;
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

    /// The name the helper's own ambient job can be opened by, or `none` when it made none.
    fn ambient_job(&self) -> &str {
        report_field(&self.helper_line, "ambient_job")
    }

    /// Whether the grandchild is in the job named `job_name` (a member of a nested job is a member
    /// of every job around it). The grandchild is pinned: it is blocked on its socket.
    fn grandchild_is_in_named_job(&self, job_name: &str) -> bool {
        let wide: Vec<u16> = job_name.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: standard Win32; `wide` is NUL-terminated for the call, both handles are closed
        // before returning, and `in_job` is a valid out-parameter.
        unsafe {
            let job = OpenJobObjectW(JOB_OBJECT_QUERY, false, PCWSTR(wide.as_ptr()))
                .unwrap_or_else(|e| panic!("open the helper's ambient job {job_name}: {e}"));
            let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, self.grandchild_pid())
                .expect("open the grandchild");
            let mut in_job = BOOL(0);
            let queried = IsProcessInJob(process, Some(job), &mut in_job);
            _ = CloseHandle(process);
            _ = CloseHandle(job);
            queried.expect("IsProcessInJob");
            in_job.as_bool()
        }
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
/// A plain grandchild of a resumed frozen child is in the job that holds the child: the helper's
/// ambient job `ambient` names, or, when `helper_contained`, the containment job the test holds. The
/// ordinary spawn is the control, so the membership check is shown to see that job at all.
fn assert_grandchild_stays_in_the_enclosing_job(
    hows: (&str, &str),
    shape: &str,
    helper_contained: bool,
    ambient: &str,
    containment: &str,
) {
    for backend in BACKENDS {
        for how in [hows.0, hows.1] {
            let measured = measure(backend, shape, how, helper_contained, ambient);

            let case = format!("{backend}/{shape}/{how}");
            assert_eq!(measured.containment(), containment, "{case}: the child's shape");
            if helper_contained {
                assert!(
                    measured.helper.test_job_handle_contains(measured.grandchild_pid()),
                    "{case}: the grandchild must be in the helper's containment job, which the test holds"
                );
            } else {
                assert!(
                    measured.grandchild_is_in_named_job(measured.ambient_job()),
                    "{case}: the grandchild must be in the helper's ambient job"
                );
            }
            measured.finish();
        }
    }
}

#[cfg(windows)]
#[skuld::test]
fn death_watch_grandchild_of_a_resumed_uncontained_child_stays_in_the_enclosing_job() {
    assert_grandchild_stays_in_the_enclosing_job(SYNC_API, "uncontained", false, "j0", "None");
}

#[cfg(all(windows, feature = "tokio"))]
#[skuld::test]
fn death_watch_grandchild_of_an_async_resumed_uncontained_child_stays_in_the_enclosing_job() {
    assert_grandchild_stays_in_the_enclosing_job(ASYNC_API, "uncontained", false, "j0", "None");
}

#[cfg(windows)]
#[skuld::test]
fn death_watch_grandchild_of_a_resumed_treewalk_child_stays_in_the_enclosing_job() {
    assert_grandchild_stays_in_the_enclosing_job(SYNC_API, "treewalk", false, "j0", "TreeWalk");
}

#[cfg(all(windows, feature = "tokio"))]
#[skuld::test]
fn death_watch_grandchild_of_an_async_resumed_treewalk_child_stays_in_the_enclosing_job() {
    assert_grandchild_stays_in_the_enclosing_job(ASYNC_API, "treewalk", false, "j0", "TreeWalk");
}

#[cfg(windows)]
#[skuld::test]
fn death_watch_grandchild_of_a_resumed_nested_child_stays_in_the_enclosing_job() {
    assert_grandchild_stays_in_the_enclosing_job(SYNC_API, "contained", true, "inherited", "Delegated");
}

#[cfg(all(windows, feature = "tokio"))]
#[skuld::test]
fn death_watch_grandchild_of_an_async_resumed_nested_child_stays_in_the_enclosing_job() {
    assert_grandchild_stays_in_the_enclosing_job(ASYNC_API, "contained", true, "inherited", "Delegated");
}

#[path = "../src/test_harness.rs"]
mod test_harness;

fn main() {
    #[cfg(windows)]
    common::install_log_capture();
    let mut runner = skuld::TestRunner::new();
    runner.libtest_names();
    runner.require_known_labels();
    runner.run()
}
