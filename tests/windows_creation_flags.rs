//! Windows: a creation-flag intent reaches the child through EVERY backend cosca can route to.
//!
//! Four reachable configurations — sync/async × argv/`executable()` — because the routing rule
//! sends an `executable()` (or any fd >= 3) to the raw `CreateProcessW` backend and everything
//! else to std, and the two async backends are hand-mirrored copies whose parity the compiler
//! does not enforce. A backend that drops a flag fails here rather than in review.
//!
//! Each leg names the backend it claims to exercise, and two independent things make that name
//! true: the `executable()` legs assert the child's own `argv0` (only the raw backend can give a
//! child an `argv[0]` that differs from the image it loaded), and the routing rule itself is one
//! crate-internal function both routers read, pinned by
//! `child::spawn::spawn_tests::routes_to_raw_backend_answers_for_executables_and_high_descriptors`.

#[cfg(windows)]
use std::net::{TcpListener, TcpStream};

#[cfg(windows)]
#[path = "common/mod.rs"]
mod common;

#[cfg(windows)]
use common::{escape_report_field, read_report_line, report_field, testbin};

#[cfg(windows)]
/// Which of the four reachable spawn configurations a leg drives.
#[derive(Clone, Copy, Debug)]
enum Backend {
    SyncArgv,
    SyncExecutable,
    #[cfg(feature = "tokio")]
    AsyncArgv,
    #[cfg(feature = "tokio")]
    AsyncExecutable,
}

#[cfg(windows)]
impl Backend {
    /// Whether this configuration routes to the raw `CreateProcessW` backend.
    fn is_raw(self) -> bool {
        match self {
            Backend::SyncArgv => false,
            Backend::SyncExecutable => true,
            #[cfg(feature = "tokio")]
            Backend::AsyncArgv => false,
            #[cfg(feature = "tokio")]
            Backend::AsyncExecutable => true,
        }
    }
}

#[cfg(windows)]
/// A listener plus the argv every leg passes, so the four spawn shapes differ only in the two
/// things under test: sync-vs-async and argv-vs-`executable()`.
fn report_argv(addr: &str, me: &str) -> [String; 4] {
    [
        // argv[0]. The `executable()` legs override the loaded image, so this stays the bare
        // name there and is what proves the raw backend ran.
        "cosca_testbin".to_string(),
        "report-console-identity".to_string(),
        addr.to_string(),
        me.to_string(),
    ]
}

#[cfg(windows)]
/// The one flag intent a leg asks for. An enum rather than a closure because the sync and async
/// `Command` types share no trait, and widening the builder's accessors so one closure could
/// serve both is a public-API decision this item does not own.
#[derive(Clone, Copy, Debug)]
enum Intent {
    None,
    NoWindow,
    Detached,
    /// `new_process_group(true)` on an uncontained spawn.
    Group,
    /// `contain()` with `new_process_group(false)`.
    ContainedWithoutGroup,
}

#[cfg(windows)]
/// What a probe saw: the child's own report, and what `terminate()` answered once the report was in.
/// The answer is what the child's RECORDED console facts decide: `Ok` when they say it leads a group
/// (the break was sent to it), `Unsupported` when they say it leads none. It is not evidence of the
/// flag the OS got.
struct Probed {
    report: String,
    terminate: Result<(), cosca::error::Error>,
}

#[cfg(windows)]
/// Spawn a `report-console-identity` child through `backend`, read its report, `terminate()` it, tear
/// it down, and return what was seen.
fn probe(backend: Backend, intent: Intent) -> Probed {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind report listener");
    let addr = listener.local_addr().unwrap().to_string();
    let me = std::process::id().to_string();
    let mut argv = report_argv(&addr, &me);
    if !backend.is_raw() {
        // No `executable()` here, so `argv[0]` must carry the image path for the OS to find it.
        argv[0] = testbin().to_string();
    }

    match backend {
        Backend::SyncArgv | Backend::SyncExecutable => {
            let mut cmd = common::command(common::Console::Asked);
            cmd.args(&argv);
            if backend.is_raw() {
                cmd.executable(testbin());
            }
            match intent {
                Intent::None => {}
                Intent::NoWindow => {
                    cmd.no_window();
                }
                Intent::Detached => {
                    cmd.detached();
                }
                Intent::Group => {
                    cmd.new_process_group(true);
                }
                Intent::ContainedWithoutGroup => {
                    cmd.contain().new_process_group(false);
                }
            }
            cmd.env(common::ACK_ENV, "1");
            let mut child = cmd.spawn().expect("spawn creation-flag probe child");
            let sock = common::accept_or_die(&listener, &mut child);
            let report = read_report_line(&sock);
            let terminate = child.terminate();
            drop(sock);
            let _ = child.kill();
            child.wait().expect("reap creation-flag probe child");
            Probed { report, terminate }
        }
        #[cfg(feature = "tokio")]
        Backend::AsyncArgv | Backend::AsyncExecutable => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build a current-thread runtime");
            rt.block_on(async {
                listener
                    .set_nonblocking(true)
                    .expect("set the listener nonblocking for tokio");
                let listener = ::tokio::net::TcpListener::from_std(listener).expect("wrap the listener for tokio");
                let mut cmd = common::tokio_command(common::Console::Asked);
                cmd.args(&argv);
                if backend.is_raw() {
                    cmd.executable(testbin());
                }
                match intent {
                    Intent::None => {}
                    Intent::NoWindow => {
                        cmd.no_window();
                    }
                    Intent::Detached => {
                        cmd.detached();
                    }
                    Intent::Group => {
                        cmd.new_process_group(true);
                    }
                    Intent::ContainedWithoutGroup => {
                        cmd.contain().new_process_group(false);
                    }
                }
                cmd.env(common::ACK_ENV, "1");
                let mut child = cmd.spawn().await.expect("spawn async creation-flag probe child");
                let sock = common::accept_or_die_async(&listener, &mut child).await;
                let report = read_report_line(&sock);
                let terminate = child.terminate().await;
                drop(sock);
                let _ = child.kill();
                child.wait().await.expect("reap async creation-flag probe child");
                Probed { report, terminate }
            })
        }
    }
}

#[cfg(windows)]
/// Every `executable()` leg proves it reached the raw backend from the CHILD's own report:
/// `argv[0]` differs from the image that ran, which only `CreateProcessW`'s independent
/// `lpApplicationName`/`lpCommandLine` can produce — on the std path std sets `argv[0]` to the
/// program it was given. See `spawn_unelevated`'s routing condition for why that is sufficient.
fn assert_backend(backend: Backend, report: &str) {
    if backend.is_raw() {
        assert_eq!(
            report_field(report, "argv0"),
            escape_report_field("cosca_testbin"),
            "{backend:?} must have reached the raw backend: {report}"
        );
    }
}

#[cfg(windows)]
fn assert_no_window(backend: Backend) {
    let report = probe(backend, Intent::NoWindow).report;
    assert_eq!(
        report_field(&report, "console"),
        "1",
        "{backend:?}: suppression still leaves a console: {report}"
    );
    assert_eq!(
        report_field(&report, "sees_caller"),
        "0",
        "{backend:?} dropped the window-suppression request: {report}"
    );
    assert_backend(backend, &report);
}

#[cfg(windows)]
fn assert_detached(backend: Backend) {
    let report = probe(backend, Intent::Detached).report;
    // A MEASURED absence, so a broken probe reports `?` and fails rather than passing.
    assert_eq!(
        report_field(&report, "console"),
        "0",
        "{backend:?} dropped the detach request: {report}"
    );
    assert_backend(backend, &report);
}

#[cfg(windows)]
/// `new_process_group(true)` reaches the child's recorded console facts through `backend`: they say it
/// leads a group, so `terminate()` sends the break to it. Without the request an uncontained child's
/// facts say none and the same call is refused.
fn assert_group(backend: Backend) {
    let probed = probe(backend, Intent::Group);
    probed.terminate.unwrap_or_else(|e| {
        panic!("{backend:?} recorded no process group for a child given new_process_group(true): {e:?}")
    });
    assert_backend(backend, &probed.report);
}

#[cfg(windows)]
/// `new_process_group(false)` reaches the child's recorded console facts through `backend` on a
/// contained spawn, which leads a group by default: they say none, so `terminate()` is refused with
/// the setter named.
fn assert_no_group(backend: Backend) {
    let probed = probe(backend, Intent::ContainedWithoutGroup);
    let err = probed
        .terminate
        .expect_err("a contained child told to lead no group must be refused the group break");
    common::assert_refused_for_no_group(&err);
    assert_backend(backend, &probed.report);
}

#[cfg(windows)]
fn assert_plain_control(backend: Backend) {
    let report = probe(backend, Intent::None).report;
    assert_eq!(
        report_field(&report, "sees_caller"),
        "1",
        "{backend:?} control: a plain child shares OUR console: {report}"
    );
    assert_backend(backend, &report);
}

#[cfg(windows)]
#[skuld::test]
fn no_window_reaches_the_child_via_sync_argv() {
    assert_no_window(Backend::SyncArgv);
}

#[cfg(windows)]
#[skuld::test]
fn no_window_reaches_the_child_via_sync_executable() {
    assert_no_window(Backend::SyncExecutable);
}

#[cfg(windows)]
#[cfg(feature = "tokio")]
#[skuld::test]
fn no_window_reaches_the_child_via_async_argv() {
    assert_no_window(Backend::AsyncArgv);
}

#[cfg(windows)]
#[cfg(feature = "tokio")]
#[skuld::test]
fn no_window_reaches_the_child_via_async_executable() {
    assert_no_window(Backend::AsyncExecutable);
}

#[cfg(windows)]
#[skuld::test]
fn detached_reaches_the_child_via_sync_argv() {
    assert_detached(Backend::SyncArgv);
}

#[cfg(windows)]
#[skuld::test]
fn detached_reaches_the_child_via_sync_executable() {
    assert_detached(Backend::SyncExecutable);
}

#[cfg(windows)]
#[cfg(feature = "tokio")]
#[skuld::test]
fn detached_reaches_the_child_via_async_argv() {
    assert_detached(Backend::AsyncArgv);
}

#[cfg(windows)]
#[cfg(feature = "tokio")]
#[skuld::test]
fn detached_reaches_the_child_via_async_executable() {
    assert_detached(Backend::AsyncExecutable);
}

#[cfg(windows)]
#[skuld::test]
fn a_child_given_a_process_group_is_sent_the_break_via_sync_argv() {
    assert_group(Backend::SyncArgv);
}

#[cfg(windows)]
#[skuld::test]
fn a_child_given_a_process_group_is_sent_the_break_via_sync_executable() {
    assert_group(Backend::SyncExecutable);
}

#[cfg(windows)]
#[cfg(feature = "tokio")]
#[skuld::test]
fn a_child_given_a_process_group_is_sent_the_break_via_async_argv() {
    assert_group(Backend::AsyncArgv);
}

#[cfg(windows)]
#[cfg(feature = "tokio")]
#[skuld::test]
fn a_child_given_a_process_group_is_sent_the_break_via_async_executable() {
    assert_group(Backend::AsyncExecutable);
}

#[cfg(windows)]
#[skuld::test]
fn a_contained_child_without_a_process_group_is_refused_the_break_via_sync_argv() {
    assert_no_group(Backend::SyncArgv);
}

#[cfg(windows)]
#[skuld::test]
fn a_contained_child_without_a_process_group_is_refused_the_break_via_sync_executable() {
    assert_no_group(Backend::SyncExecutable);
}

#[cfg(windows)]
#[cfg(feature = "tokio")]
#[skuld::test]
fn a_contained_child_without_a_process_group_is_refused_the_break_via_async_argv() {
    assert_no_group(Backend::AsyncArgv);
}

#[cfg(windows)]
#[cfg(feature = "tokio")]
#[skuld::test]
fn a_contained_child_without_a_process_group_is_refused_the_break_via_async_executable() {
    assert_no_group(Backend::AsyncExecutable);
}

#[cfg(windows)]
/// The control legs. Without them every assertion above is satisfiable by a helper that never
/// reached the backend it names — "not in our console" is also what a child that failed to
/// register, or was never spawned at all, would look like.
#[skuld::test]
fn a_plain_child_joins_the_callers_console_via_sync_argv() {
    assert_plain_control(Backend::SyncArgv);
}

#[cfg(windows)]
#[skuld::test]
fn a_plain_child_joins_the_callers_console_via_sync_executable() {
    assert_plain_control(Backend::SyncExecutable);
}

#[cfg(windows)]
#[cfg(feature = "tokio")]
#[skuld::test]
fn a_plain_child_joins_the_callers_console_via_async_argv() {
    assert_plain_control(Backend::AsyncArgv);
}

#[cfg(windows)]
#[cfg(feature = "tokio")]
#[skuld::test]
fn a_plain_child_joins_the_callers_console_via_async_executable() {
    assert_plain_control(Backend::AsyncExecutable);
}

#[cfg(windows)]
/// Each raw backend builds its own `Prepared` literal, so its console facts are a SEPARATE
/// derivation from `prepare`'s: the std-path twin passing says nothing about this one.
///
/// Two children, so neither a constant nor an unwired derivation passes: a derivation reading
/// only the containment half of the word records a route for both.
#[skuld::test]
fn a_no_window_contained_child_reports_no_in_process_route_via_the_raw_backend() {
    use cosca::StopTarget;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let me = std::process::id().to_string();

    let spawn_one = |hidden: bool| -> (cosca::Child, TcpStream) {
        let mut cmd = common::command(common::Console::Asked);
        cmd.executable(testbin())
            .args(report_argv(&addr, &me))
            .env(common::ACK_ENV, "1")
            .contain();
        if hidden {
            cmd.no_window();
        }
        let mut child = cmd.spawn().expect("spawn contained raw-backend child");
        let sock = common::accept_or_die(&listener, &mut child);
        let report = read_report_line(&sock);
        assert_eq!(
            report_field(&report, "argv0"),
            escape_report_field("cosca_testbin"),
            "this leg must have reached the raw backend: {report}"
        );
        (child, sock)
    };

    let (plain, plain_sock) = spawn_one(false);
    assert!(
        StopTarget::from(&plain).leads_group_on_our_console(),
        "a contained raw-backend child leads a group in OUR console"
    );
    let (hidden, hidden_sock) = spawn_one(true);
    assert!(
        !StopTarget::from(&hidden).leads_group_on_our_console(),
        "the raw backend's own derivation must read the composed word"
    );

    for (child, sock) in [(plain, plain_sock), (hidden, hidden_sock)] {
        drop(sock);
        let _ = child.kill_tree();
        child.wait().expect("reap");
    }
}

#[cfg(windows)]
/// The async raw backend reads the composed word too: a contained child it spawns with `no_window` gets
/// a console of its own, as the child itself reports, while a plain one shares ours.
#[cfg(feature = "tokio")]
#[skuld::test]
async fn an_async_no_window_contained_child_gets_a_console_of_its_own_via_the_raw_backend() {
    let (listener, addr) = common::bind_async_listener();
    let me = std::process::id().to_string();

    async fn spawn_one(
        listener: &::tokio::net::TcpListener,
        addr: &str,
        me: &str,
        hidden: bool,
    ) -> (cosca::tokio::Child, TcpStream, String) {
        let mut cmd = common::tokio_command(common::Console::Asked);
        cmd.executable(testbin())
            .args(report_argv(addr, me))
            .env(common::ACK_ENV, "1")
            .contain();
        if hidden {
            cmd.no_window();
        }
        let mut child = cmd.spawn().await.expect("spawn contained async raw-backend child");
        let sock = common::accept_or_die_async(listener, &mut child).await;
        let report = read_report_line(&sock);
        assert_eq!(
            report_field(&report, "argv0"),
            escape_report_field("cosca_testbin"),
            "this leg must have reached the raw backend: {report}"
        );
        (child, sock, report)
    }

    let (plain, plain_sock, plain_report) = spawn_one(&listener, &addr, &me, false).await;
    assert_eq!(
        report_field(&plain_report, "sees_caller"),
        "1",
        "a plain contained child shares OUR console: {plain_report}"
    );
    assert!(
        cosca::StopTarget::from(&plain).leads_group_on_our_console(),
        "cosca recorded the plain child as leading a group on our console"
    );
    let (hidden, hidden_sock, hidden_report) = spawn_one(&listener, &addr, &me, true).await;
    assert_eq!(
        report_field(&hidden_report, "sees_caller"),
        "0",
        "the async raw backend must read the composed word: {hidden_report}"
    );
    assert!(
        !cosca::StopTarget::from(&hidden).leads_group_on_our_console(),
        "cosca recorded the hidden child as outside our console"
    );

    for (mut child, sock) in [(plain, plain_sock), (hidden, hidden_sock)] {
        drop(sock);
        let _ = child.kill_tree().await;
        child.wait().await.expect("reap");
    }
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
