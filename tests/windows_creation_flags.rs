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
#![cfg(windows)]

use std::net::{TcpListener, TcpStream};

#[path = "common/mod.rs"]
mod common;

use common::{escape_report_field, read_report_line, report_field, testbin};

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

/// The one flag intent a leg asks for. An enum rather than a closure because the sync and async
/// `Command` types share no trait, and widening the builder's accessors so one closure could
/// serve both is a public-API decision this item does not own.
#[derive(Clone, Copy, Debug)]
enum Intent {
    None,
    NoWindow,
    Detached,
}

/// Spawn a `report-console-identity` child through `backend`, read its report, tear it down, and
/// return the report line.
fn probe(backend: Backend, intent: Intent) -> String {
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
            let mut cmd = cosca::Command::new();
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
            }
            let child = cmd.spawn().expect("spawn creation-flag probe child");
            let (sock, _) = listener.accept().expect("accept report socket");
            let report = read_report_line(&sock);
            drop(sock);
            let _ = child.kill();
            child.wait().expect("reap creation-flag probe child");
            report
        }
        #[cfg(feature = "tokio")]
        Backend::AsyncArgv | Backend::AsyncExecutable => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build a current-thread runtime");
            rt.block_on(async {
                let mut cmd = cosca::tokio::Command::new();
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
                }
                let mut child = cmd.spawn().expect("spawn async creation-flag probe child");
                let (sock, _) = listener.accept().expect("accept report socket");
                let report = read_report_line(&sock);
                drop(sock);
                let _ = child.kill();
                child.wait().await.expect("reap async creation-flag probe child");
                report
            })
        }
    }
}

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

fn assert_no_window(backend: Backend) {
    let report = probe(backend, Intent::NoWindow);
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

fn assert_detached(backend: Backend) {
    let report = probe(backend, Intent::Detached);
    // A MEASURED absence, so a broken probe reports `?` and fails rather than passing.
    assert_eq!(
        report_field(&report, "console"),
        "0",
        "{backend:?} dropped the detach request: {report}"
    );
    assert_backend(backend, &report);
}

fn assert_plain_control(backend: Backend) {
    let report = probe(backend, Intent::None);
    assert_eq!(
        report_field(&report, "sees_caller"),
        "1",
        "{backend:?} control: a plain child shares OUR console: {report}"
    );
    assert_backend(backend, &report);
}

#[test]
fn no_window_reaches_the_child_via_sync_argv() {
    assert_no_window(Backend::SyncArgv);
}

#[test]
fn no_window_reaches_the_child_via_sync_executable() {
    assert_no_window(Backend::SyncExecutable);
}

#[cfg(feature = "tokio")]
#[test]
fn no_window_reaches_the_child_via_async_argv() {
    assert_no_window(Backend::AsyncArgv);
}

#[cfg(feature = "tokio")]
#[test]
fn no_window_reaches_the_child_via_async_executable() {
    assert_no_window(Backend::AsyncExecutable);
}

#[test]
fn detached_reaches_the_child_via_sync_argv() {
    assert_detached(Backend::SyncArgv);
}

#[test]
fn detached_reaches_the_child_via_sync_executable() {
    assert_detached(Backend::SyncExecutable);
}

#[cfg(feature = "tokio")]
#[test]
fn detached_reaches_the_child_via_async_argv() {
    assert_detached(Backend::AsyncArgv);
}

#[cfg(feature = "tokio")]
#[test]
fn detached_reaches_the_child_via_async_executable() {
    assert_detached(Backend::AsyncExecutable);
}

/// The control legs. Without them every assertion above is satisfiable by a helper that never
/// reached the backend it names — "not in our console" is also what a child that failed to
/// register, or was never spawned at all, would look like.
#[test]
fn a_plain_child_joins_the_callers_console_via_sync_argv() {
    assert_plain_control(Backend::SyncArgv);
}

#[test]
fn a_plain_child_joins_the_callers_console_via_sync_executable() {
    assert_plain_control(Backend::SyncExecutable);
}

#[cfg(feature = "tokio")]
#[test]
fn a_plain_child_joins_the_callers_console_via_async_argv() {
    assert_plain_control(Backend::AsyncArgv);
}

#[cfg(feature = "tokio")]
#[test]
fn a_plain_child_joins_the_callers_console_via_async_executable() {
    assert_plain_control(Backend::AsyncExecutable);
}

/// Each raw backend builds its own `Prepared` literal, so its cooperative-signal derivation is a
/// SEPARATE site from `prepare`'s: the std-path twin passing says nothing about this one.
///
/// Two children, so neither a constant nor an unwired derivation passes: a derivation reading
/// only the containment half of the word reports `ConsoleGroup` for both.
#[test]
fn a_no_window_contained_child_reports_no_in_process_route_via_the_raw_backend() {
    use cosca::GracefulMechanism;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let me = std::process::id().to_string();

    let spawn_one = |hidden: bool| -> (cosca::Child, TcpStream) {
        let mut cmd = cosca::Command::new();
        cmd.executable(testbin()).args(report_argv(&addr, &me)).contain();
        if hidden {
            cmd.no_window();
        }
        let child = cmd.spawn().expect("spawn contained raw-backend child");
        let (sock, _) = listener.accept().expect("accept");
        let report = read_report_line(&sock);
        assert_eq!(
            report_field(&report, "argv0"),
            escape_report_field("cosca_testbin"),
            "this leg must have reached the raw backend: {report}"
        );
        (child, sock)
    };

    let (plain, plain_sock) = spawn_one(false);
    assert_eq!(
        plain.graceful_mechanism(),
        GracefulMechanism::ConsoleGroup,
        "a contained raw-backend child leads a group in OUR console"
    );
    let (hidden, hidden_sock) = spawn_one(true);
    assert_eq!(
        hidden.graceful_mechanism(),
        GracefulMechanism::OtherConsoleGroup,
        "the raw backend's own derivation must read the composed word"
    );

    for (child, sock) in [(plain, plain_sock), (hidden, hidden_sock)] {
        drop(sock);
        let _ = child.kill_tree();
        child.wait().expect("reap");
    }
}

/// The async raw backend has a `Prepared` literal of its own — a third derivation site.
#[cfg(feature = "tokio")]
#[tokio::test]
async fn an_async_no_window_contained_child_reports_no_in_process_route_via_the_raw_backend() {
    use cosca::GracefulMechanism;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let me = std::process::id().to_string();

    let spawn_one = |hidden: bool| -> (cosca::tokio::Child, TcpStream) {
        let mut cmd = cosca::tokio::Command::new();
        cmd.executable(testbin()).args(report_argv(&addr, &me)).contain();
        if hidden {
            cmd.no_window();
        }
        let child = cmd.spawn().expect("spawn contained async raw-backend child");
        let (sock, _) = listener.accept().expect("accept");
        let report = read_report_line(&sock);
        assert_eq!(
            report_field(&report, "argv0"),
            escape_report_field("cosca_testbin"),
            "this leg must have reached the raw backend: {report}"
        );
        (child, sock)
    };

    let (plain, plain_sock) = spawn_one(false);
    assert_eq!(plain.graceful_mechanism(), GracefulMechanism::ConsoleGroup);
    let (hidden, hidden_sock) = spawn_one(true);
    assert_eq!(
        hidden.graceful_mechanism(),
        GracefulMechanism::OtherConsoleGroup,
        "the async raw backend's own derivation must read the composed word"
    );

    for (mut child, sock) in [(plain, plain_sock), (hidden, hidden_sock)] {
        drop(sock);
        let _ = child.kill_tree();
        child.wait().await.expect("reap");
    }
}
