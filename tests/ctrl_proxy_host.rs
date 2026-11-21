//! A host that has not called `cosca::init_helpers()`: this binary's `main` does not, so
//! `CtrlProxy::HostExecutable` would start a second copy of it that runs as itself. A Windows stop that
//! would start it as the proxy panics instead, as the first thing the proxy route does, before anything
//! starts; a stop that needs no helper (the direct send, an `Executable` setting) does not.
//!
//! The proof that nothing started is the marker a copy of this binary leaves when it is started as a
//! helper (with `__COSCA_HELPER` set, spelled out here since the variable is crate-private), in the
//! directory the test made for it ([`MarkerDir`]).

#[cfg(windows)]
#[path = "common/mod.rs"]
mod common;

/// The directory in which a copy of this binary started as the proxy by the process `caller` leaves its
/// mark. Only the test makes it, and only a copy started by it can leave the mark in it.
#[cfg(windows)]
fn marker_dir(caller: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("cosca-ctrl-proxy-host-started-by-{caller}"))
}

/// A fresh, empty [`marker_dir`] for this process, removed when dropped (a failed test too).
#[cfg(windows)]
struct MarkerDir(std::path::PathBuf);

#[cfg(windows)]
impl MarkerDir {
    fn new() -> MarkerDir {
        let dir = marker_dir(&std::process::id().to_string());
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir(&dir).expect("a directory for the marker");
        MarkerDir(dir)
    }

    fn marker(&self) -> std::path::PathBuf {
        self.0.join("started")
    }
}

#[cfg(windows)]
impl Drop for MarkerDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

/// The panic of a stop in a host that never called the hook says what is wrong and both ways out, the hook
/// first.
#[cfg(windows)]
#[track_caller]
fn assert_names_the_hook_then_the_executable(payload: Box<dyn std::any::Any + Send>) {
    let text = common::panic_message(payload);
    let hook = text.find("cosca::init_helpers()").expect(&text);
    let executable = text
        .find("Command::ctrl_proxy(CtrlProxy::Executable(..))")
        .expect(&text);
    assert!(hook < executable, "the hook comes first: {text}");
    assert!(text.contains("cosca-ctrl-proxy"), "{text}");
}

/// A proxy setting that names a program no stop here ever starts: the stops that must not panic are asked
/// of an exited child, which is answered before anything starts.
#[cfg(windows)]
fn never_started() -> cosca::CtrlProxy {
    cosca::CtrlProxy::Executable("cosca-ctrl-proxy-that-is-never-started.exe".into())
}

/// `STATUS_CONTROL_C_EXIT`: how a process with no handler ends on a delivered break.
#[cfg(windows)]
const STATUS_CONTROL_C_EXIT: i32 = 0xC000_013A_u32 as i32;

/// The four public stop calls (each with a sync and a tokio form) that carry the `# Panics` section.
#[cfg(windows)]
#[derive(Debug, Clone, Copy)]
enum Call {
    Terminate,
    TerminateTree,
    GracefulShutdown,
    GracefulShutdownTree,
}

#[cfg(windows)]
impl Call {
    const ALL: [Call; 4] = [
        Call::Terminate,
        Call::TerminateTree,
        Call::GracefulShutdown,
        Call::GracefulShutdownTree,
    ];

    /// The tree calls need a contained child: on any other they fail before the stop action runs.
    fn applies_to(self, contained: bool) -> bool {
        contained || !matches!(self, Call::TerminateTree | Call::GracefulShutdownTree)
    }

    fn run(self, child: &cosca::Child) -> Result<(), cosca::error::Error> {
        let grace = std::time::Duration::ZERO;
        match self {
            Call::Terminate => child.terminate().map_err(Into::into),
            Call::TerminateTree => child.terminate_tree().map_err(Into::into),
            Call::GracefulShutdown => child.graceful_shutdown(grace).map(drop),
            Call::GracefulShutdownTree => child.graceful_shutdown_tree(grace).map(drop),
        }
    }

    #[cfg(feature = "tokio")]
    async fn run_async(self, child: &mut cosca::tokio::Child) -> Result<(), cosca::error::Error> {
        let grace = std::time::Duration::ZERO;
        match self {
            Call::Terminate => child.terminate().await.map_err(Into::into),
            Call::TerminateTree => child.terminate_tree().await.map_err(Into::into),
            Call::GracefulShutdown => child.graceful_shutdown(grace).await.map(drop),
            Call::GracefulShutdownTree => child.graceful_shutdown_tree(grace).await.map(drop),
        }
    }

    /// What the call answers for a contained or plain root that had exited, when it does not panic and
    /// starts no proxy: the root's exit is looked at first. `terminate_tree` errs with nothing sent (a
    /// member that outlived the root is out of the proxy's reach); the others go on and end `Ok`.
    #[track_caller]
    fn assert_exited_root_outcome(self, result: Result<(), cosca::error::Error>) {
        match self {
            Call::TerminateTree => {
                let err = result.expect_err("nothing was sent to the tree");
                let said_nothing_was_sent = matches!(
                    &err,
                    cosca::error::Error::Unassessable { detail, .. } if detail.contains("nothing was sent")
                );
                assert!(said_nothing_was_sent, "{self:?}: {err:?}");
            }
            _ => result.unwrap_or_else(|e| panic!("{self:?}: an exited root is answered Ok: {e:?}")),
        }
    }
}

/// In a host that did not call `init_helpers`, the default stop panics (naming `cosca::init_helpers()` and
/// the `Executable` setting) only on the route that would start this program as the proxy: a child outside
/// our console. A child that leads a group on our console is sent the direct Ctrl+Break and ends by it, and
/// one on our console with no group gets the direct send's refusal: neither needs a helper, neither panics.
/// On the proxy route every public stop call panics (`terminate`, `terminate_tree`, `graceful_shutdown`,
/// `graceful_shutdown_tree`), and the child is still there to kill. No process is started. Mutants: the
/// check sits in the default's body before the route is chosen (the first two panic); a call maps the panic
/// to an error.
#[cfg(windows)]
#[skuld::test]
fn the_default_stop_without_the_init_hook_panics_only_on_the_proxy_route() {
    assert!(
        !cosca::helpers_initialized(),
        "this binary's `main` must not call `cosca::init_helpers()`"
    );
    for contain in [false, true] {
        let markers = MarkerDir::new();

        let (leading, sock) = common::spawn_control_on_console_with("control-block", &["R"], contain, |cmd| {
            _ = cmd.new_process_group(true);
        });
        leading
            .terminate()
            .unwrap_or_else(|e| panic!("contained {contain}: the direct break needs no hook: {e:?}"));
        let status = leading.wait().expect("the child's exit");
        assert_eq!(
            status.code(),
            Some(STATUS_CONTROL_C_EXIT),
            "contained {contain}: the direct break ended it: {status:?}"
        );
        drop(sock);

        let (ungrouped, sock) = common::spawn_control_on_console_with("control-block", &["R"], contain, |cmd| {
            _ = cmd.new_process_group(false);
        });
        let err = ungrouped
            .terminate()
            .expect_err("a child that leads no group cannot be addressed");
        common::assert_refused_for_no_group(err.error());
        ungrouped.kill().expect("kill the child");
        drop(sock);

        let (outside, sock) = common::spawn_control_with("control-block", &["R"], contain, |cmd| {
            cmd.no_window();
        });
        for call in Call::ALL.into_iter().filter(|call| call.applies_to(contain)) {
            let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| call.run(&outside)))
                .expect_err(&format!("contained {contain}: {call:?} panics on the proxy route"));
            assert_names_the_hook_then_the_executable(payload);
        }
        outside.kill().expect("kill the child");
        drop(sock);

        assert!(
            !markers.marker().exists(),
            "contained {contain}: a copy of the host was started as the proxy"
        );
    }
}

/// `send_console_event_via_proxy` in a host that did not call `init_helpers` panics, for a running child
/// and for one that has exited (the check is before the look at the child). No process is started.
/// Mutant: the check sits after the look at the child, so the exited child is answered `Ok`.
#[cfg(windows)]
#[skuld::test]
fn the_proxy_send_without_the_init_hook_panics_even_for_an_exited_child() {
    let (running, running_sock) = common::spawn_control_with("control-block", &["R"], false, |_| {});
    let (exited, exited_sock) = common::spawn_control_with("control-block", &["R"], false, |_| {});
    exited.kill().expect("kill the child");
    exited.wait().expect("see its exit");
    drop(exited_sock);
    for (state, child) in [("running", &running), ("exited", &exited)] {
        let markers = MarkerDir::new();
        let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            cosca::stop::send_console_event_via_proxy(&cosca::StopTarget::from(child), cosca::CtrlEvent::CtrlBreak)
        }))
        .expect_err(&format!("{state}: the send panics"));
        assert_names_the_hook_then_the_executable(payload);
        assert!(
            !markers.marker().exists(),
            "{state}: a copy of the host was started as the proxy"
        );
    }
    running.kill().expect("kill the child");
    drop(running_sock);
}

/// Every public stop call on an exited child outside our console panics too: the check is at the start of
/// the proxy route, before the look at the child. Mutants: the check sits after the look at the child (the
/// exited child is answered `Ok`); a tree call maps the panic to an error.
#[cfg(windows)]
#[skuld::test]
fn the_stop_calls_without_the_init_hook_panic_for_an_exited_child_on_the_proxy_route() {
    for contain in [false, true] {
        let (child, sock) = common::spawn_control_with("control-block", &["R"], contain, |_| {});
        child.kill().expect("kill the child");
        child.wait().expect("see its exit");
        drop(sock);
        let markers = MarkerDir::new();

        for call in Call::ALL.into_iter().filter(|call| call.applies_to(contain)) {
            let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| call.run(&child)))
                .expect_err(&format!("contained {contain}: {call:?} panics"));
            assert_names_the_hook_then_the_executable(payload);
        }
        assert!(
            !markers.marker().exists(),
            "contained {contain}: a copy of the host was started as the proxy"
        );
    }
}

/// A command that names `CtrlProxy::Executable(..)` needs no hook on either route: no public stop call
/// panics, and the exited-root outcomes are the ones a host with the hook gets, with nothing started: the
/// default and the proxy send answer an exited child `Ok`, `terminate_tree` errs with `Unassessable` saying
/// nothing was sent, `graceful_shutdown_tree` goes on to its sweep and reap. Mutants: the check ignores the
/// setting, so the proxy route panics; the exit look is skipped for tree calls (the proxy would be started,
/// and the answer is another error).
#[cfg(windows)]
#[skuld::test]
fn an_executable_setting_needs_no_init_hook() {
    for contain in [false, true] {
        for call in Call::ALL.into_iter().filter(|call| call.applies_to(contain)) {
            let (child, sock) = common::spawn_control_with("control-block", &["R"], contain, |cmd| {
                cmd.ctrl_proxy(never_started());
            });
            child.kill().expect("kill the child");
            child.wait().expect("see its exit");
            drop(sock);
            call.assert_exited_root_outcome(call.run(&child));
        }
    }

    let (child, sock) = common::spawn_control_on_console_with("control-block", &["R"], false, |cmd| {
        cmd.new_process_group(true).ctrl_proxy(never_started());
    });
    child.kill().expect("kill the child");
    child.wait().expect("see its exit");
    drop(sock);
    child
        .terminate()
        .unwrap_or_else(|e| panic!("on our console: an exited child is Ok: {e:?}"));

    let (child, sock) = common::spawn_control_with("control-block", &["R"], false, |cmd| {
        cmd.ctrl_proxy(never_started());
    });
    child.kill().expect("kill the child");
    child.wait().expect("see its exit");
    drop(sock);
    cosca::stop::send_console_event_via_proxy(&cosca::StopTarget::from(&child), cosca::CtrlEvent::CtrlBreak)
        .unwrap_or_else(|e| panic!("an exited child is Ok: {e:?}"));
}

/// The async twins: every public stop call of the tokio `Child` panics on the proxy route (a child outside
/// our console, running or exited) and so does `tokio::stop::send_console_event_via_proxy`; a child that
/// leads a group on our console is sent the direct break and ends by it; an executable setting panics on
/// none, and the exited-root outcomes are checked as in the sync test. Mutants: the async default's check
/// is before the route is chosen (the leading child panics); the async proxy send skips it; a tree call
/// maps the panic to an error; the exit look is skipped for tree calls.
#[cfg(all(windows, feature = "tokio"))]
#[skuld::test]
async fn async_stops_without_the_init_hook_panic_only_on_the_proxy_route() {
    use cosca::StopTarget;

    for contain in [false, true] {
        let (mut running, running_sock) = common::spawn_control_async_with("control-block", &["R"], contain, |cmd| {
            cmd.no_window();
        })
        .await;
        let markers = MarkerDir::new();

        for call in Call::ALL.into_iter().filter(|call| call.applies_to(contain)) {
            let payload = common::catching(call.run_async(&mut running))
                .await
                .expect_err(&format!(
                    "contained {contain}: the async {call:?} panics on the proxy route"
                ));
            assert_names_the_hook_then_the_executable(payload);
        }
        let payload = common::catching(cosca::tokio::stop::send_console_event_via_proxy(
            &StopTarget::from(&running),
            cosca::CtrlEvent::CtrlBreak,
        ))
        .await
        .expect_err("the async proxy send panics");
        assert_names_the_hook_then_the_executable(payload);
        assert!(
            !markers.marker().exists(),
            "contained {contain}: a copy of the host was started as the proxy"
        );
        running.kill().expect("kill the child");
        drop(running_sock);

        let (mut leading, leading_sock) =
            common::spawn_control_async_on_console_with("control-block", &["R"], contain, |cmd| {
                cmd.new_process_group(true);
            })
            .await;
        leading
            .terminate()
            .await
            .unwrap_or_else(|e| panic!("contained {contain}: the direct break needs no hook: {e:?}"));
        let status = leading.wait().await.expect("the child's exit");
        assert_eq!(
            status.code(),
            Some(STATUS_CONTROL_C_EXIT),
            "contained {contain}: the direct break ended it: {status:?}"
        );
        drop(leading_sock);

        let (mut exited, exited_sock) =
            common::spawn_control_async_with("control-block", &["R"], contain, |_| {}).await;
        exited.kill().expect("kill the child");
        exited.wait().await.expect("see its exit");
        drop(exited_sock);
        for call in Call::ALL.into_iter().filter(|call| call.applies_to(contain)) {
            let payload = common::catching(call.run_async(&mut exited)).await.expect_err(&format!(
                "contained {contain}: the async {call:?} panics for an exited child"
            ));
            assert_names_the_hook_then_the_executable(payload);
        }

        for call in Call::ALL.into_iter().filter(|call| call.applies_to(contain)) {
            let (mut named, named_sock) = common::spawn_control_async_with("control-block", &["R"], contain, |cmd| {
                cmd.ctrl_proxy(never_started());
            })
            .await;
            named.kill().expect("kill the child");
            named.wait().await.expect("see its exit");
            drop(named_sock);
            call.assert_exited_root_outcome(call.run_async(&mut named).await);
        }
        let (mut named, named_sock) = common::spawn_control_async_with("control-block", &["R"], contain, |cmd| {
            cmd.ctrl_proxy(never_started());
        })
        .await;
        named.kill().expect("kill the child");
        named.wait().await.expect("see its exit");
        drop(named_sock);
        cosca::tokio::stop::send_console_event_via_proxy(&StopTarget::from(&named), cosca::CtrlEvent::CtrlBreak)
            .await
            .unwrap_or_else(|e| panic!("contained {contain}: the async proxy send answers Ok: {e:?}"));
    }
}

#[path = "../src/test_harness.rs"]
mod test_harness;

fn main() {
    // A copy of this binary started as a helper: a stop that should have panicked started it. It leaves the
    // marker the test looks for and exits 0, which is no answer of the protocol. The variable name is
    // spelled out, the constant is crate-private.
    #[cfg(windows)]
    {
        let args: Vec<String> = std::env::args().collect();
        if std::env::var_os("__COSCA_HELPER").is_some() {
            if let Some(dir) = args.get(5).map(|caller| marker_dir(caller)).filter(|dir| dir.is_dir()) {
                std::fs::write(dir.join("started"), "started").expect("leave the marker");
            }
            return;
        }
        common::install_log_capture();
    }
    let mut runner = skuld::TestRunner::new();
    runner.libtest_names();
    runner.require_known_labels();
    runner.run()
}
