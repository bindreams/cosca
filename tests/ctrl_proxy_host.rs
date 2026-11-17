//! A host that has not called `cosca::init()`: this binary's `main` does not, so
//! `CtrlProxy::HostExecutable` would start a second copy of it that runs as itself. The send is refused
//! before anything starts.
//!
//! The proof that nothing started is the marker a copy of this binary leaves when it is started with
//! proxy arguments, in the directory the test made for it ([`MarkerDir`]); the argv is the protocol's
//! wire form, spelled out, since the protocol is crate-private.

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

/// The default proxy of a host that did not call `init` is refused with `Unsupported` naming
/// `cosca::init()`, and no process is started. Mutant: the gate is dropped, so a copy of this binary is
/// started as the proxy: it leaves its marker, and its exit (0) is no answer (`Unassessable`).
#[cfg(windows)]
#[skuld::test]
fn without_the_init_hook_the_host_is_not_started() {
    assert!(
        !cosca::installed(),
        "this binary's `main` must not call `cosca::init()`"
    );
    let (child, sock) = common::spawn_control_with("control-block", &["R"], false, |_| {});
    let markers = MarkerDir::new();

    let err = cosca::stop::send_console_event_via_proxy(&cosca::StopTarget::from(&child), cosca::CtrlEvent::CtrlBreak)
        .expect_err("the host did not call init");

    let cosca::error::Error::Unsupported { detail, .. } = &err else {
        panic!("expected Unsupported, got {err:?}");
    };
    assert!(detail.contains("cosca::init()"), "{detail}");
    assert!(!detail.contains("  "), "a run of spaces: {detail:?}");
    assert!(
        !markers.marker().exists(),
        "a copy of the host was started as the proxy"
    );
    child.kill().expect("kill the child");
    drop(sock);
}

/// The default stop of a child that does not lead its group on our console asks the proxy: in a host
/// that did not call `init` that is refused naming `cosca::init()`, with no process started, for an
/// uncontained child (which leads no group) and for a contained one with a console of its own. Mutant:
/// the default sends the direct break for either (the answer is no `Unsupported`, or does not name
/// `init`).
#[cfg(windows)]
#[skuld::test]
fn the_default_for_a_child_outside_our_group_asks_the_proxy() {
    for contain in [false, true] {
        let (child, sock) = common::spawn_control_with("control-block", &["R"], contain, |cmd| {
            cmd.no_window();
        });
        let markers = MarkerDir::new();

        let err = child.terminate().expect_err("the host did not call init");

        let cosca::error::Error::Unsupported { detail, .. } = &err else {
            panic!("contained {contain}: expected Unsupported, got {err:?}");
        };
        assert!(detail.contains("cosca::init()"), "contained {contain}: {detail}");
        assert!(
            !markers.marker().exists(),
            "contained {contain}: a copy of the host was started as the proxy"
        );
        child.kill().expect("kill the child");
        drop(sock);
    }
}

/// A child created on our console without a group (an uncontained one, a contained one given
/// `new_process_group(false)`) is the direct send's refusal in a host that did not call `init`: the default
/// needs no proxy for it, so the refusal names `Command::new_process_group` and not `cosca::init()`, and
/// no process is started. Mutant: the default takes the proxy for it (the refusal names `init`).
#[cfg(windows)]
#[skuld::test]
fn the_default_for_a_child_on_our_console_without_a_group_is_refused_without_init() {
    for contain in [false, true] {
        let (child, sock) = common::spawn_control_on_console_with("control-block", &["R"], contain, |cmd| {
            _ = cmd.new_process_group(false);
        });
        let markers = MarkerDir::new();

        let err = child.terminate().expect_err("the child leads no group");

        common::assert_refused_for_no_group(&err);
        let cosca::error::Error::Unsupported { detail, .. } = &err else {
            panic!("contained {contain}: expected Unsupported, got {err:?}");
        };
        assert!(
            !detail.contains("cosca::init()"),
            "contained {contain}: the proxy's refusal: {detail}"
        );
        assert!(
            !markers.marker().exists(),
            "contained {contain}: a copy of the host was started as the proxy"
        );
        child.kill().expect("kill the child");
        drop(sock);
    }
}

/// A child the default sends through the proxy that has exited is `Ok`, as for every other child, in a host
/// that did not call `init`: the look at its exit comes before the gate that needs `init`, so nothing is
/// refused and nothing is started. A tree call ends in the "root exited" outcome: `terminate_tree` errs with
/// nothing sent (not `Unsupported`), `graceful_shutdown_tree` goes on to its sweep and reap. Mutant: the
/// gate comes first (`Unsupported`, naming `init`).
#[cfg(windows)]
#[skuld::test]
fn an_exited_child_the_default_sends_through_the_proxy_is_answered_without_init() {
    for contain in [false, true] {
        let (child, sock) = common::spawn_control_with("control-block", &["R"], contain, |_| {});
        let markers = MarkerDir::new();
        child.kill().expect("kill the child");
        child.wait().expect("see its exit");
        drop(sock);

        child
            .terminate()
            .unwrap_or_else(|e| panic!("contained {contain}: an exited child is Ok: {e:?}"));
        if contain {
            let err = child.terminate_tree().expect_err("nothing was sent to the tree");
            assert!(
                matches!(&err, cosca::error::Error::Unassessable { detail, .. } if detail.contains("nothing was sent")),
                "{err:?}"
            );
            child
                .graceful_shutdown_tree(std::time::Duration::ZERO)
                .unwrap_or_else(|e| panic!("the call goes on to its sweep: {e:?}"));
        }
        assert!(
            !markers.marker().exists(),
            "contained {contain}: a copy of the host was started as the proxy"
        );
    }
}

#[path = "../src/test_harness.rs"]
mod test_harness;

fn main() {
    // A copy of this binary started as the proxy (only a refusal that failed to hold starts one): it
    // says so and exits 0, which is no answer of the protocol.
    #[cfg(windows)]
    {
        let args: Vec<String> = std::env::args().collect();
        if args.get(1).is_some_and(|a| a.starts_with("--cosca-ctrl-proxy")) {
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
