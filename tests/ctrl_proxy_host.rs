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
