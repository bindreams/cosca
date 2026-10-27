use cosca::error::QuoteErrorKind;
use cosca::quote::posix;
use cosca::quote::windows;
use cosca::Command;
use cosca::Containment;

#[skuld::test]
fn public_surface_is_usable() {
    // POSIX round-trip via the public path.
    let args: Vec<&[u8]> = vec![b"echo", b"a b"];
    let line = posix::join(&args);
    assert_eq!(posix::split(&line).unwrap(), vec![b"echo".to_vec(), b"a b".to_vec()]);

    // POSIX error surfaced publicly.
    assert_eq!(
        posix::split(b"x\\").unwrap_err().kind,
        QuoteErrorKind::TrailingBackslash
    );

    // Windows join + first-token via the public path.
    let wides: Vec<Vec<u16>> = ["a b", "c"].iter().map(|s| s.encode_utf16().collect()).collect();
    let refs: Vec<&[u16]> = wides.iter().map(|v| v.as_slice()).collect();
    let joined = windows::join_wide(&refs);
    assert_eq!(String::from_utf16(&joined).unwrap(), "\"a b\" c");
    let ft = windows::first_token_wide(&"prog x".encode_utf16().collect::<Vec<_>>()).unwrap();
    assert_eq!(String::from_utf16(&ft).unwrap(), "prog");

    // Command builder is constructible from the crate root.
    let mut cmd = Command::new();
    cmd.args(["ls", "-la"]);
    let _ = cmd; // input model exercised in unit tests
}

/// Containment public-surface smoke: `.contain()` on a supported host must
/// report a mechanism other than `None`. The test spawns a child that blocks on a piped stdin
/// it holds, asserts the achieved containment, kills the tree and waits — all via the public API.
/// The child leaves with status 0 once stdin is released, so a `kill_tree` that sends nothing
/// fails the final assertion instead of hanging the wait. The full tree-death proof lives in
/// `spawn_io.rs`; this is just the surface reachability check.
///
/// Mutant: `kill_tree` is a no-op.
#[cfg(any(unix, windows))]
#[skuld::test]
fn containment_smoke() {
    let _warns = common::warn_watch();
    let tb = env!("CARGO_BIN_EXE_cosca_testbin");
    let mut cmd = cosca::Command::new();
    cmd.executable(tb)
        .args(["cosca_testbin", "read-fd", "0"])
        .stdin(cosca::Stdio::pipe())
        .unwrap()
        .stdout(cosca::Stdio::null())
        .unwrap();
    // On Linux this asks for a session, not `.contain()`'s cgroup leaf, which warns where none is
    // delegated; the live cgroup mechanism is covered in the `cgroup` group (`spawn_io`).
    common::contain_without_cgroup(&mut cmd);
    let mut child = cmd.spawn().expect("spawn contained child");
    let stdin = child.stdin().expect("piped stdin");

    // On every supported host (Unix + Windows) the strongest mechanism must
    // not be None.
    assert_ne!(
        child.containment(),
        Containment::None,
        "contain() must use a real mechanism on this platform, got None"
    );

    // Per-OS assertions on the specific mechanism.
    #[cfg(windows)]
    assert_eq!(child.containment(), Containment::JobObject);
    #[cfg(target_os = "linux")]
    assert_eq!(child.containment(), Containment::Session);
    #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
    assert!(
        matches!(
            child.containment(),
            Containment::ProcessGroup | Containment::Session | Containment::FdMarker
        ),
        "macOS/BSD must use ProcessGroup, Session or FdMarker, got {:?}",
        child.containment()
    );

    child.kill_tree().expect("kill_tree");
    drop(stdin);
    let status = child.wait().expect("reap");
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "kill_tree must SIGKILL the child: {status:?}"
        );
    }
    #[cfg(windows)]
    assert_eq!(
        status.code(),
        Some(1),
        "kill_tree must kill the child (exit code 1): {status:?}"
    );
}

#[skuld::test]
fn spawn_public_surface_is_usable() {
    use cosca::{run, Stdio};
    // run([...]) -> output() captures; status code reachable.
    let out = run([env!("CARGO_BIN_EXE_cosca_testbin"), "echo-argv", "hi"])
        .output()
        .expect("output");
    assert!(out.status.success());
    assert_eq!(out.stdout, b"hi\n");
    // The Stdio constructors are reachable from the crate root.
    let _ = Stdio::pipe();
    let _ = Stdio::null();
}

#[path = "common/mod.rs"]
mod common;

#[path = "../src/test_harness.rs"]
mod test_harness;

fn main() {
    common::install_log_capture();
    let mut runner = skuld::TestRunner::new();
    runner.libtest_names();
    runner.require_known_labels();
    runner.run()
}

/// Spike probe: the self dev-dependency turns `__test_hooks` on for this binary, and the testbin
/// built in the same invocation shares that build of the lib.
#[skuld::test]
fn test_hooks_reach_the_integration_test_and_the_testbin() {
    assert!(cosca::audit::enabled(), "__test_hooks is off in this tests/ binary");
    let status =
        common::status_locked(std::process::Command::new(env!("CARGO_BIN_EXE_cosca_testbin")).arg("audit-enabled"))
            .expect("run the testbin");
    assert!(status.success(), "__test_hooks is off in the testbin: {status}");
}
