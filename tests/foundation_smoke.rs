use subprocess::error::QuoteErrorKind;
use subprocess::quote::posix;
use subprocess::quote::windows;
use subprocess::Command;
use subprocess::Containment;

#[test]
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
/// report a mechanism other than `None`. The test spawns the simplest possible
/// child (`exit 0`), asserts the achieved containment, kills the tree, and
/// waits — all via the public API. The full tree-death proof lives in
/// `spawn_io.rs`; this is just the surface reachability check.
#[cfg(any(unix, windows))]
#[test]
fn containment_smoke() {
    let tb = env!("CARGO_BIN_EXE_subprocess_testbin");
    let mut cmd = subprocess::Command::new();
    cmd.executable(tb).args(["subprocess_testbin", "exit", "0"]).contain();
    let child = cmd.spawn().expect("spawn contained child");

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
    assert!(
        matches!(child.containment(), Containment::CgroupV2 | Containment::ProcessGroup),
        "Linux must use CgroupV2 or ProcessGroup, got {:?}",
        child.containment()
    );
    #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
    assert!(
        matches!(child.containment(), Containment::ProcessGroup | Containment::Session),
        "macOS/BSD must use ProcessGroup or Session, got {:?}",
        child.containment()
    );

    child.kill_tree().expect("kill_tree");
    let _ = child.wait();
}

#[test]
fn spawn_public_surface_is_usable() {
    use subprocess::{run, Stdio};
    // run([...]) -> output() captures; status code reachable.
    let out = run([env!("CARGO_BIN_EXE_subprocess_testbin"), "echo-argv", "hi"])
        .output()
        .expect("output");
    assert!(out.status.success());
    assert_eq!(out.stdout, b"hi\n");
    // The Stdio constructors are reachable from the crate root.
    let _ = Stdio::pipe();
    let _ = Stdio::null();
}
