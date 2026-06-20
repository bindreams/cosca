use subprocess::error::QuoteErrorKind;
use subprocess::quote::posix;
use subprocess::quote::windows;
use subprocess::Command;

#[test]
fn public_surface_is_usable() {
    // POSIX round-trip via the public path.
    let args: Vec<&[u8]> = vec![b"echo", b"a b"];
    let line = posix::join(&args);
    assert_eq!(posix::split(&line).unwrap(), vec![b"echo".to_vec(), b"a b".to_vec()]);

    // POSIX error surfaced publicly.
    assert_eq!(posix::split(b"x\\").unwrap_err().kind, QuoteErrorKind::TrailingBackslash);

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
