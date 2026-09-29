//! Controls for the fixtures in `test_child`: the assumptions a test's assertion leans on, run
//! against the fixture alone so a wrong one fails here and not as a confusing failure elsewhere.

/// [`windows_more`](super::windows_more) exits 0 when its stdin closes. Every Windows test that
/// takes a non-zero exit as proof of a kill relies on this: were it non-zero, a natural end would
/// read as a kill.
#[cfg(windows)]
#[test]
fn windows_more_exits_zero_when_its_stdin_closes() {
    let mut cmd = crate::Command::new();
    cmd.args([super::windows_more()]);
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::null()).expect("set stdout null");
    let mut child = cmd.spawn().expect("spawn");
    drop(child.stdin().expect("piped stdin"));
    let status = child.wait().expect("wait");
    assert!(
        status.success(),
        "more.com must exit 0 on stdin EOF, or a natural end reads as a kill: {status:?}"
    );
}
