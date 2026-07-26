use super::build_argv;
use crate::elevation::{Auth, Backend};
use std::ffi::{OsStr, OsString};

fn s(v: &[&str]) -> Vec<OsString> {
    v.iter().map(|x| OsString::from(*x)).collect()
}
fn env(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
    pairs.iter().map(|(k, v)| (OsString::from(*k), OsString::from(*v))).collect()
}

#[test]
fn sudo_noninteractive_names_env_in_preserve_env_with_terminator() {
    let argv = build_argv(
        Backend::Sudo,
        OsStr::new("/usr/bin/sudo"),
        &Auth::NonInteractive,
        OsStr::new("/usr/bin/systemctl"),
        &s(&["restart", "nginx"]),
        &env(&[("FOO", "bar")]),
    )
    .unwrap();
    assert_eq!(
        argv,
        s(&["/usr/bin/sudo", "-n", "--preserve-env=FOO", "--", "/usr/bin/systemctl", "restart", "nginx"])
    );
    // The VALUE never appears in argv (it is set in sudo's own env by the rewrite).
    assert!(!argv.iter().any(|a| a.to_string_lossy().contains("bar")));
}

#[test]
fn sudo_preserve_env_joins_multiple_names() {
    let argv = build_argv(Backend::Sudo, OsStr::new("/usr/bin/sudo"), &Auth::NonInteractive, OsStr::new("id"), &[], &env(&[("A", "1"), ("B", "2")])).unwrap();
    assert_eq!(argv, s(&["/usr/bin/sudo", "-n", "--preserve-env=A,B", "--", "id"]));
}

#[test]
fn sudo_interactive_no_env_has_no_flags() {
    let argv = build_argv(Backend::Sudo, OsStr::new("/usr/bin/sudo"), &Auth::Interactive, OsStr::new("id"), &s(&["-u"]), &[]).unwrap();
    assert_eq!(argv, s(&["/usr/bin/sudo", "--", "id", "-u"]));
}

#[test]
fn sudo_stdin_uses_dash_s() {
    let argv = build_argv(Backend::Sudo, OsStr::new("/usr/bin/sudo"), &Auth::Stdin(crate::elevation::Secret::new("pw")), OsStr::new("id"), &[], &[]).unwrap();
    assert_eq!(argv, s(&["/usr/bin/sudo", "-S", "--", "id"]));
}

#[test]
fn sudo_askpass_uses_dash_a() {
    let argv = build_argv(Backend::Sudo, OsStr::new("/usr/bin/sudo"), &Auth::Askpass("/usr/bin/ssh-askpass".into()), OsStr::new("id"), &[], &[]).unwrap();
    assert_eq!(argv, s(&["/usr/bin/sudo", "-A", "--", "id"]));
}

#[test]
fn sudo_rejects_an_unforwardable_env_name() {
    for bad in [("A,B", "1"), ("A=C", "1"), ("PÄTH", "1"), ("", "1"), ("1BAD", "1")] {
        let r = build_argv(Backend::Sudo, OsStr::new("/usr/bin/sudo"), &Auth::NonInteractive, OsStr::new("id"), &[], &env(&[bad]));
        assert!(matches!(r, Err(crate::error::Error::Unsupported { .. })), "expected reject for {bad:?}");
    }
}

#[test]
fn doas_noninteractive_no_env_emits_dash_n() {
    let argv = build_argv(Backend::Doas, OsStr::new("/usr/bin/doas"), &Auth::NonInteractive, OsStr::new("id"), &s(&["-u"]), &[]).unwrap();
    assert_eq!(argv, s(&["/usr/bin/doas", "-n", "--", "id", "-u"]));
}

#[test]
fn run0_forces_pipe_and_forwards_env_via_setenv() {
    let argv = build_argv(Backend::Run0, OsStr::new("/usr/bin/run0"), &Auth::NonInteractive, OsStr::new("id"), &[], &env(&[("A", "1"), ("B", "2")])).unwrap();
    assert_eq!(argv, s(&["/usr/bin/run0", "--pipe", "--no-ask-password", "--setenv=A=1", "--setenv=B=2", "--", "id"]));
}

#[test]
fn run0_rejects_an_unforwardable_env_name() {
    let r = build_argv(Backend::Run0, OsStr::new("/usr/bin/run0"), &Auth::NonInteractive, OsStr::new("id"), &[], &env(&[("A=B", "1")]));
    assert!(matches!(r, Err(crate::error::Error::Unsupported { .. })));
}

#[test]
fn pkexec_gui_disables_internal_agent_and_uses_no_terminator() {
    // No `--` for pkexec (its option loop mis-parses it); --disable-internal-agent pins
    // the graphical-only contract.
    let argv = build_argv(Backend::Pkexec, OsStr::new("/usr/bin/pkexec"), &Auth::Gui, OsStr::new("id"), &[], &[]).unwrap();
    assert_eq!(argv, s(&["/usr/bin/pkexec", "--disable-internal-agent", "id"]));
    assert!(!argv.iter().any(|a| a == &OsString::from("--")), "pkexec must not emit a -- terminator");
}

#[test]
fn pkexec_rejects_a_leading_dash_program() {
    // With no `--` shield, a leading-dash program would be mis-parsed as a pkexec option.
    let r = build_argv(Backend::Pkexec, OsStr::new("/usr/bin/pkexec"), &Auth::Gui, OsStr::new("-prog"), &[], &[]);
    assert!(matches!(r, Err(crate::error::Error::Unsupported { .. })));
    // An `=` in the program path is safe under pkexec (no assignment parsing).
    let ok = build_argv(Backend::Pkexec, OsStr::new("/usr/bin/pkexec"), &Auth::Gui, OsStr::new("/opt/we=ird"), &[], &[]).unwrap();
    assert_eq!(ok, s(&["/usr/bin/pkexec", "--disable-internal-agent", "/opt/we=ird"]));
}

#[test]
fn terminator_protects_a_program_with_equals_or_leading_dash() {
    let eq = build_argv(Backend::Sudo, OsStr::new("/usr/bin/sudo"), &Auth::NonInteractive, OsStr::new("/opt/we=ird"), &[], &[]).unwrap();
    assert_eq!(eq, s(&["/usr/bin/sudo", "-n", "--", "/opt/we=ird"]));
    let dash = build_argv(Backend::Doas, OsStr::new("/usr/bin/doas"), &Auth::Interactive, OsStr::new("-prog"), &[], &[]).unwrap();
    assert_eq!(dash, s(&["/usr/bin/doas", "--", "-prog"]));
}

#[cfg(unix)]
#[test]
fn resolve_in_path_var_finds_an_executable_in_a_temp_dir() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("sudo");
    std::fs::write(&f, b"#!/bin/sh\ntrue\n").unwrap();
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
    let got = super::resolve_in_path_var(dir.path().as_os_str(), "sudo");
    assert_eq!(got, Some(f));
}

#[cfg(unix)]
#[test]
fn resolve_skips_a_non_executable_same_named_file() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("sudo");
    std::fs::write(&f, b"not exec").unwrap(); // mode 0644 — no exec bit
    let got = super::resolve_in_path_var(dir.path().as_os_str(), "sudo");
    assert_eq!(got, None, "a non-executable file named sudo must be skipped");
}

#[cfg(unix)]
#[test]
fn empty_path_element_is_not_resolved_from_cwd() {
    // `resolve_in_path_var` is PURE (it takes the PATH string as a parameter), so
    // this is tested directly against explicit PATH values — no process-global
    // chdir, and thus no cross-test race and no leaked CWD on a mid-test panic.

    // A single empty PATH element must be skipped, never treated as "." (CWD).
    assert_eq!(super::resolve_in_path_var(OsStr::new(""), "sudo"), None);

    // A mid-string empty element is skipped too: put a non-matching dir, then the
    // empty element, then the real match — so the empty branch is actually exercised
    // (matching in an earlier element would let a skip bug pass silently).
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let sudo = dir.path().join("sudo");
    std::fs::write(&sudo, b"#!/bin/sh\ntrue\n").unwrap();
    std::fs::set_permissions(&sudo, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path_var = format!("/nonexistent::{}", dir.path().display());
    let got = super::resolve_in_path_var(OsStr::new(&path_var), "sudo");
    assert_eq!(got, Some(sudo), "a mid-string empty PATH element must be skipped, not resolved");

    // A PATH consisting only of empty elements resolves nothing.
    assert_eq!(super::resolve_in_path_var(OsStr::new(":"), "sudo"), None);
}
