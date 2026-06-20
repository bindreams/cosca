use crate::command::{Command, CommandInput};
use std::ffi::OsString;
use std::path::Path;

fn argv(cmd: &Command) -> Vec<String> {
    match cmd.input() {
        CommandInput::Argv(v) => v.iter().map(|s| s.to_string_lossy().into_owned()).collect(),
        other => panic!("expected Argv, got {:?}", other),
    }
}

#[test]
fn new_is_empty() {
    let cmd = Command::new();
    assert!(matches!(cmd.input(), CommandInput::Empty));
    assert!(cmd.executable_path().is_none());
}

#[test]
fn args_sets_and_extends_argv() {
    let mut cmd = Command::new();
    cmd.args(["git", "status"]).args(["--short"]);
    assert_eq!(argv(&cmd), ["git", "status", "--short"]);
}

#[test]
fn arg_appends_one() {
    let mut cmd = Command::new();
    cmd.arg("echo").arg("hi");
    assert_eq!(argv(&cmd), ["echo", "hi"]);
}

#[test]
fn commandline_sets_string_source() {
    let mut cmd = Command::new();
    cmd.commandline(r#"git "status""#);
    match cmd.input() {
        CommandInput::CommandLine(s) => assert_eq!(s, &OsString::from(r#"git "status""#)),
        other => panic!("expected CommandLine, got {:?}", other),
    }
}

#[test]
fn commandline_then_args_switches_source_and_discards() {
    let mut cmd = Command::new();
    cmd.commandline("ignored string").args(["real", "argv"]);
    assert_eq!(argv(&cmd), ["real", "argv"]);
}

#[test]
fn args_then_commandline_switches_to_string() {
    let mut cmd = Command::new();
    cmd.args(["a", "b"]).commandline("c d");
    assert!(matches!(cmd.input(), CommandInput::CommandLine(_)));
}

#[test]
fn executable_overrides_load_path_independently_of_argv() {
    let mut cmd = Command::new();
    cmd.executable("/bin/busybox").args(["sh", "-c", "echo hi"]);
    assert_eq!(cmd.executable_path(), Some(Path::new("/bin/busybox")));
    assert_eq!(argv(&cmd), ["sh", "-c", "echo hi"]);
}
