use crate::command::{Command, CommandInput};
use crate::containment::Nesting;
use crate::stdio::{Direction, ResolvedStdio, Stdio};
use crate::{ContainMode, Fd};
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

#[test]
fn stdout_shorthand_records_resolved_pipe_out() {
    let mut cmd = Command::new();
    cmd.args(["x"]);
    cmd.stdout(Stdio::pipe()).unwrap();
    let fds = cmd.fds();
    assert!(matches!(
        fds.get(&Fd::STDOUT),
        Some(ResolvedStdio::Pipe(Direction::Out))
    ));
}

#[test]
fn stdin_pipe_infers_in() {
    let mut cmd = Command::new();
    cmd.stdin(Stdio::pipe()).unwrap();
    assert!(matches!(
        cmd.fds().get(&Fd::STDIN),
        Some(ResolvedStdio::Pipe(Direction::In))
    ));
}

#[test]
fn bare_pipe_on_fd3_errs_at_attach() {
    let mut cmd = Command::new();
    assert!(cmd.fd(3, Stdio::pipe()).is_err());
}

#[test]
fn explicit_pipe_out_on_fd3_attaches() {
    let mut cmd = Command::new();
    cmd.fd(3, Stdio::pipe_out()).unwrap();
    assert!(matches!(
        cmd.fds().get(&Fd::from(3)),
        Some(ResolvedStdio::Pipe(Direction::Out))
    ));
}

#[test]
fn kill_on_drop_defaults_true_and_toggles() {
    let mut cmd = Command::new();
    assert!(cmd.kill_on_drop_flag());
    cmd.kill_on_drop(false);
    assert!(!cmd.kill_on_drop_flag());
}

#[test]
fn fd_last_set_wins_for_same_slot() {
    let mut cmd = Command::new();
    cmd.stdout(Stdio::pipe()).unwrap();
    cmd.stdout(Stdio::null()).unwrap();
    assert!(matches!(cmd.fds().get(&Fd::STDOUT), Some(ResolvedStdio::Null)));
}

#[test]
fn inherit_resolves_through_builder() {
    let mut cmd = Command::new();
    cmd.stderr(Stdio::inherit()).unwrap();
    assert!(matches!(cmd.fds().get(&Fd::STDERR), Some(ResolvedStdio::Inherit)));
}

#[test]
fn null_resolves_through_builder() {
    let mut cmd = Command::new();
    cmd.stdin(Stdio::null()).unwrap();
    assert!(matches!(cmd.fds().get(&Fd::STDIN), Some(ResolvedStdio::Null)));
}

#[test]
fn merge_resolves_through_builder() {
    let mut cmd = Command::new();
    cmd.stderr(Stdio::merge(Fd::STDOUT)).unwrap();
    assert!(matches!(
        cmd.fds().get(&Fd::STDERR),
        Some(ResolvedStdio::Merge(Fd::STDOUT))
    ));
}

#[test]
fn env_ops_recorded_in_order() {
    use crate::command::EnvOp;
    let mut cmd = Command::new();
    cmd.env_clear();
    cmd.env("A", "1");
    cmd.env_remove("B");
    cmd.envs([("C", "3"), ("D", "4")]);
    let ops = cmd.env_ops();
    assert!(matches!(ops[0], EnvOp::Clear));
    assert!(matches!(&ops[1], EnvOp::Set(k, v) if k == "A" && v == "1"));
    assert!(matches!(&ops[2], EnvOp::Remove(k) if k == "B"));
    assert!(matches!(&ops[3], EnvOp::Set(k, v) if k == "C" && v == "3"));
    assert!(matches!(&ops[4], EnvOp::Set(k, v) if k == "D" && v == "4"));
    assert_eq!(ops.len(), 5);
}

#[test]
fn envs_empty_iterator_records_nothing() {
    let mut cmd = Command::new();
    cmd.envs::<_, &str, &str>([]);
    assert!(cmd.env_ops().is_empty());
}

#[test]
fn cwd_recorded() {
    let mut cmd = Command::new();
    cmd.current_dir("/tmp");
    assert_eq!(cmd.cwd(), Some(Path::new("/tmp")));
}

#[test]
fn contain_records_strongest_request() {
    let mut cmd = Command::new();
    cmd.contain();
    let req = cmd.contain_request();
    assert_eq!(req.mode, Some(ContainMode::Strongest));
    assert_eq!(req.nesting, Nesting::Mark);
}

#[test]
fn uncontained_by_default() {
    assert_eq!(Command::new().contain_request().mode, None);
}

#[test]
fn contain_with_and_nesting_recorded() {
    let mut cmd = Command::new();
    cmd.contain_with(ContainMode::TreeWalk).nesting(Nesting::Opaque);
    let req = cmd.contain_request();
    assert_eq!(req.mode, Some(ContainMode::TreeWalk));
    assert_eq!(req.nesting, Nesting::Opaque);
}
