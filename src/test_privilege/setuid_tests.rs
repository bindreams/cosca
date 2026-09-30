//! Unit tests for [`super::setuid`].

use super::setuid::{setuid_gate, Gate};

fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
    move |k| pairs.iter().find(|(name, _)| *name == k).map(|(_, v)| (*v).to_owned())
}

#[test]
fn setuid_gate_zero_disables_the_group() {
    assert_eq!(setuid_gate(env(&[("COSCA_TEST_SETUID", "0")])), Gate::Disabled);
}

#[test]
fn setuid_gate_zero_disables_it_even_with_consent() {
    let vars = [("COSCA_TEST_SETUID", "0"), ("COSCA_TEST_SETUID_CONSENT", "1")];
    assert_eq!(setuid_gate(env(&vars)), Gate::Disabled);
}

#[test]
#[should_panic(expected = "COSCA_TEST_SETUID_CONSENT")]
fn setuid_gate_unset_group_and_consent_panics() {
    setuid_gate(env(&[]));
}

#[test]
#[should_panic(expected = "COSCA_TEST_SETUID_CONSENT")]
fn setuid_gate_group_on_without_consent_panics() {
    setuid_gate(env(&[("COSCA_TEST_SETUID", "1")]));
}

#[test]
#[should_panic(expected = "COSCA_TEST_SETUID_CONSENT")]
fn setuid_gate_consent_other_than_one_panics() {
    setuid_gate(env(&[("COSCA_TEST_SETUID_CONSENT", "yes")]));
}

#[test]
fn setuid_gate_names_both_variables_in_the_panic() {
    let msg = std::panic::catch_unwind(|| setuid_gate(env(&[]))).unwrap_err();
    let msg = msg.downcast_ref::<String>().expect("a formatted panic message");
    assert!(
        msg.contains("COSCA_TEST_SETUID_CONSENT") && msg.contains("COSCA_TEST_SETUID=0"),
        "{msg}"
    );
}

#[test]
fn setuid_gate_consent_one_runs() {
    assert_eq!(setuid_gate(env(&[("COSCA_TEST_SETUID_CONSENT", "1")])), Gate::Run);
}

#[test]
fn setuid_gate_any_group_value_but_zero_runs_with_consent() {
    let vars = [("COSCA_TEST_SETUID", "yes"), ("COSCA_TEST_SETUID_CONSENT", "1")];
    assert_eq!(setuid_gate(env(&vars)), Gate::Run);
}

// The testbin protocol -----

use super::setuid::setuid_helper;
use std::io::{Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Stdio};

struct Helper {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
}

impl Helper {
    fn start(helper: &std::path::Path, mode: &str) -> Self {
        let mut cmd = std::process::Command::new(helper);
        cmd.args(["setuid-stdin-block", mode])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = crate::test_spawn::spawn(&mut cmd).expect("spawn the setuid helper");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        Self { child, stdin, stdout }
    }

    /// The next byte on stdout, or `None` at EOF.
    fn byte(&mut self) -> Option<u8> {
        let mut b = [0u8; 1];
        (self.stdout.read(&mut b).expect("read the helper's stdout") == 1).then_some(b[0])
    }

    fn send(&mut self, cmd: u8) {
        self.stdin.write_all(&[cmd]).expect("write a command");
    }

    /// Closes stdin and returns the exit code and stderr.
    fn finish(self) -> (Option<i32>, String) {
        let Self { child, stdin, stdout } = self;
        drop(stdin);
        drop(stdout);
        let out = child.wait_with_output().expect("wait for the helper");
        (out.status.code(), String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    /// (real, effective, saved) uid of `pid`, from the kernel.
    fn proc_ids(pid: u32) -> (u32, u32, u32) {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("read /proc status");
        let line = status.lines().find_map(|l| l.strip_prefix("Uid:")).expect("a Uid line");
        let f: Vec<u32> = line.split_whitespace().map(|n| n.parse().unwrap()).collect();
        (f[0], f[1], f[2])
    }

    fn caller() -> u32 {
        // SAFETY: `geteuid` has no preconditions.
        unsafe { libc::geteuid() }
    }

    #[test]
    fn setuid_testbin_modes_reach_their_triples() {
        let Some(helper) = setuid_helper() else { return };
        let c = caller();
        for (mode, want) in [
            ("root", (0, 0, 0)),
            ("permitted", (c, c, 0)),
            ("euid-only", (c, 0, c)),
            ("suid-only", (0, 0, c)),
        ] {
            let mut h = Helper::start(&helper, mode);
            assert_eq!(h.byte(), Some(b'+'), "mode {mode} did not report ready");
            assert_eq!(proc_ids(h.child.id()), want, "mode {mode}");
            assert_eq!(h.finish(), (Some(0), String::new()), "mode {mode}");
        }
    }

    #[test]
    fn setuid_testbin_commands_ack_after_their_syscall() {
        let Some(helper) = setuid_helper() else { return };
        let c = caller();
        let mut h = Helper::start(&helper, "root");
        assert_eq!(h.byte(), Some(b'+'));
        let pid = h.child.id();
        h.send(b'd');
        assert_eq!((h.byte(), proc_ids(pid)), (Some(b'D'), (c, c, 0)));
        h.send(b'r');
        assert_eq!((h.byte(), proc_ids(pid)), (Some(b'R'), (0, 0, 0)));
        h.send(b'n');
        assert_eq!(h.byte(), Some(b'N'));
        h.send(b'd');
        assert_eq!(h.byte(), Some(b'D'));
        // Without CAP_SETUID this fails, so nothing may be acknowledged.
        h.send(b'x');
        assert_eq!(h.byte(), None, "a failed syscall was acknowledged");
        let (code, stderr) = h.finish();
        assert_eq!(code, Some(3));
        assert!(stderr.contains("setresuid"), "{stderr}");
    }

    #[test]
    fn setuid_testbin_rejects_an_unknown_mode_and_command() {
        let Some(helper) = setuid_helper() else { return };
        let mut h = Helper::start(&helper, "bogus");
        assert_eq!(h.byte(), None);
        assert_eq!(h.finish().0, Some(3));
        let mut h = Helper::start(&helper, "root");
        assert_eq!(h.byte(), Some(b'+'));
        h.send(b'?');
        assert_eq!(h.byte(), None);
        assert_eq!(h.finish().0, Some(3));
    }
}

#[cfg(target_os = "macos")]
#[test]
fn setuid_testbin_modes_reach_their_triples() {
    let Some(helper) = setuid_helper() else { return };
    let mut h = Helper::start(&helper, "root");
    assert_eq!(h.byte(), Some(b'+'), "the macOS setuid helper did not reach uid 0");
    h.send(b'd');
    assert_eq!(h.byte(), None, "macOS has no `d` command");
    assert_eq!(h.finish().0, Some(3));
    for mode in ["permitted", "euid-only", "suid-only"] {
        let mut h = Helper::start(&helper, mode);
        assert_eq!(h.byte(), None, "mode {mode} exists only on Linux");
        assert_eq!(h.finish().0, Some(3));
    }
}

// The lane check -----

fn lane_check(helper_body: &str) -> std::process::Output {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().expect("tempdir");
    let fake = dir.path().join("helper");
    std::fs::write(&fake, format!("#!/bin/sh\n{helper_body}\n")).unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut cmd = std::process::Command::new("bash");
    cmd.arg(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/.github/scripts/setuid-lane-check.sh"
    ))
    .arg(&fake);
    crate::test_spawn::output_captured(&mut cmd).expect("run the lane check")
}

/// What the check expects a real helper to print on this OS.
#[cfg(target_os = "linux")]
const GOOD: &str = "+N";
#[cfg(not(target_os = "linux"))]
const GOOD: &str = "+";

/// A helper that does not reach uid 0 prints nothing, or the wrong thing, or exits nonzero: the
/// check must fail loudly for each, whether or not the caller is root.
#[test]
fn setuid_lane_check_rejects_a_helper_that_does_not_reach_root() {
    for (name, body) in [
        ("silent", "cat > /dev/null".to_owned()),
        ("wrong output", "cat > /dev/null; printf 'x'".to_owned()),
        ("extra output", format!("cat > /dev/null; printf '{GOOD}+'")),
        ("nonzero exit", format!("cat > /dev/null; printf '{GOOD}'; exit 3")),
    ] {
        let out = lane_check(&body);
        assert!(!out.status.success(), "{name}: the lane check passed");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("::error::setuid lane check failed"), "{name}: {stderr}");
    }
}
