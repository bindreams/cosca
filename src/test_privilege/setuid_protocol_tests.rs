//! Tests of the testbin's `setuid-stdin-block` protocol, run against the setuid helper.

use super::setuid::setuid_helper;
use std::io::{Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Stdio};

struct Helper {
    child: Child,
    stdin: Option<ChildStdin>,
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
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        Self { child, stdin, stdout }
    }

    /// The next byte on stdout, or `None` at EOF.
    fn byte(&mut self) -> Option<u8> {
        let mut b = [0u8; 1];
        (self.stdout.read(&mut b).expect("read the helper's stdout") == 1).then_some(b[0])
    }

    fn send(&mut self, cmd: u8) {
        self.stdin
            .as_mut()
            .expect("stdin is open")
            .write_all(&[cmd])
            .expect("write a command");
    }

    /// Sends `cmd` and closes stdin, for a command that must not be acknowledged: a helper that
    /// silently ignores it then reaches EOF and exits, instead of blocking the read that follows.
    fn send_last(&mut self, cmd: u8) {
        self.send(cmd);
        self.stdin = None;
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

    #[skuld::test]
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

    /// From every mode the caller's and root's uid are still among the current ids, so `d` then
    /// `r` succeed and are acknowledged only once the kernel shows the new triple.
    #[skuld::test]
    fn setuid_testbin_credential_commands_ack_after_their_syscall_in_every_mode() {
        let Some(helper) = setuid_helper() else { return };
        let c = caller();
        for mode in ["root", "permitted", "euid-only", "suid-only"] {
            let mut h = Helper::start(&helper, mode);
            assert_eq!(h.byte(), Some(b'+'), "mode {mode}");
            let pid = h.child.id();
            h.send(b'd');
            assert_eq!((h.byte(), proc_ids(pid)), (Some(b'D'), (c, c, 0)), "mode {mode} d");
            h.send(b'r');
            assert_eq!((h.byte(), proc_ids(pid)), (Some(b'R'), (0, 0, 0)), "mode {mode} r");
            h.send(b'd');
            assert_eq!(h.byte(), Some(b'D'), "mode {mode} d again");
            assert_eq!(h.finish(), (Some(0), String::new()), "mode {mode}");
        }
    }

    /// The new user namespace maps no uid, so a `setresuid` after `n` fails with `EINVAL`. That is
    /// the only evidence from outside that `n` created a namespace (the helper's
    /// `/proc/<pid>/ns/user` is closed to this caller), and the failed command must not be acked.
    #[skuld::test]
    fn setuid_testbin_unshare_creates_a_namespace_where_credential_commands_fail() {
        let Some(helper) = setuid_helper() else { return };
        let mut h = Helper::start(&helper, "root");
        assert_eq!(h.byte(), Some(b'+'));
        h.send(b'n');
        assert_eq!(h.byte(), Some(b'N'));
        h.send_last(b'r');
        assert_eq!(h.byte(), None, "a failed syscall was acknowledged");
        let (code, stderr) = h.finish();
        assert_eq!(code, Some(3));
        assert!(
            stderr.contains("setresuid(0, 0, 0)") && stderr.contains("Invalid argument"),
            "{stderr}"
        );
    }

    #[skuld::test]
    fn setuid_testbin_rejects_an_unknown_mode_and_command() {
        let Some(helper) = setuid_helper() else { return };
        let mut h = Helper::start(&helper, "bogus");
        assert_eq!(h.byte(), None);
        let (code, stderr) = h.finish();
        assert_eq!(code, Some(3));
        assert!(stderr.contains("unknown mode \"bogus\""), "{stderr}");
        let mut h = Helper::start(&helper, "root");
        assert_eq!(h.byte(), Some(b'+'));
        h.send_last(b'?');
        assert_eq!(h.byte(), None);
        let (code, stderr) = h.finish();
        assert_eq!(code, Some(3));
        assert!(stderr.contains("unknown command 0x3f"), "{stderr}");
    }
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn setuid_testbin_modes_reach_their_triples() {
    let Some(helper) = setuid_helper() else { return };
    let mut h = Helper::start(&helper, "root");
    assert_eq!(h.byte(), Some(b'+'), "the macOS setuid helper did not reach uid 0");
    h.send_last(b'd');
    assert_eq!(h.byte(), None, "macOS has no `d` command");
    let (code, stderr) = h.finish();
    assert_eq!(code, Some(3));
    assert!(stderr.contains("command 0x64 exists only on Linux"), "{stderr}");
    for mode in ["permitted", "euid-only", "suid-only"] {
        let mut h = Helper::start(&helper, mode);
        assert_eq!(h.byte(), None, "mode {mode} exists only on Linux");
        let (code, stderr) = h.finish();
        assert_eq!(code, Some(3), "mode {mode}");
        assert!(
            stderr.contains(&format!("mode \"{mode}\" exists only on Linux")),
            "{mode}: {stderr}"
        );
    }
}
