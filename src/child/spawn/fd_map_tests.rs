use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::process::{Command, Stdio};

use super::{install, install_preserved, FdMapping};

/// A throwaway file holding `content`, rewound to its start so a child reading it from the
/// beginning sees exactly `content`.
fn file_with(content: &str) -> File {
    let mut f = tempfile::tempfile().expect("tempfile");
    f.write_all(content.as_bytes()).expect("write tempfile");
    f.seek(SeekFrom::Start(0)).expect("seek to start");
    f
}

/// Spawn `/bin/sh -c script` with `mappings` installed exactly as a real `Command::fd()` caller
/// would, and return its captured stdout as a `String`.
fn run_sh(script: &str, mappings: Vec<FdMapping>) -> String {
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c").arg(script).stdout(Stdio::piped());
    install(&mut cmd, mappings).expect("install");
    let out = cmd.output().expect("spawn /bin/sh");
    assert!(out.status.success(), "child failed: {out:?}");
    String::from_utf8(out.stdout).expect("utf8 stdout")
}

// Basic mapping =====

#[test]
fn a_simple_mapping_lands_the_parent_fd_on_the_requested_child_number() {
    let f = file_with("hello-fd5");
    let out = run_sh(
        "cat <&5",
        vec![FdMapping {
            parent_fd: f.into(),
            child_fd: 5,
        }],
    );
    assert_eq!(out, "hello-fd5");
}

#[test]
fn empty_mappings_installs_nothing_and_spawns_normally() {
    assert_eq!(run_sh("echo ok", vec![]).trim(), "ok");
}

// The "already on the right number" branch (fcntl F_SETFD only, no dup2) =====

#[test]
fn a_mapping_onto_its_own_current_number_clears_cloexec_without_dup2() {
    let f = file_with("self-mapped");
    let owned: OwnedFd = f.into();
    let raw = owned.as_raw_fd();
    let out = run_sh(
        &format!("cat <&{raw}"),
        vec![FdMapping {
            parent_fd: owned,
            child_fd: raw,
        }],
    );
    assert_eq!(out, "self-mapped");
}

// Colliding mappings: command-fds' temporary-fd shuffle =====

/// Map file A onto file B's current number and file B onto file A's — the swap that forces the
/// collision-avoiding temporary-fd shuffle (mirrors command-fds' own `swap_mappings` test).
#[test]
fn colliding_mappings_are_resolved_via_a_temporary_fd() {
    let a = file_with("AAA");
    let b = file_with("BBB");
    let a_owned: OwnedFd = a.into();
    let b_owned: OwnedFd = b.into();
    let a_raw = a_owned.as_raw_fd();
    let b_raw = b_owned.as_raw_fd();
    let out = run_sh(
        &format!("cat <&{b_raw}; cat <&{a_raw}"),
        vec![
            FdMapping {
                parent_fd: a_owned,
                child_fd: b_raw,
            },
            FdMapping {
                parent_fd: b_owned,
                child_fd: a_raw,
            },
        ],
    );
    // a's content now lives at b's old number (a -> b_raw), and vice versa.
    assert_eq!(
        out, "AAABBB",
        "the swap must deliver each file's OWN content, uncorrupted"
    );
}

/// Three-way rotation (A->B, B->C, C->A): the simple two-mapping swap above cannot catch a
/// shuffle that only handles ONE collision at a time.
#[test]
fn a_three_way_rotation_of_colliding_mappings_resolves_correctly() {
    let a = file_with("AAA");
    let b = file_with("BBB");
    let c = file_with("CCC");
    let a_owned: OwnedFd = a.into();
    let b_owned: OwnedFd = b.into();
    let c_owned: OwnedFd = c.into();
    let a_raw = a_owned.as_raw_fd();
    let b_raw = b_owned.as_raw_fd();
    let c_raw = c_owned.as_raw_fd();
    let out = run_sh(
        &format!("cat <&{a_raw}; cat <&{b_raw}; cat <&{c_raw}"),
        vec![
            FdMapping {
                parent_fd: c_owned,
                child_fd: a_raw,
            },
            FdMapping {
                parent_fd: a_owned,
                child_fd: b_raw,
            },
            FdMapping {
                parent_fd: b_owned,
                child_fd: c_raw,
            },
        ],
    );
    assert_eq!(out, "CCCAAABBB");
}

// preserved_fds equivalent =====

#[test]
fn install_preserved_clears_cloexec_so_the_fd_survives_exec() {
    let f = file_with("preserved");
    let owned: OwnedFd = f.into();
    let raw = owned.as_raw_fd();
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c").arg(format!("cat <&{raw}")).stdout(Stdio::piped());
    install_preserved(&mut cmd, vec![owned]);
    let out = cmd.output().expect("spawn");
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "preserved");
}

/// Baseline for the previous test: the identical setup MINUS `install_preserved` must NOT
/// survive exec (`std`'s `File`/`OwnedFd` is `FD_CLOEXEC` by default) — proves the previous
/// test is actually exercising the CLOEXEC-clearing code path, not passing by accident (e.g.
/// because `/bin/sh` itself happened to inherit the fd some other way).
#[test]
fn without_install_preserved_the_fd_is_closed_at_exec() {
    let f = file_with("not-preserved");
    let owned: OwnedFd = f.into();
    let raw = owned.as_raw_fd();
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg(format!("cat <&{raw} 2>/dev/null || echo CLOSED"))
        .stdout(Stdio::piped());
    let out = cmd.output().expect("spawn");
    drop(owned); // keep it alive in the parent until after spawn, exactly like a real caller
    assert_eq!(String::from_utf8(out.stdout).unwrap().trim(), "CLOSED");
}

// Parent-side checked arithmetic (I14) =====

/// `child_fd == i32::MAX` must be rejected by `install` itself, in the parent, before any
/// `pre_exec` hook is even registered — not left to overflow post-fork. No process is spawned
/// by this test at all: a bug here would either panic (debug, `+1` overflow-checked) or wrap
/// silently to a bogus negative floor (release), neither of which this test would need a real
/// child to observe.
#[test]
fn a_child_fd_of_i32_max_is_rejected_by_checked_arithmetic_before_any_syscall() {
    let f = file_with("x");
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c").arg("true");
    let err = install(
        &mut cmd,
        vec![FdMapping {
            parent_fd: f.into(),
            child_fd: i32::MAX,
        }],
    )
    .expect_err("i32::MAX must be rejected by the parent-side checked arithmetic");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

/// An out-of-range but representable child fd (e.g. one far beyond any real process' open-file
/// limit) is NOT a parent-side rejection — `install` accepts it (checked arithmetic does not
/// overflow), and the resulting spawn fails at `dup2` in the child instead, surfaced as an
/// ordinary `Err` from `Command::spawn` rather than an abort. This is the process-level I14
/// regression test; `cosca::Command::fd`-level coverage lives in `tests/spawn_io.rs`.
#[test]
fn an_out_of_range_but_representable_child_fd_fails_at_spawn_not_at_install() {
    let f = file_with("x");
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c").arg("true").stdout(Stdio::piped());
    install(
        &mut cmd,
        vec![FdMapping {
            parent_fd: f.into(),
            child_fd: 1_000_000,
        }],
    )
    .expect("1_000_000 must be accepted by install (representable, just not achievable)");
    let err = cmd
        .spawn()
        .and_then(|c| c.wait_with_output())
        .expect_err("dup2 onto an unachievable fd number must fail the spawn with an Err, not abort the child");
    // EBADF (or whatever the target OS reports for an out-of-range dup2 target) — not a crash,
    // not a hang, just a normal io::Error.
    assert!(err.raw_os_error().is_some(), "expected an OS error, got {err:?}");
}
