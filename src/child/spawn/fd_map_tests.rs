use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

#[cfg(target_os = "macos")]
use super::install_preserved;
use super::{install, FdMapping};

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

#[cfg(target_os = "macos")]
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
#[cfg(target_os = "macos")]
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

// Very large child fds fail at spawn, not at install (I14 / M1) =====

/// `child_fd == i32::MAX` must be ACCEPTED by `install` in the parent — the old parent-side
/// checked-arithmetic floor that used to refuse it there is gone (M1 replaced the single global
/// floor with a per-mapping `F_DUPFD_CLOEXEC` search that starts at 3 and never computes
/// `i32::MAX + 1` at all) — and fails only later, in the child, at `dup2`: an ordinary `EBADF`,
/// not a parent-side refusal and not an abort.
#[test]
fn an_i32_max_child_fd_fails_at_spawn_not_at_install() {
    let f = file_with("x");
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c").arg("true").stdout(Stdio::piped());
    install(
        &mut cmd,
        vec![FdMapping {
            parent_fd: f.into(),
            child_fd: i32::MAX,
        }],
    )
    .expect("i32::MAX must be accepted by install — M1 removed the parent-side refusal");
    let err = cmd
        .spawn()
        .and_then(|c| c.wait_with_output())
        .expect_err("dup2 onto i32::MAX must fail the spawn with an Err, not abort the child");
    // EBADF (or whatever the target OS reports for an out-of-range dup2 target) — not a crash,
    // not a hang, just a normal io::Error.
    assert!(err.raw_os_error().is_some(), "expected an OS error, got {err:?}");
}

/// An out-of-range but representable child fd (e.g. one far beyond any real process' open-file
/// limit) is NOT a parent-side rejection — `install` accepts it, and the resulting spawn fails
/// at `dup2` in the child instead, surfaced as an ordinary `Err` from `Command::spawn` rather
/// than an abort. This is the process-level I14 regression test; `cosca::Command::fd`-level
/// coverage lives in `tests/spawn_io.rs`.
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

// M1: one distant child_fd must not inflate every temporary past a tight RLIMIT_NOFILE =====

/// The OLD algorithm computed ONE global temporary-fd floor from the numerically highest fd
/// anywhere in the mapping set, so a single distant `child_fd` (here 255) pushed EVERY OTHER
/// mapping's temporary-fd search above it too — even when the collision that actually needs a
/// temporary (the A/B swap below) has plenty of free numbers well below that ceiling. Under a
/// tight `RLIMIT_NOFILE` (256, so fd 255 is the highest valid number) that global floor of 256
/// is itself out of range, and the swap fails with `EINVAL` even though it could have been
/// resolved at some ordinary low number. M1's per-mapping `F_DUPFD_CLOEXEC(fd, 3)` search must
/// not have this problem: it must resolve the swap using a low temporary, independent of the
/// numerically distant 255 target.
#[test]
fn a_distant_high_target_does_not_inflate_every_other_temporary_past_a_tight_rlimit() {
    let a = file_with("AAA");
    let b = file_with("BBB");
    let c = file_with("CCC");
    let a_owned: OwnedFd = a.into();
    let b_owned: OwnedFd = b.into();
    let c_owned: OwnedFd = c.into();
    let a_raw = a_owned.as_raw_fd();
    let b_raw = b_owned.as_raw_fd();

    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg(format!("cat <&{b_raw}; cat <&{a_raw}"))
        .stdout(Stdio::piped());

    // Lower the CHILD's RLIMIT_NOFILE to 256 before `install`'s own pre_exec hook runs.
    // `pre_exec` hooks run in registration order, and `install` documents that its own hook
    // must be registered LAST — so registering this one first mirrors that same ordering
    // constraint containment hooks rely on in production.
    unsafe {
        cmd.pre_exec(|| {
            let lim = libc::rlimit {
                rlim_cur: 256,
                rlim_max: 256,
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &lim) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    install(
        &mut cmd,
        vec![
            FdMapping {
                parent_fd: a_owned,
                child_fd: b_raw,
            },
            FdMapping {
                parent_fd: b_owned,
                child_fd: a_raw,
            },
            // Numerically distant but still a valid fd under the 256 rlimit (0..255): under the
            // OLD algorithm this alone was enough to push the swap's temporary search past the
            // rlimit ceiling.
            FdMapping {
                parent_fd: c_owned,
                child_fd: 255,
            },
        ],
    )
    .expect("install");

    let out = cmd.output().expect("spawn /bin/sh");
    assert!(out.status.success(), "child failed: {out:?}");
    assert_eq!(
        out.stdout, b"AAABBB",
        "the swap must still resolve correctly even with a numerically distant child_fd \
         elsewhere in the mapping set"
    );
}

// M2: a parent_fd below fd 3 must not be clobbered by std's own stdio dup2 =====

/// Dup fd 2 aside and close the original, so the CURRENT test process's fd 2 is free for the
/// test to reuse — restoring it on drop even if the test panics. Safe because this workspace's
/// test runner (`cargo nextest`) puts every test function in its own OS process, so this cannot
/// affect any other test.
struct RestoreFd2 {
    saved: OwnedFd,
}

impl RestoreFd2 {
    fn take() -> RestoreFd2 {
        // SAFETY: F_DUPFD_CLOEXEC(2, 3) duplicates fd 2 to a fresh number >= 3, checked below.
        let saved = unsafe { libc::fcntl(2, libc::F_DUPFD_CLOEXEC, 3) };
        assert!(saved >= 0, "dup fd 2 aside before closing it");
        // SAFETY: `saved` was just returned by a successful F_DUPFD_CLOEXEC.
        let saved = unsafe { OwnedFd::from_raw_fd(saved) };
        assert_eq!(unsafe { libc::close(2) }, 0, "close the test process' fd 2");
        RestoreFd2 { saved }
    }
}

impl Drop for RestoreFd2 {
    fn drop(&mut self) {
        // SAFETY: dup2 back onto 2; `self.saved` stays valid (and is closed normally by its own
        // Drop) regardless of this call's outcome.
        unsafe {
            libc::dup2(self.saved.as_raw_fd(), 2);
        }
    }
}

/// A mapping whose parent-side source starts out sitting at fd 2 — because the current process
/// just closed its own fd 2 and the source is the next thing opened — must not be silently
/// repointed to whatever std's OWN `.stderr()` setup later `dup2`s onto fd 2 in the child. Std
/// runs that dup2 in the child BEFORE any `pre_exec` hook (including `install`'s own), so
/// without M2's parent-side relocation, `fd_map`'s later `dup2(2, 3)` would duplicate the
/// stderr pipe (now sitting at fd 2) instead of the mapping's actual source. Reproduces the bug
/// measured on tokio: `close(2)`, `stderr(pipe())` + `fd(3, null)` delivered the stderr pipe's
/// bytes through fd 3 instead of the mapping's real source.
#[test]
fn a_source_starting_below_fd_3_is_moved_before_stdio_dup2_can_clobber_it() {
    let _restore = RestoreFd2::take();
    // The next fd opened lands at 2 (just closed above by `RestoreFd2::take`) — this IS the
    // mapping's source, at the exact number the bug needs to reproduce.
    let owned: OwnedFd = file_with("fd3-token").into();
    assert_eq!(
        owned.as_raw_fd(),
        2,
        "test setup invariant: the source must land exactly at fd 2 to reproduce the bug"
    );

    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg("cat <&3 >&1; echo unrelated-stderr >&2")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    install(
        &mut cmd,
        vec![FdMapping {
            parent_fd: owned,
            child_fd: 3,
        }],
    )
    .expect("install");

    let out = cmd.output().expect("spawn /bin/sh");
    assert!(out.status.success(), "child failed: {out:?}");
    assert_eq!(
        out.stdout, b"fd3-token",
        "fd 3 in the child must deliver the mapping's OWN source, not whatever std's stdio \
         dup2 later put at the parent-side fd 2 number"
    );
    assert_eq!(
        String::from_utf8(out.stderr).unwrap().trim(),
        "unrelated-stderr",
        "the stderr pipe must carry only the child's own stderr writes, not fd 3's bytes"
    );
}
