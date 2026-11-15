//! Runtime-chosen fds can be >= 10. `/bin/sh` on Debian/Ubuntu is dash, whose `<&N` parses only a
//! single digit and fails with "Bad fd number" past 9 — so reads go through `/dev/fd/N`
//! (`read_fd`).

use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::Read;
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
#[cfg(not(target_os = "linux"))]
use std::os::unix::process::CommandExt;
#[cfg(not(target_os = "linux"))]
use std::process::{Command, Stdio};

use super::{install, FdMapping};
#[cfg(not(target_os = "linux"))]
use crate::child::spawn::in_child::register_alone;
use crate::child::spawn::in_child::InChild;
use crate::test_own_process::{own_process, test_path};
#[cfg(not(target_os = "linux"))]
use crate::test_spawn::spawn;
use crate::test_stdio::RestoreStdio;

/// A throwaway file holding `content`, rewound to its start so a child reading it from the
/// beginning sees exactly `content`.
fn file_with(content: &str) -> File {
    let mut f = tempfile::tempfile().expect("tempfile");
    f.write_all(content.as_bytes()).expect("write tempfile");
    f.seek(SeekFrom::Start(0)).expect("seek to start");
    f
}

/// `install` on `cmd`, as the only step of its hook.
#[cfg(not(target_os = "linux"))]
fn install_on(cmd: &mut Command, mappings: Vec<FdMapping>) -> std::io::Result<()> {
    register_alone(cmd, |steps| install(steps, mappings))
}

/// Spawn `/bin/sh -c script` with `mappings` installed exactly as a real `Command::fd()` caller
/// would, and return its captured stdout as a `String`.
#[cfg(not(target_os = "linux"))]
fn run_sh(script: &str, mappings: Vec<FdMapping>) -> String {
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c").arg(script).stdout(Stdio::piped());
    install_on(&mut cmd, mappings).expect("install");
    let out = crate::test_spawn::output_captured(&mut cmd).expect("spawn /bin/sh");
    assert!(out.status.success(), "child failed: {out:?}");
    String::from_utf8(out.stdout).expect("utf8 stdout")
}

/// Spawn `/bin/sh -c script` through the ordinary spawn's entry with `mappings` installed exactly as a real
/// `Command::fd()` caller would, and return its captured stdout as a `String`.
#[cfg(target_os = "linux")]
fn run_sh(script: &str, mappings: Vec<FdMapping>) -> String {
    let (mut stdout_read, mut steps) = sh_steps(mappings);
    let started = crate::child::spawn::in_child::spawn_sh(script, &mut steps).expect("spawn /bin/sh");
    // The parent's copy of the stdout pipe's write end: it reads EOF once the child is done with its own.
    drop(steps);
    let mut stdout = String::new();
    stdout_read.read_to_string(&mut stdout).expect("read the stdout");
    assert_eq!(
        crate::child::spawn::in_child::exit_code(&started),
        Some(0),
        "child failed"
    );
    stdout
}

/// The steps of a child whose stdout is a pipe (its read end is returned) and whose fds are `mappings`.
#[cfg(target_os = "linux")]
fn sh_steps(mappings: Vec<FdMapping>) -> (std::io::PipeReader, InChild) {
    let (stdout_read, stdout_write) = std::io::pipe().expect("pipe");
    let mut steps = InChild::default();
    steps.map_stdio(super::Plan::stdio(vec![FdMapping {
        parent_fd: OwnedFd::from(stdout_write),
        child_fd: 1,
    }]));
    install(&mut steps, mappings).expect("install");
    (stdout_read, steps)
}

/// A shell snippet that reads `fd` via `/dev/fd/N`, never via `<&N` (see the module docs).
fn read_fd(fd: RawFd) -> String {
    format!("cat /dev/fd/{fd}")
}

// Basic mapping =====

#[skuld::test]
fn a_simple_mapping_lands_the_parent_fd_on_the_requested_child_number() {
    let f = file_with("hello-fd5");
    let out = run_sh(
        &read_fd(5),
        vec![FdMapping {
            parent_fd: f.into(),
            child_fd: 5,
        }],
    );
    assert_eq!(out, "hello-fd5");
}

#[skuld::test]
fn empty_mappings_installs_nothing_and_spawns_normally() {
    assert_eq!(run_sh("echo ok", vec![]).trim(), "ok");
}

// The "already on the right number" branch: CLOEXEC cleared in place, fd survives exec =====

#[skuld::test]
fn a_mapping_onto_its_own_current_number_clears_cloexec_so_the_fd_survives_exec() {
    let f = file_with("self-mapped");
    let owned: OwnedFd = f.into();
    let raw = owned.as_raw_fd();
    let out = run_sh(
        &read_fd(raw),
        vec![FdMapping {
            parent_fd: owned,
            child_fd: raw,
        }],
    );
    assert_eq!(out, "self-mapped");
}

// Colliding mappings deliver each file's own content =====

/// Map file A onto file B's current number and file B onto file A's — the swap that, internally,
/// forces a collision-avoiding temporary-fd shuffle (mirrors command-fds' own `swap_mappings`
/// test). This only checks the externally visible outcome (each file's own content, uncorrupted);
/// it does not observe the shuffle itself, since any mechanism that resolves the collision without
/// corrupting either file's content would pass it too.
#[skuld::test]
fn colliding_mappings_deliver_each_files_own_content() {
    let a = file_with("AAA");
    let b = file_with("BBB");
    let a_owned: OwnedFd = a.into();
    let b_owned: OwnedFd = b.into();
    let a_raw = a_owned.as_raw_fd();
    let b_raw = b_owned.as_raw_fd();
    let out = run_sh(
        &format!("{}; {}", read_fd(b_raw), read_fd(a_raw)),
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
#[skuld::test]
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
        &format!("{}; {}; {}", read_fd(a_raw), read_fd(b_raw), read_fd(c_raw)),
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

// A duplicate child fd is rejected in every build profile =====

/// Two mappings that both target `child_fd: 5` must be rejected by `install` itself, as an
/// ordinary `io::Error`, in a RELEASE build exactly as reliably as in a debug build. Both
/// production callers build their mapping set from a `BTreeMap<Fd, _>`, whose keys are already
/// unique, so this is unreachable from them — but `install` takes a plain `Vec<FdMapping>`, and
/// nothing about that signature stops some OTHER caller (present or future) from handing it a
/// duplicate. A check that only fires via `debug_assert!` protects debug builds and nothing else:
/// in release, `Plan::apply`'s pass 2 would dup2 both mappings onto fd 5 in order, so the second
/// mapping's source silently wins and the first is silently misrouted with no error and no crash
/// — a strictly weaker disposition than an explicit `Err`.
#[skuld::test]
fn install_rejects_a_duplicate_child_fd_in_every_build_profile() {
    let a = file_with("A");
    let b = file_with("B");
    let err = install(
        &mut InChild::default(),
        vec![
            FdMapping {
                parent_fd: a.into(),
                child_fd: 5,
            },
            FdMapping {
                parent_fd: b.into(),
                child_fd: 5,
            },
        ],
    )
    .expect_err("a duplicate child fd must be rejected by install itself, in every build profile");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::InvalidInput,
        "expected InvalidInput (mirrors Command::fd's own negative-fd rejection), got {err:?}"
    );
}

// preserved_fds equivalent =====

#[cfg(target_os = "macos")]
#[skuld::test]
fn preserve_clears_cloexec_so_the_fd_survives_exec() {
    let f = file_with("preserved");
    let owned: OwnedFd = f.into();
    let raw = owned.as_raw_fd();
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c").arg(read_fd(raw)).stdout(Stdio::piped());
    register_alone(&mut cmd, |steps| steps.preserve(owned));
    let out = crate::test_spawn::output_captured(&mut cmd).expect("spawn");
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "preserved");
}

/// Baseline for the previous test: the identical setup MINUS the preserve step must NOT
/// survive exec (`std`'s `File`/`OwnedFd` is `FD_CLOEXEC` by default) — proves the previous
/// test is actually exercising the CLOEXEC-clearing code path, not passing by accident (e.g.
/// because `/bin/sh` itself happened to inherit the fd some other way).
#[cfg(target_os = "macos")]
#[skuld::test]
fn without_preserve_the_fd_is_closed_at_exec() {
    let f = file_with("not-preserved");
    let owned: OwnedFd = f.into();
    let raw = owned.as_raw_fd();
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg(format!("{} 2>/dev/null || echo CLOSED", read_fd(raw)))
        .stdout(Stdio::piped());
    let out = crate::test_spawn::output_captured(&mut cmd).expect("spawn");
    drop(owned); // keep it alive in the parent until after spawn, exactly like a real caller
    assert_eq!(String::from_utf8(out.stdout).unwrap().trim(), "CLOSED");
}

// Very large child fds fail at spawn, not at install =====

/// `child_fd == i32::MAX` must be ACCEPTED by `install` in the parent — its per-mapping
/// `F_DUPFD_CLOEXEC` search starts at 3 and never computes `i32::MAX + 1` at all — and fails only
/// later, in the child, at `dup2`: an ordinary `EBADF`, not a parent-side refusal and not an
/// abort.
#[skuld::test]
fn an_i32_max_child_fd_fails_at_spawn_not_at_install() {
    let f = file_with("x");
    let mapping = vec![FdMapping {
        parent_fd: f.into(),
        child_fd: i32::MAX,
    }];
    #[cfg(not(target_os = "linux"))]
    let err = {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg("true").stdout(Stdio::piped());
        install_on(&mut cmd, mapping).expect("i32::MAX must be accepted by install");
        crate::test_spawn::spawn(&mut cmd)
            .and_then(|c| c.wait_with_output())
            .expect_err("dup2 onto i32::MAX must fail the spawn with an Err, not abort the child")
    };
    #[cfg(target_os = "linux")]
    let err = failed_spawn_of_true(mapping);
    // EBADF (or whatever the target OS reports for an out-of-range dup2 target) — not a crash,
    // not a hang, just a normal io::Error.
    assert!(err.raw_os_error().is_some(), "expected an OS error, got {err:?}");
}

/// The error of the spawn of `true` with `mappings` installed, which must fail.
#[cfg(target_os = "linux")]
fn failed_spawn_of_true(mappings: Vec<FdMapping>) -> std::io::Error {
    let (_stdout, mut steps) = sh_steps(mappings);
    match crate::child::spawn::in_child::spawn_sh("true", &mut steps) {
        Err(err) => err,
        Ok(started) => panic!("the spawn succeeded (child {})", started.pid),
    }
}

/// Lowers this process's soft `RLIMIT_NOFILE` to 256, which its children inherit: the limit the tests below
/// need for the child's `dup2`s. For a process of the test's own, which the `Completion` witnesses.
#[cfg(target_os = "linux")]
fn lower_the_limit_to_256(_own_process: &crate::test_own_process::Completion) {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: reads and lowers this process's own limit, which only this process's own test uses.
    unsafe {
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit), 0);
        limit.rlim_cur = 256;
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &limit), 0, "lower the limit");
    }
}

/// An out-of-range but representable child fd (e.g. one far beyond any real process' open-file
/// limit) is NOT a parent-side rejection — `install` accepts it, and the resulting spawn fails
/// at `dup2` in the child instead, surfaced as an ordinary `Err` from `Command::spawn` rather
/// than an abort. This is the process-level regression test; `cosca::Command::fd`-level coverage
/// lives in `tests/spawn_io.rs`.
///
/// Lowers the `RLIMIT_NOFILE` of the CHILD to 256, so `1_000_000` is guaranteed out of range for THIS
/// spawn regardless of the host's own ambient `ulimit -n`. Without it, this would depend on the
/// runner: on Linux, a soft limit raised past `1_000_000` is entirely ordinary (see
/// `tests/common::RestoreRlimitNofile`'s doc), so the same `dup2` this test expects to fail could
/// instead succeed. On macOS a `pre_exec` hook registered BEFORE `install`'s does it; on Linux, which
/// has no hook, the test's own process does (the child inherits the limit).
#[skuld::test]
fn an_out_of_range_but_representable_child_fd_fails_at_spawn_not_at_install() {
    #[cfg(target_os = "linux")]
    {
        let Some(done) = own_process(
            test_path!(an_out_of_range_but_representable_child_fd_fails_at_spawn_not_at_install),
            crate::test_spawn::spawn,
        ) else {
            return;
        };
        lower_the_limit_to_256(&done);
        let mapping = vec![FdMapping {
            parent_fd: file_with("x").into(),
            child_fd: 1_000_000,
        }];
        let err = failed_spawn_of_true(mapping);
        assert!(err.raw_os_error().is_some(), "expected an OS error, got {err:?}");
    }
    #[cfg(not(target_os = "linux"))]
    {
        let f = file_with("x");
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg("true").stdout(Stdio::piped());

        // SAFETY: `pre_exec` runs post-fork, pre-exec, in the child only; `setrlimit` is a checked,
        // non-allocating raw syscall. Registered first so it runs before the fd map's hook.
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

        install_on(
            &mut cmd,
            vec![FdMapping {
                parent_fd: f.into(),
                child_fd: 1_000_000,
            }],
        )
        .expect("1_000_000 must be accepted by install (representable, just not achievable)");
        let err = crate::test_spawn::spawn(&mut cmd)
            .and_then(|c| c.wait_with_output())
            .expect_err("dup2 onto an unachievable fd number must fail the spawn with an Err, not abort the child");
        // EBADF (or whatever the target OS reports for an out-of-range dup2 target) — not a crash,
        // not a hang, just a normal io::Error.
        assert!(err.raw_os_error().is_some(), "expected an OS error, got {err:?}");
    }
}

// One distant child_fd must not inflate every temporary past a tight RLIMIT_NOFILE =====

/// A single distant `child_fd` (here 255) must not push every OTHER mapping's temporary-fd
/// search above it too — even when the collision that actually needs a temporary (the A/B swap
/// below) has plenty of free numbers well below that ceiling. Under a tight `RLIMIT_NOFILE` (256,
/// so fd 255 is the highest valid number), this module's per-mapping `F_DUPFD_CLOEXEC(fd, 3)`
/// search must resolve the swap using a low temporary, independent of the numerically distant
/// 255 target.
#[skuld::test]
fn a_distant_high_target_does_not_inflate_every_other_temporary_past_a_tight_rlimit() {
    // On Linux, which has no hook for the child's limit, the test's own process lowers it: the child
    // inherits it.
    #[cfg(target_os = "linux")]
    let Some(done) = own_process(
        test_path!(a_distant_high_target_does_not_inflate_every_other_temporary_past_a_tight_rlimit),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let a = file_with("AAA");
    let b = file_with("BBB");
    let c = file_with("CCC");
    let a_owned: OwnedFd = a.into();
    let b_owned: OwnedFd = b.into();
    let c_owned: OwnedFd = c.into();
    let a_raw = a_owned.as_raw_fd();
    let b_raw = b_owned.as_raw_fd();
    let script = format!("{}; {}", read_fd(b_raw), read_fd(a_raw));
    let mappings = vec![
        FdMapping {
            parent_fd: a_owned,
            child_fd: b_raw,
        },
        FdMapping {
            parent_fd: b_owned,
            child_fd: a_raw,
        },
        // Numerically distant but still a valid fd under the 256 rlimit (0..255) — must not push
        // the swap's temporary search past the rlimit ceiling.
        FdMapping {
            parent_fd: c_owned,
            child_fd: 255,
        },
    ];

    #[cfg(target_os = "linux")]
    let stdout = {
        lower_the_limit_to_256(&done);
        run_sh(&script, mappings).into_bytes()
    };
    #[cfg(not(target_os = "linux"))]
    let stdout = {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg(script).stdout(Stdio::piped());

        // Lower the CHILD's RLIMIT_NOFILE to 256 before the fd map's hook runs. `pre_exec` hooks run
        // in registration order, and the fd map's step runs last — so registering this one first
        // mirrors the order containment steps rely on in production.
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
        install_on(&mut cmd, mappings).expect("install");
        let out = crate::test_spawn::output_captured(&mut cmd).expect("spawn /bin/sh");
        assert!(out.status.success(), "child failed: {out:?}");
        out.stdout
    };
    assert_eq!(
        stdout, b"AAABBB",
        "the swap must still resolve correctly even with a numerically distant child_fd \
         elsewhere in the mapping set"
    );
}

// A parent_fd below fd 3 must not be clobbered by std's own stdio dup2 =====

/// A mapping whose parent-side source starts out sitting at fd 2 — because the current process
/// just closed its own fd 2 and the source is the next thing opened — must not be silently
/// repointed to whatever std's OWN `.stderr()` setup later `dup2`s onto fd 2 in the child. Std
/// runs that dup2 in the child BEFORE any `pre_exec` hook (including `install`'s own), so
/// without a parent-side relocation, `fd_map`'s later `dup2(2, 3)` would duplicate the stderr
/// pipe (now sitting at fd 2) instead of the mapping's actual source. Reproduces the bug measured
/// on tokio: `close(2)`, `stderr(pipe())` + `fd(3, null)` delivered the stderr pipe's bytes
/// through fd 3 instead of the mapping's real source.
#[cfg(not(target_os = "linux"))]
#[skuld::test]
fn a_source_starting_below_fd_3_is_moved_before_stdio_dup2_can_clobber_it() {
    let Some(done) = own_process(
        test_path!(a_source_starting_below_fd_3_is_moved_before_stdio_dup2_can_clobber_it),
        spawn,
    ) else {
        return;
    };
    let _restore = RestoreStdio::close(&done, &[2]);
    // The next fd opened lands at 2 (just closed above by `RestoreStdio::close`) — this IS the
    // mapping's source, at the exact number the bug needs to reproduce.
    let owned: OwnedFd = file_with("fd3-token").into();
    assert_eq!(
        owned.as_raw_fd(),
        2,
        "test setup invariant: the source must land exactly at fd 2 to reproduce the bug"
    );

    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg(format!(
            // Without the relocation fd 3 is the stderr pipe, and `cat` on it would block on its own writer.
            "if test -f /dev/fd/3; then {} >&1; else printf %s fd3-is-not-a-regular-file; fi; echo unrelated-stderr >&2",
            read_fd(3)
        ))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    install_on(
        &mut cmd,
        vec![FdMapping {
            parent_fd: owned,
            child_fd: 3,
        }],
    )
    .expect("install");

    let out = crate::test_spawn::output_captured(&mut cmd).expect("spawn /bin/sh");
    assert!(out.status.success(), "child failed: {out:?}");
    assert_ne!(
        out.stdout, b"fd3-is-not-a-regular-file",
        "fd 3 in the child is not a regular file: the relocation is missing and fd 3 is the stderr pipe"
    );
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

/// The same hazard on Linux, where the child's own steps `dup2` its stdio onto 0 to 2 (a plan of their
/// own) before the fd map's: a source that starts out at fd 2 must not be repointed to the stderr
/// pipe the stdio plan puts there.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_source_starting_below_fd_3_is_moved_before_the_stdio_plan_can_clobber_it() {
    let Some(done) = own_process(
        test_path!(a_source_starting_below_fd_3_is_moved_before_the_stdio_plan_can_clobber_it),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let _restore = RestoreStdio::close(&done, &[2]);
    // The next fd opened lands at 2 (just closed above by `RestoreStdio::close`) — this IS the
    // mapping's source, at the exact number the bug needs to reproduce.
    let owned: OwnedFd = file_with("fd3-token").into();
    assert_eq!(
        owned.as_raw_fd(),
        2,
        "test setup invariant: the source must land exactly at fd 2 to reproduce the bug"
    );
    let (mut stdout_read, stdout_write) = std::io::pipe().expect("pipe");
    let (mut stderr_read, stderr_write) = std::io::pipe().expect("pipe");
    let mut steps = InChild::default();
    steps.map_stdio(super::Plan::stdio(vec![
        FdMapping {
            parent_fd: OwnedFd::from(stdout_write),
            child_fd: 1,
        },
        FdMapping {
            parent_fd: OwnedFd::from(stderr_write),
            child_fd: 2,
        },
    ]));
    install(
        &mut steps,
        vec![FdMapping {
            parent_fd: owned,
            child_fd: 3,
        }],
    )
    .expect("install");

    let script = format!(
        // Without the relocation fd 3 is the stderr pipe, and `cat` on it would block on its own writer.
        "if test -f /dev/fd/3; then {} >&1; else printf %s fd3-is-not-a-regular-file; fi; echo unrelated-stderr >&2",
        read_fd(3)
    );
    let started = crate::child::spawn::in_child::spawn_sh(&script, &mut steps).expect("spawn /bin/sh");
    drop(steps);
    let (mut stdout, mut stderr) = (String::new(), String::new());
    stdout_read.read_to_string(&mut stdout).expect("read the stdout");
    stderr_read.read_to_string(&mut stderr).expect("read the stderr");
    assert_eq!(
        crate::child::spawn::in_child::exit_code(&started),
        Some(0),
        "child failed"
    );
    assert_ne!(
        stdout, "fd3-is-not-a-regular-file",
        "fd 3 in the child is not a regular file: the relocation is missing and fd 3 is the stderr pipe"
    );
    assert_eq!(
        stdout, "fd3-token",
        "fd 3 in the child must deliver the mapping's OWN source, not whatever the stdio plan later put \
         at the parent-side fd 2 number"
    );
    assert_eq!(
        stderr.trim(),
        "unrelated-stderr",
        "the stderr pipe must carry only the child's own stderr writes, not fd 3's bytes"
    );
}

/// A relocated low `parent_fd`'s ORIGINAL number must stay open (busy) in the parent for as long
/// as the steps that hold it (`std_cmd`'s `pre_exec` closure on macOS) exist — not just until
/// `install` returns. Freeing it any earlier hands that exact number back to the OS right before
/// the spawn does its own internal fd allocation (e.g. its child-to-parent error-reporting pipe, or
/// any piped stdio), which can then claim that same number in the parent and collide with a dup2
/// the child makes before the fd map's step runs — so the freed number ends up serving two
/// different purposes across the fork, corrupting whichever one loses.
#[skuld::test]
fn a_relocated_low_parent_fd_stays_open_in_the_parent_until_its_steps_drop() {
    let Some(done) = own_process(
        test_path!(a_relocated_low_parent_fd_stays_open_in_the_parent_until_its_steps_drop),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let _restore = RestoreStdio::close(&done, &[2]);
    // The next fd opened lands at 2 (just closed above by `RestoreStdio::close`).
    let owned: OwnedFd = file_with("kept-open").into();
    assert_eq!(
        owned.as_raw_fd(),
        2,
        "test setup invariant: the source must land exactly at fd 2 to reproduce the bug"
    );

    let mut steps = InChild::default();
    install(
        &mut steps,
        vec![FdMapping {
            parent_fd: owned,
            child_fd: 5,
        }],
    )
    .expect("install");

    // fd 2, in THIS process, must still be a live descriptor right after `install` returns —
    // freeing it earlier is exactly the bug: it must stay open until `steps` itself (and the
    // Plan it owns) drops.
    let still_open = unsafe { libc::fcntl(2, libc::F_GETFD) } != -1;
    assert!(
        still_open,
        "the original low fd (2) must remain open across install() — it must not be freed \
         back to the OS before the spawn's own fd allocations have run"
    );

    drop(steps); // only now may the retired original actually close

    // Once `steps` (and the `Plan`/`retired` it owned) has dropped, fd 2 must actually be freed —
    // proving `_retired` isn't just leaked open for the life of the process.
    let closed_after_drop = unsafe { libc::fcntl(2, libc::F_GETFD) } == -1;
    assert!(
        closed_after_drop,
        "the retired original fd (2) must be closed once its steps drop, not leaked open"
    );
}
