//! `tokio::Command::spawn_suspended` and `tokio::SuspendedChild`, on real frozen children.
//!
//! Every Windows child is a windowless blocker (no console window on a developer's desktop): by
//! default `more.com`, which exits 0 on EOF, so a kill that sent nothing fails on how the child
//! ended; `findstr x` where a test needs its match or its exit 1. Tests that need a job, a `TreeWalk` root or any other containment are named for it;
//! the uncontained ones are the ones that are safe to run on a developer's host.

use static_assertions::assert_impl_all;

use super::SuspendedChild;
#[cfg(not(windows))]
use crate::error::Error;

assert_impl_all!(SuspendedChild: Send);

/// What `spawn_suspended` is refused with off Windows, before the runtime check: the same verdict
/// inside and outside a runtime.
#[cfg(not(windows))]
fn assert_spawn_suspended_is_refused() {
    let mut cmd = crate::tokio::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.kill_on_drop(false);

    let err = cmd.spawn_suspended().expect_err("there is no frozen spawn here");

    let Error::Unsupported { op, .. } = &err else {
        panic!("expected Unsupported, got {err:?}");
    };
    assert_eq!(op, "spawn_suspended");
    assert!(
        !cmd.sync().kill_on_drop_flag(),
        "the refusal must leave the command as it was"
    );
}

#[cfg(not(windows))]
#[skuld::test]
fn spawn_suspended_is_unsupported_off_windows() {
    assert_spawn_suspended_is_refused();
}

#[cfg(not(windows))]
#[skuld::test]
async fn spawn_suspended_is_unsupported_off_windows_inside_a_runtime() {
    assert_spawn_suspended_is_refused();
}

#[cfg(windows)]
mod on_windows {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Threading::{
        OpenProcess, TerminateProcess, WaitForSingleObject, INFINITE, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
    };

    use crate::containment::windows::fault::{force_next, Step};
    use crate::error::{ChildFate, Error};
    use crate::test_frozen::{limit_flags, InitialThread, Remote};
    use crate::tokio::{Child, Command};
    use crate::Containment;

    const ERROR_ACCESS_DENIED: u32 = 5;

    /// A windowless blocker that exits 0 once its stdin closes; `raw` routes it to the raw
    /// `CreateProcessW` backend by giving it an `executable()`.
    fn blocker(raw: bool) -> Command {
        let more = crate::test_child::windows_more();
        let mut cmd = Command::new();
        cmd.args([&more]);
        if raw {
            cmd.executable(&more);
        }
        cmd.stdin(crate::Stdio::pipe()).expect("stdin pipe");
        cmd.stdout(crate::Stdio::null()).expect("stdout null");
        cmd.stderr(crate::Stdio::null()).expect("stderr null");
        cmd.no_window();
        cmd
    }

    /// [`blocker`] with `findstr x`: it prints the matching line, and exits 1 on input with no
    /// match.
    fn findstr_blocker(raw: bool) -> Command {
        let mut cmd = Command::new();
        cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
        if raw {
            cmd.executable(crate::test_child::BLOCKER_ARGV[0]);
        }
        cmd.stdin(crate::Stdio::pipe()).expect("stdin pipe");
        cmd.stdout(crate::Stdio::null()).expect("stdout null");
        cmd.stderr(crate::Stdio::null()).expect("stderr null");
        cmd.no_window();
        cmd
    }

    /// Both spawn backends, so a backend that drops the hold fails its own leg.
    const BACKENDS: [bool; 2] = [false, true];

    /// Kill `child`, then release its stdin: it exits 0 on EOF, so a kill that sent nothing fails
    /// the assertion on how it ended instead of the reap blocking for ever.
    async fn end(mut child: Child) {
        let stdin = child.stdin().expect("the blocker's piped stdin");
        child.kill().expect("kill the resumed child");
        drop(stdin);
        crate::test_child::assert_killed("the resumed child", child.wait().await.expect("reap the resumed child"));
    }

    /// The blocker for one `kill_on_drop` leg of a drop test. Stdin decides the child's fate: the
    /// `true` leg leaks its write end, so only the drop's kill can end the child. The `false` leg
    /// pipes stdin and stdout, which [`drop_and_expect_it_runs`] keeps past the drop.
    fn drop_leg_blocker(kill_on_drop: bool) -> Command {
        let mut cmd = findstr_blocker(false);
        cmd.kill_on_drop(kill_on_drop);
        if kill_on_drop {
            cmd.stdin(crate::test_child::leaked_writer_stdin()).expect("stdin");
        } else {
            cmd.stdout(crate::Stdio::pipe()).expect("stdout pipe");
        }
        cmd
    }

    /// Drop `child` (built by [`drop_leg_blocker`]`(false)`) and prove the drop did not kill it, by
    /// a round trip only a live child answers: a line in through its stdin, the match out of its
    /// stdout (`findstr x` prints it once its input ends). The drop issues its kill before the
    /// first byte is written, so a child the drop killed answers nothing, whenever it dies.
    async fn drop_and_expect_it_runs(mut child: Child, what: &str) {
        use ::tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let mut stdin = child.stdin().expect("piped stdin");
        let mut stdout = child.stdout().expect("piped stdout");

        drop(child);

        stdin
            .write_all(b"x\n")
            .await
            .unwrap_or_else(|e| panic!("{what}: kill_on_drop(false) must leave the child running: {e}"));
        drop(stdin);
        let mut answer = String::new();
        stdout.read_to_string(&mut answer).await.expect("read the answer");
        assert_eq!(
            answer.trim_end(),
            "x",
            "{what}: kill_on_drop(false) must leave the child running"
        );
    }

    // Refusals =====

    #[skuld::test]
    async fn spawn_suspended_with_elevate_is_unsupported_and_takes_nothing_from_the_command() {
        let mut cmd = blocker(false);
        cmd.elevate();

        let err = cmd.spawn_suspended().expect_err("a frozen spawn cannot be elevated");

        let Error::Unsupported { op, .. } = &err else {
            panic!("expected Unsupported, got {err:?}");
        };
        assert!(op.contains("elevate"), "{op}");
        assert!(
            cmd.sync().fds().contains_key(&crate::Fd::STDIN),
            "a refusal before anything is taken must leave the stdio configuration in place"
        );
    }

    #[skuld::test]
    async fn spawn_suspended_with_breakaway_and_contain_is_unsupported() {
        let mut cmd = blocker(false);
        cmd.contain().breakaway_from_job();

        let err = cmd.spawn_suspended().expect_err("breakaway and contain are refused");

        let Error::Unsupported { op, .. } = &err else {
            panic!("expected Unsupported, got {err:?}");
        };
        assert!(op.contains("breakaway_from_job"), "{op}");
    }

    /// Outside any runtime the spawn is a typed error, as `spawn` gives, and the command is as it
    /// was.
    #[skuld::test]
    fn async_spawn_suspended_outside_a_runtime_is_a_typed_error() {
        for kill_on_drop in [true, false] {
            let mut cmd = blocker(false);
            cmd.kill_on_drop(kill_on_drop);

            let err = cmd.spawn_suspended().expect_err("there is no runtime");

            assert!(err.fate().is_none(), "nothing started, got {err:?}");
            assert!(matches!(err, Error::Io(_)), "got {err:?}");
            assert_eq!(cmd.sync().kill_on_drop_flag(), kill_on_drop);
            assert!(!cmd.sync().flags_request().suspended);
        }
    }

    // The window =====

    /// Suspend count 1 is the kernel's statement that the initial thread has run nothing.
    #[skuld::test]
    async fn frozen_child_has_executed_no_instruction_before_resume() {
        for raw in BACKENDS {
            let frozen = blocker(raw).spawn_suspended().expect("spawn suspended");
            let thread = InitialThread::of(frozen.id().pid());
            assert_eq!(thread.suspend_count(), 1, "raw={raw}: frozen until resumed");

            let child = frozen.resume().expect("resume");

            assert_eq!(thread.suspend_count(), 0, "raw={raw}: running after resume");
            end(child).await;
        }
    }

    /// Something else started a running thread in the frozen child (an EDR agent, a debugger): the
    /// initial thread is still frozen exactly once, so the resume goes through.
    #[skuld::test]
    async fn resume_succeeds_when_another_party_started_a_running_thread_in_the_frozen_child() {
        for raw in BACKENDS {
            let frozen = blocker(raw).spawn_suspended().expect("spawn suspended");
            let _injected = crate::test_frozen::inject_running_thread_into_pid(frozen.id().pid());

            let child = frozen
                .resume()
                .unwrap_or_else(|e| panic!("raw={raw}: a running second thread failed the resume: {e:?}"));

            end(child).await;
        }
    }

    #[skuld::test]
    async fn id_recorded_while_frozen_equals_the_resumed_childs_id() {
        for raw in BACKENDS {
            let frozen = blocker(raw).spawn_suspended().expect("spawn suspended");
            let recorded = frozen.id();

            let child = frozen.resume().expect("resume");

            assert_eq!(child.id(), recorded, "raw={raw}");
            end(child).await;
        }
    }

    #[skuld::test]
    async fn contained_frozen_child_is_inside_its_job_before_resume() {
        for raw in BACKENDS {
            let mut cmd = blocker(raw);
            cmd.contain();
            let frozen = cmd.spawn_suspended().expect("spawn suspended");
            assert!(
                frozen.test_job_handle_contains_self(),
                "raw={raw}: in its job while frozen"
            );

            let child = frozen.resume().expect("resume");

            assert_eq!(child.containment(), Containment::JobObject, "raw={raw}");
            assert!(child.test_job_handle_contains_self(), "raw={raw}");
            end(child).await;
        }
    }

    #[skuld::test]
    async fn uncontained_frozen_child_has_no_cosca_job_and_reports_containment_none() {
        for raw in BACKENDS {
            let frozen = blocker(raw).spawn_suspended().expect("spawn suspended");
            assert!(!frozen.test_job_handle_contains_self(), "raw={raw}: no containment job");
            assert_eq!(frozen.test_containment(), Containment::None, "raw={raw}");

            let child = frozen.resume().expect("resume");

            assert_eq!(child.containment(), Containment::None, "raw={raw}");
            end(child).await;
        }
    }

    /// The resumed child is armed as a `spawn()` child is, or not, as the command said.
    #[skuld::test]
    async fn contained_resumed_child_takes_the_commands_kill_on_drop() {
        use crate::containment::Attached;
        for kill_on_drop in [true, false] {
            let mut cmd = blocker(false);
            cmd.contain().kill_on_drop(kill_on_drop);

            let child = cmd
                .spawn_suspended()
                .expect("spawn suspended")
                .resume()
                .expect("resume");

            assert_eq!(child.kill_on_drop, kill_on_drop);
            let Attached::JobObject(job) = &child.os.attached else {
                panic!("expected a job, got {:?}", child.os.attached);
            };
            let kills_on_close =
                limit_flags(job).0 & windows::Win32::System::JobObjects::JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.0 != 0;
            assert_eq!(kills_on_close, kill_on_drop, "kill_on_drop({kill_on_drop})");
            end(child).await;
        }
    }

    // The resumed child is a tokio child =====

    /// The pipes the frozen spawn made serve the resumed child: a line written to its stdin comes
    /// back on its stdout, and the exit is awaited. The echoed match and exit 0 show it ran:
    /// `findstr x` on input with no match exits 1.
    #[skuld::test]
    async fn a_resumed_child_serves_its_piped_stdin_and_stdout_and_is_awaited() {
        use ::tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        for raw in BACKENDS {
            let mut cmd = findstr_blocker(raw);
            cmd.stdout(crate::Stdio::pipe()).expect("stdout pipe");
            let mut child = cmd
                .spawn_suspended()
                .expect("spawn suspended")
                .resume()
                .expect("resume");
            let mut stdin = child.stdin().expect("piped stdin");
            let mut stdout = child.stdout().expect("piped stdout");

            stdin.write_all(b"xyz\nabc\n").await.expect("write the child's stdin");
            drop(stdin);
            let mut answer = String::new();
            stdout
                .read_to_string(&mut answer)
                .await
                .expect("read the child's stdout");
            let status = child.wait().await.expect("await the exit");

            assert_eq!(answer.trim_end(), "xyz", "raw={raw}: only the matching line comes back");
            assert_eq!(status.code(), Some(0), "raw={raw}: findstr found a match");
        }
    }

    /// The resumed child's piped stderr carries what it writes: `findstr` names the file it cannot
    /// open there, and nothing reaches stdout.
    #[skuld::test]
    async fn a_resumed_child_serves_its_piped_stderr() {
        use ::tokio::io::AsyncReadExt as _;
        const MISSING: &str = "cosca-49-no-such-file.txt";
        for raw in BACKENDS {
            let mut cmd = Command::new();
            cmd.args(["findstr", "x", MISSING]);
            if raw {
                cmd.executable("findstr");
            }
            cmd.stdin(crate::Stdio::null()).expect("stdin null");
            cmd.stdout(crate::Stdio::pipe()).expect("stdout pipe");
            cmd.stderr(crate::Stdio::pipe()).expect("stderr pipe");
            cmd.no_window();
            let mut child = cmd
                .spawn_suspended()
                .expect("spawn suspended")
                .resume()
                .expect("resume");
            let mut stdout = child.stdout().expect("piped stdout");
            let mut stderr = child.stderr().expect("piped stderr");

            let (mut out, mut err) = (String::new(), String::new());
            stderr.read_to_string(&mut err).await.expect("read the child's stderr");
            stdout.read_to_string(&mut out).await.expect("read the child's stdout");
            let status = child.wait().await.expect("await the exit");

            assert!(err.contains(MISSING), "raw={raw}: stderr was {err:?}");
            assert_eq!(out, "", "raw={raw}");
            assert_ne!(status.code(), Some(0), "raw={raw}: the file does not exist");
        }
    }

    /// The command's `kill_on_drop` decides what dropping the resumed `Child` does: a resumed child
    /// that kept the frozen spawn's forced `true` would be killed by a command that opted out.
    ///
    /// The `true` leg's child can only end by the drop's kill (without it the run is bounded by
    /// nextest's terminate-after). The `false` leg proves the child alive after the drop with a
    /// round trip, not a look at the process.
    #[skuld::test]
    async fn death_watch_dropping_an_uncontained_resumed_child_follows_the_commands_kill_on_drop() {
        for kill_on_drop in [true, false] {
            let child = drop_leg_blocker(kill_on_drop)
                .spawn_suspended()
                .expect("spawn suspended")
                .resume()
                .expect("resume");
            assert_eq!(child.kill_on_drop, kill_on_drop);

            if kill_on_drop {
                let remote = Remote::open(child.id().pid());
                drop(child);
                remote.wait_for_death();
            } else {
                drop_and_expect_it_runs(child, "uncontained").await;
            }
        }
    }

    /// As above for every containment: a `TreeWalk` root and a job each follow the command too.
    #[skuld::test]
    async fn death_watch_dropping_a_contained_resumed_child_follows_the_commands_kill_on_drop() {
        for mode in [crate::ContainMode::TreeWalk, crate::ContainMode::Strongest] {
            for kill_on_drop in [true, false] {
                let mut cmd = drop_leg_blocker(kill_on_drop);
                cmd.contain_with(mode);
                let child = cmd
                    .spawn_suspended()
                    .expect("spawn suspended")
                    .resume()
                    .expect("resume");
                assert_eq!(child.kill_on_drop, kill_on_drop, "{mode:?}");

                if kill_on_drop {
                    let remote = Remote::open(child.id().pid());
                    drop(child);
                    remote.wait_for_death();
                } else {
                    drop_and_expect_it_runs(child, &format!("{mode:?}")).await;
                }
            }
        }
    }

    // Refusals before anything exists =====

    /// A program that does not exist fails as the same command's `spawn` does, and the command is as
    /// it was: the borrowed `kill_on_drop` and suspended request are put back.
    #[skuld::test]
    async fn spawn_suspended_of_a_nonexistent_program_fails_as_spawn_does_and_leaves_the_command_as_it_was() {
        fn io_kind(err: &Error) -> Option<std::io::ErrorKind> {
            match err {
                Error::Io(e) => Some(e.kind()),
                Error::MayHaveStarted { source, .. } => io_kind(source),
                _ => None,
            }
        }
        for raw in BACKENDS {
            for kill_on_drop in [true, false] {
                let mut cmd = Command::new();
                cmd.args(["cosca-49-no-such-program.exe"]);
                if raw {
                    cmd.executable("cosca-49-no-such-program.exe");
                }
                cmd.no_window().kill_on_drop(kill_on_drop);
                let plain = cmd.spawn().expect_err("there is no such program");

                let err = cmd.spawn_suspended().expect_err("there is no such program");

                assert_eq!(
                    io_kind(&err),
                    Some(std::io::ErrorKind::NotFound),
                    "raw={raw}: got {err:?}"
                );
                assert_eq!(io_kind(&err), io_kind(&plain), "raw={raw}");
                assert_eq!(err.fate(), plain.fate(), "raw={raw}");
                assert_eq!(cmd.sync().kill_on_drop_flag(), kill_on_drop, "raw={raw}");
                assert!(!cmd.sync().flags_request().suspended, "raw={raw}");
            }
        }
    }

    // Drop =====

    /// A dropped frozen child is killed whatever `kill_on_drop` says. Nothing but the drop can end
    /// it (its stdin write end is leaked), and the drop is the async `Child`'s bounded one: it signals
    /// and returns, so the proof is the process object, opened while the frozen child pins the pid.
    #[skuld::test]
    async fn death_watch_dropping_an_uncontained_frozen_child_kills_it_whatever_kill_on_drop_says() {
        for kill_on_drop in [false, true] {
            let mut cmd = blocker(false);
            cmd.kill_on_drop(kill_on_drop);
            cmd.stdin(crate::test_child::leaked_writer_stdin()).expect("stdin");
            let frozen = cmd.spawn_suspended().expect("spawn suspended");
            let remote = Remote::open(frozen.id().pid());

            drop(frozen);

            remote.wait_for_death();
        }
    }

    /// As above for a `TreeWalk` root and a job.
    #[skuld::test]
    async fn death_watch_dropping_a_contained_frozen_child_kills_it_whatever_kill_on_drop_says() {
        for mode in [crate::ContainMode::TreeWalk, crate::ContainMode::Strongest] {
            for kill_on_drop in [false, true] {
                let mut cmd = blocker(false);
                cmd.contain_with(mode).kill_on_drop(kill_on_drop);
                cmd.stdin(crate::test_child::leaked_writer_stdin()).expect("stdin");
                let frozen = cmd.spawn_suspended().expect("spawn suspended");
                let remote = Remote::open(frozen.id().pid());

                drop(frozen);

                remote.wait_for_death();
            }
        }
    }

    /// Piped stdout and stderr on a dropped frozen child neither hang the drop nor keep the child
    /// alive.
    #[skuld::test]
    async fn death_watch_dropping_a_frozen_child_with_piped_stdio_kills_it_without_hanging() {
        for raw in BACKENDS {
            let mut cmd = blocker(raw);
            cmd.stdout(crate::Stdio::pipe()).expect("stdout pipe");
            cmd.stderr(crate::Stdio::pipe()).expect("stderr pipe");
            cmd.stdin(crate::test_child::leaked_writer_stdin()).expect("stdin");
            let frozen = cmd.spawn_suspended().expect("spawn suspended");
            let remote = Remote::open(frozen.id().pid());

            drop(frozen);

            remote.wait_for_death();
        }
    }

    // Failure =====

    #[skuld::test]
    async fn a_failed_thread_resume_kills_the_child_and_reports_its_fate() {
        crate::tokio::test_runtime::assert_current_thread();
        let frozen = blocker(false).spawn_suspended().expect("spawn suspended");
        let remote = Remote::open(frozen.id().pid());
        let forced = force_next(Step::Resume, ERROR_ACCESS_DENIED);

        let err = frozen.resume().expect_err("the resume was forced to fail");
        drop(forced);

        let fate = err
            .fate()
            .unwrap_or_else(|| panic!("expected MayHaveStarted, got {err:?}"));
        assert!(matches!(fate, ChildFate::Killed | ChildFate::Reaped), "{fate:?}");
        remote.wait_for_death();
    }

    /// Something else killed the frozen process. The process is observed dead (its handle is
    /// signalled) before `resume`, so the answer is not a race with the kill: an error with a fate,
    /// and no hang.
    #[skuld::test]
    async fn resume_after_an_external_kill_is_may_have_started_with_a_fate() {
        let frozen = blocker(false).spawn_suspended().expect("spawn suspended");
        // Opened while `frozen` holds the process, so the pid cannot name anything else.
        // SAFETY: plain Win32 calls; the handle is closed below.
        let victim: HANDLE = unsafe { OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, false, frozen.id().pid()) }
            .expect("open the frozen child");
        // SAFETY: `victim` is live.
        unsafe {
            TerminateProcess(victim, 1).expect("terminate the frozen child");
            // An event, not a timer: the process object signals when the process is gone.
            WaitForSingleObject(victim, INFINITE);
            _ = CloseHandle(victim);
        }

        let err = frozen.resume().expect_err("a dead child cannot be resumed");

        let fate = err
            .fate()
            .unwrap_or_else(|| panic!("expected MayHaveStarted, got {err:?}"));
        assert!(
            matches!(fate, ChildFate::Reaped | ChildFate::Killed | ChildFate::Gone),
            "{fate:?}"
        );
    }

    /// Something suspended the initial thread during the window. One resume would leave the child
    /// frozen, so `resume` must not return `Ok`.
    #[skuld::test]
    async fn resume_when_the_initial_thread_was_suspended_twice_kills_the_child_instead_of_returning_ok() {
        let frozen = blocker(false).spawn_suspended().expect("spawn suspended");
        let remote = Remote::open(frozen.id().pid());
        InitialThread::of(frozen.id().pid()).suspend_once();

        let err = frozen.resume().expect_err("the child is still frozen after one resume");

        assert!(err.fate().is_some(), "got {err:?}");
        remote.wait_for_death();
    }

    // The command =====

    /// The spawn borrows `kill_on_drop` and the suspended request for its duration only.
    #[skuld::test]
    async fn spawn_suspended_leaves_kill_on_drop_and_flags_as_they_were() {
        for kill_on_drop in [true, false] {
            let mut cmd = blocker(false);
            cmd.kill_on_drop(kill_on_drop);

            drop(cmd.spawn_suspended().expect("spawn suspended"));

            assert_eq!(cmd.sync().kill_on_drop_flag(), kill_on_drop);
            assert!(!cmd.sync().flags_request().suspended);
        }
    }

    /// A command used for `spawn_suspended` and then for `spawn` yields a running child. A child
    /// that stayed frozen never exits, so the wait is bounded by nextest's `death_watch_` override.
    #[skuld::test]
    async fn death_watch_the_command_spawns_an_ordinary_child_after_a_frozen_one() {
        let mut cmd = findstr_blocker(false);
        drop(cmd.spawn_suspended().expect("spawn suspended"));

        // A spawn takes the stdio configuration out of the command, so the second one is given its own.
        cmd.stdin(crate::Stdio::pipe()).expect("stdin pipe");
        let mut child = cmd.spawn().expect("an ordinary spawn");
        drop(child.stdin().expect("piped stdin"));

        let status = child.wait().await.expect("await the exit");

        assert_eq!(status.code(), Some(1), "the spawn after a frozen one must run");
    }

    #[skuld::test]
    async fn two_frozen_children_can_be_held_at_once_and_resumed_in_either_order() {
        for in_spawn_order in [true, false] {
            let a = blocker(false).spawn_suspended().expect("first");
            let b = blocker(false).spawn_suspended().expect("second");
            let (x, y) = if in_spawn_order { (a, b) } else { (b, a) };
            let (cx, cy) = (x.resume().expect("resume x"), y.resume().expect("resume y"));
            end(cx).await;
            end(cy).await;
        }
    }

    /// No lock is held across the window: an ordinary spawn completes while another child is frozen.
    #[skuld::test]
    async fn spawning_while_another_child_is_frozen_does_not_block() {
        let frozen = blocker(false).spawn_suspended().expect("spawn suspended");
        let other = blocker(false).spawn().expect("an ordinary spawn while one is frozen");
        end(other).await;
        drop(frozen);
    }

    #[skuld::test]
    async fn a_suspended_child_resumes_on_another_thread() {
        let frozen = blocker(false).spawn_suspended().expect("spawn suspended");
        let child = std::thread::spawn(move || frozen.resume().expect("resume on another thread"))
            .join()
            .expect("the resuming thread");
        end(child).await;
    }
}
