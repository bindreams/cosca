//! `Command::spawn_suspended` and `SuspendedChild`, on real frozen children.
//!
//! Every Windows child is a windowless `findstr x` blocker (no console window on a developer's
//! desktop), held by a pipe the test keeps, so it ends only when the code under test kills it.

use static_assertions::assert_impl_all;

use crate::child::SuspendedChild;
#[cfg(not(windows))]
use crate::error::Error;

assert_impl_all!(SuspendedChild: Send);

/// What `spawn_suspended` is refused with off Windows.
#[cfg(not(windows))]
#[skuld::test]
fn spawn_suspended_is_unsupported_off_windows() {
    let mut cmd = crate::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.kill_on_drop(false);

    let err = cmd.spawn_suspended().expect_err("there is no frozen spawn here");

    let Error::Unsupported { op, .. } = &err else {
        panic!("expected Unsupported, got {err:?}");
    };
    assert_eq!(op, "spawn_suspended");
    assert!(!cmd.kill_on_drop_flag(), "the refusal must leave the command as it was");
}

#[cfg(windows)]
mod on_windows {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Threading::{
        OpenProcess, TerminateProcess, WaitForSingleObject, INFINITE, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
    };

    use crate::containment::windows::fault::{force_next, Step};
    use crate::error::{ChildFate, Error};
    use crate::test_frozen::{limit_flags, InitialThread};
    use crate::Containment;

    const ERROR_ACCESS_DENIED: u32 = 5;

    /// A windowless blocker; `raw` routes it to the raw `CreateProcessW` backend by giving it an
    /// `executable()`.
    fn blocker(raw: bool) -> crate::Command {
        let mut cmd = crate::Command::new();
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

    fn end(child: crate::Child) {
        child.kill().expect("kill the resumed child");
        child.wait().expect("reap the resumed child");
    }

    // Refusals =====

    #[skuld::test]
    fn spawn_suspended_with_elevate_is_unsupported_and_takes_nothing_from_the_command() {
        let mut cmd = blocker(false);
        cmd.elevate();

        let err = cmd.spawn_suspended().expect_err("a frozen spawn cannot be elevated");

        let Error::Unsupported { op, .. } = &err else {
            panic!("expected Unsupported, got {err:?}");
        };
        assert!(op.contains("elevate"), "{op}");
        assert!(
            cmd.fds().contains_key(&crate::Fd::STDIN),
            "a refusal before anything is taken must leave the stdio configuration in place"
        );
    }

    #[skuld::test]
    fn spawn_suspended_with_breakaway_and_contain_is_unsupported() {
        let mut cmd = blocker(false);
        cmd.contain().breakaway_from_job();

        let err = cmd.spawn_suspended().expect_err("breakaway and contain are refused");

        let Error::Unsupported { op, .. } = &err else {
            panic!("expected Unsupported, got {err:?}");
        };
        assert!(op.contains("breakaway_from_job"), "{op}");
    }

    // The window =====

    /// Suspend count 1 is the kernel's statement that the initial thread has run nothing.
    #[skuld::test]
    fn frozen_child_has_executed_no_instruction_before_resume() {
        for raw in BACKENDS {
            let frozen = blocker(raw).spawn_suspended().expect("spawn suspended");
            let thread = InitialThread::of(frozen.id().pid());
            assert_eq!(thread.suspend_count(), 1, "raw={raw}: frozen until resumed");

            let child = frozen.resume().expect("resume");

            assert_eq!(thread.suspend_count(), 0, "raw={raw}: running after resume");
            end(child);
        }
    }

    /// Something else started a running thread in the frozen child (an EDR agent, a debugger): the
    /// initial thread is still frozen exactly once, so the resume goes through, contained or not.
    #[skuld::test]
    fn resume_succeeds_when_another_party_started_a_running_thread_in_the_frozen_child() {
        for raw in BACKENDS {
            for contain in [false, true] {
                let mut cmd = blocker(raw);
                if contain {
                    cmd.contain();
                }
                let frozen = cmd.spawn_suspended().expect("spawn suspended");
                let _injected = crate::test_frozen::inject_running_thread_into_pid(frozen.id().pid());

                let child = frozen.resume().unwrap_or_else(|e| {
                    panic!("raw={raw} contain={contain}: a running second thread failed the resume: {e:?}")
                });

                end(child);
            }
        }
    }

    #[skuld::test]
    fn id_recorded_while_frozen_equals_the_resumed_childs_id() {
        for raw in BACKENDS {
            let frozen = blocker(raw).spawn_suspended().expect("spawn suspended");
            let recorded = frozen.id();

            let child = frozen.resume().expect("resume");

            assert_eq!(child.id(), recorded, "raw={raw}");
            end(child);
        }
    }

    #[skuld::test]
    fn contained_frozen_child_is_inside_its_job_before_resume() {
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
            end(child);
        }
    }

    #[skuld::test]
    fn uncontained_frozen_child_has_no_cosca_job_and_reports_containment_none() {
        for raw in BACKENDS {
            let frozen = blocker(raw).spawn_suspended().expect("spawn suspended");
            assert!(!frozen.test_job_handle_contains_self(), "raw={raw}: no containment job");
            assert_eq!(frozen.test_containment(), Containment::None, "raw={raw}");

            let child = frozen.resume().expect("resume");

            assert_eq!(child.containment(), Containment::None, "raw={raw}");
            end(child);
        }
    }

    /// The resumed child is armed as a `spawn()` child is, or not, as the command said.
    #[skuld::test]
    fn resumed_child_takes_the_commands_kill_on_drop() {
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
            let Attached::JobObject(job) = &child.attached else {
                panic!("expected a job, got {:?}", child.attached);
            };
            let kills_on_close =
                limit_flags(job).0 & windows::Win32::System::JobObjects::JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.0 != 0;
            assert_eq!(kills_on_close, kill_on_drop, "kill_on_drop({kill_on_drop})");
            child.kill().expect("kill");
            child.wait().expect("reap");
        }
    }

    /// An owned handle on a process that can wait for it and end it, opened while the caller still
    /// holds the process, so the pid names nothing else.
    struct Remote(HANDLE);

    impl Remote {
        fn open(pid: u32) -> Remote {
            // SAFETY: plain Win32 call; the handle is closed on drop.
            let handle = unsafe { OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, false, pid) }
                .expect("open the resumed child");
            Remote(handle)
        }

        /// Block until the process is gone; the process object signals, nothing here is a timer.
        fn wait_for_death(&self) {
            // SAFETY: `self.0` is live.
            unsafe { WaitForSingleObject(self.0, INFINITE) };
        }

        /// Whether the process is gone now. A single non-blocking look, used only after a drop that
        /// kills synchronously, so it is not a bet that enough time has passed.
        fn is_dead_now(&self) -> bool {
            // SAFETY: `self.0` is live.
            unsafe { WaitForSingleObject(self.0, 0) }.0 == 0
        }

        fn end(&self) {
            // SAFETY: `self.0` is live with `PROCESS_TERMINATE`.
            unsafe { TerminateProcess(self.0, 1) }.expect("end the resumed child");
            self.wait_for_death();
        }
    }

    impl Drop for Remote {
        fn drop(&mut self) {
            // SAFETY: owned, closed once.
            unsafe { _ = CloseHandle(self.0) };
        }
    }

    /// The command's `kill_on_drop` decides what dropping the resumed `Child` does, for every
    /// containment: a resumed child that kept the frozen spawn's forced `true` would be killed by a
    /// command that opted out.
    ///
    /// The child's stdin write end is leaked, so no EOF can end it: it dies only if the drop kills
    /// it. Without the drop's kill the `true` leg never sees the child die (the run is bounded by
    /// nextest's terminate-after); a drop that kills regardless fails the `false` leg's check.
    #[skuld::test]
    fn death_watch_dropping_a_resumed_child_follows_the_commands_kill_on_drop_for_every_containment() {
        for (shape, contain) in [
            ("uncontained", None),
            ("treewalk", Some(crate::ContainMode::TreeWalk)),
            ("strongest", Some(crate::ContainMode::Strongest)),
        ] {
            for kill_on_drop in [true, false] {
                let mut cmd = blocker(false);
                if let Some(mode) = contain {
                    cmd.contain_with(mode);
                }
                cmd.kill_on_drop(kill_on_drop);
                cmd.stdin(crate::test_child::leaked_writer_stdin()).expect("stdin");
                let child = cmd
                    .spawn_suspended()
                    .expect("spawn suspended")
                    .resume()
                    .expect("resume");
                assert_eq!(child.kill_on_drop, kill_on_drop, "{shape}");
                let remote = Remote::open(child.id().pid());

                drop(child);

                if kill_on_drop {
                    remote.wait_for_death();
                } else {
                    assert!(
                        !remote.is_dead_now(),
                        "{shape}: kill_on_drop(false) must leave the resumed child running"
                    );
                    remote.end();
                }
            }
        }
    }

    // Refusals before anything exists =====

    /// A program that does not exist is the plain spawn error, not `MayHaveStarted`, and the command
    /// is as it was: the borrowed `kill_on_drop` and suspended request are put back.
    #[skuld::test]
    fn spawn_suspended_of_a_nonexistent_program_returns_the_plain_error_and_leaves_the_command_as_it_was() {
        for raw in BACKENDS {
            for kill_on_drop in [true, false] {
                let mut cmd = crate::Command::new();
                cmd.args(["cosca-49-no-such-program.exe"]);
                if raw {
                    cmd.executable("cosca-49-no-such-program.exe");
                }
                cmd.no_window().kill_on_drop(kill_on_drop);

                let err = cmd.spawn_suspended().expect_err("there is no such program");

                assert!(err.fate().is_none(), "raw={raw}: nothing started, got {err:?}");
                assert!(matches!(err, Error::Io(_)), "raw={raw}: got {err:?}");
                assert_eq!(cmd.kill_on_drop_flag(), kill_on_drop, "raw={raw}");
                assert!(!cmd.flags_request().suspended, "raw={raw}");
            }
        }
    }

    // Drop =====

    /// A dropped frozen child is killed by the `Child` teardown whatever `kill_on_drop` says, for every
    /// containment: the uncontained and `TreeWalk` shapes have no job to end it, so the teardown's
    /// own kill is all that does. The stdin write end is leaked, so nothing but a kill can end the
    /// process; a drop that does not kill leaves the wait below blocked (bounded by nextest's
    /// terminate-after). The teardown count shows the drop ran the `Child` teardown, not the job's
    /// asynchronous close.
    #[skuld::test]
    fn death_watch_dropping_a_frozen_child_kills_it_whatever_kill_on_drop_says() {
        for (shape, contain) in [
            ("uncontained", None),
            ("treewalk", Some(crate::ContainMode::TreeWalk)),
            ("strongest", Some(crate::ContainMode::Strongest)),
        ] {
            for kill_on_drop in [false, true] {
                let mut cmd = blocker(false);
                if let Some(mode) = contain {
                    cmd.contain_with(mode);
                }
                cmd.kill_on_drop(kill_on_drop);
                cmd.stdin(crate::test_child::leaked_writer_stdin()).expect("stdin");
                let frozen = cmd.spawn_suspended().expect("spawn suspended");
                let remote = Remote::open(frozen.id().pid());
                let teardowns = crate::test_frozen::record_root_teardowns();

                drop(frozen);

                remote.wait_for_death();
                assert_eq!(teardowns.count(), 1, "{shape}, kill_on_drop({kill_on_drop})");
            }
        }
    }

    /// Piped stdout and stderr on a dropped frozen child neither hang the drop nor keep the child
    /// alive.
    #[skuld::test]
    fn death_watch_dropping_a_frozen_child_with_piped_stdio_kills_it_without_hanging() {
        for raw in BACKENDS {
            let mut cmd = blocker(raw);
            cmd.stdout(crate::Stdio::pipe()).expect("stdout pipe");
            cmd.stdin(crate::test_child::leaked_writer_stdin()).expect("stdin");
            let frozen = cmd.spawn_suspended().expect("spawn suspended");
            let remote = Remote::open(frozen.id().pid());

            drop(frozen);

            remote.wait_for_death();
        }
    }

    // Failure =====

    #[skuld::test]
    fn a_failed_thread_resume_kills_the_child_and_reports_its_fate() {
        let frozen = blocker(false).spawn_suspended().expect("spawn suspended");
        let id = frozen.id();
        let forced = force_next(Step::Resume, ERROR_ACCESS_DENIED);

        let err = frozen.resume().expect_err("the resume was forced to fail");
        drop(forced);

        assert!(matches!(err.fate(), Some(ChildFate::Reaped)), "got {err:?}");
        assert_eq!(id.is_alive(), crate::identity::Liveness::Dead);
    }

    /// Something else killed the frozen process. The process is observed dead (its handle is
    /// signalled) before `resume`, so the answer is not a race with the kill: an error with a fate,
    /// and no hang.
    #[skuld::test]
    fn resume_after_an_external_kill_is_may_have_started_with_a_fate() {
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
    fn resume_when_the_initial_thread_was_suspended_twice_kills_the_child_instead_of_returning_ok() {
        let frozen = blocker(false).spawn_suspended().expect("spawn suspended");
        let id = frozen.id();
        InitialThread::of(id.pid()).suspend_once();

        let err = frozen.resume().expect_err("the child is still frozen after one resume");

        assert!(err.fate().is_some(), "got {err:?}");
        assert_eq!(id.is_alive(), crate::identity::Liveness::Dead);
    }

    // The command =====

    /// The spawn borrows `kill_on_drop` and the suspended request for its duration only.
    #[skuld::test]
    fn spawn_suspended_leaves_kill_on_drop_and_flags_as_they_were() {
        for kill_on_drop in [true, false] {
            let mut cmd = blocker(false);
            cmd.kill_on_drop(kill_on_drop);

            drop(cmd.spawn_suspended().expect("spawn suspended"));

            assert_eq!(cmd.kill_on_drop_flag(), kill_on_drop);
            assert!(!cmd.flags_request().suspended);
        }
    }

    /// A command used for `spawn_suspended` and then for `spawn` yields a running child.
    #[skuld::test]
    fn the_command_spawns_an_ordinary_child_after_a_frozen_one() {
        let mut cmd = blocker(false);
        drop(cmd.spawn_suspended().expect("spawn suspended"));

        let child = crate::child::spawn::spawn_uncommitted(&mut cmd).expect("an ordinary spawn");

        assert_eq!(
            InitialThread::of(child.id().pid()).suspend_count(),
            0,
            "the spawn after a frozen one must run"
        );
        end(child);
    }

    #[skuld::test]
    fn two_frozen_children_can_be_held_at_once_and_resumed_in_either_order() {
        for in_spawn_order in [true, false] {
            let a = blocker(false).spawn_suspended().expect("first");
            let b = blocker(false).spawn_suspended().expect("second");
            let (x, y) = if in_spawn_order { (a, b) } else { (b, a) };
            let (cx, cy) = (x.resume().expect("resume x"), y.resume().expect("resume y"));
            end(cx);
            end(cy);
        }
    }

    /// No lock is held across the window: an ordinary spawn completes while another child is frozen.
    #[skuld::test]
    fn spawning_while_another_child_is_frozen_does_not_block() {
        let frozen = blocker(false).spawn_suspended().expect("spawn suspended");
        let other = blocker(false).spawn().expect("an ordinary spawn while one is frozen");
        end(other);
        drop(frozen);
    }

    #[skuld::test]
    fn a_suspended_child_resumes_on_another_thread() {
        let frozen = blocker(false).spawn_suspended().expect("spawn suspended");
        let child = std::thread::spawn(move || frozen.resume().expect("resume on another thread"))
            .join()
            .expect("the resuming thread");
        end(child);
    }
}
