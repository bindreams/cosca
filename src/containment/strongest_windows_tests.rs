//! Windows: what a spawn gets when its Job Object assignment fails. `Strongest` fails the spawn
//! and the program never runs; `BestEffort` degrades to a tree walk, warns, and the program runs.
//! Both spawn backends are driven: the std one, and the raw `CreateProcessW` one (a command with an
//! `executable()`).

use crate::child::spawn::fault::{self, SpawnPoint};
use crate::containment::windows::fault::{force_next, Step};
use crate::error::{ChildFate, Error};
use crate::test_child::Console;
use crate::test_frozen::{InitialThread, Remote};
use crate::{ContainMode, Containment};

const ERROR_ACCESS_DENIED: u32 = 5;
const BACKENDS: [bool; 2] = [false, true];

/// A windowless command that creates `marker` when it runs: its absence shows the program did not
/// run to its end. `raw` routes it to the raw backend.
fn writes_marker(marker: &std::path::Path, mode: ContainMode, raw: bool) -> crate::Command {
    let cmd_exe = crate::test_child::system32("cmd.exe");
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.args([
        cmd_exe.to_str().expect("a UTF-8 System32 path"),
        "/d",
        "/c",
        "type",
        "nul",
        ">",
    ])
    .arg(marker);
    if raw {
        cmd.executable(&cmd_exe);
    }
    cmd.contain_with(mode);
    cmd
}

/// Holds a handle on the child of the next spawn on this thread, opened while it is still
/// suspended, so the test can ask the process object itself whether it is gone.
struct ChildWatch {
    remote: std::rc::Rc<std::cell::RefCell<Option<Remote>>>,
    _armed: crate::oneshot_hook::Armed,
}

impl ChildWatch {
    fn arm() -> ChildWatch {
        ChildWatch::arm_then(|_| ())
    }

    /// [`arm`](Self::arm), and `then` runs with the child's pid right after the child is opened.
    fn arm_then(then: impl FnOnce(u32) + 'static) -> ChildWatch {
        let remote = std::rc::Rc::new(std::cell::RefCell::new(None));
        let _armed = fault::set_at(SpawnPoint::BeforeAttach, {
            let remote = std::rc::Rc::clone(&remote);
            move || {
                let pid = fault::spawn_pid();
                *remote.borrow_mut() = Some(Remote::open(pid));
                then(pid);
            }
        });
        ChildWatch { remote, _armed }
    }

    /// The child's handle. Panics when the spawn never reached its attach.
    fn into_child(self) -> Remote {
        self.remote
            .borrow_mut()
            .take()
            .expect("the spawn reached its attach, which opened the child")
    }
}

/// A `Strongest` or `Session` spawn (Windows treats `Session` as `Strongest`) whose Job Object
/// assignment fails is `Error::Containment` that names the Job Object, with the OS error as its
/// source and the program not started. The child is gone when the spawn returns, on both backends,
/// and the program wrote nothing. (That the root's thread was never resumed is pinned at the attach,
/// in `dispatch_tests`: a root resumed and killed at once leaves no marker either.)
///
/// Mutants: the spawn degrades to a tree walk; the child is left; the failure answers
/// `MayHaveStarted`; the OS error is dropped.
#[skuld::test]
fn a_strict_spawn_whose_job_assignment_fails_fails_and_the_program_never_runs() {
    for mode in [ContainMode::Strongest, ContainMode::Session] {
        for raw in BACKENDS {
            let dir = tempfile::tempdir().expect("tempdir");
            let marker = dir.path().join("ran");
            let watch = ChildWatch::arm();
            let _forced = force_next(Step::Assign, ERROR_ACCESS_DENIED);

            let spawned = writes_marker(&marker, mode, raw).spawn();

            let Err(error) = spawned else {
                panic!("{mode:?}, raw {raw}: a failed Job assignment must fail a strict spawn");
            };
            let which = format!("{mode:?}, raw {raw}: {error:?}");
            let Error::Containment { detail, .. } = &error else {
                panic!("not started, as Containment: {which}");
            };
            assert!(detail.contains("Job Object"), "the error names the Job Object: {which}");
            assert_eq!(
                crate::error::first_os_code(&error),
                Some(ERROR_ACCESS_DENIED as i32),
                "{which}"
            );
            assert!(error.fate().is_none(), "the program did not start: {which}");
            // The process object says it is gone; only then does the marker's absence say the
            // program never ran, and not that it had not yet got to it.
            assert!(
                watch.into_child().is_dead_now(),
                "the child was torn down before the spawn returned: {which}"
            );
            assert!(!marker.exists(), "the program ran: {which}");
        }
    }
}

/// A strict spawn whose root was resumed by someone else before the assignment, and whose
/// assignment then fails, cannot say the program did not run: it is `MayHaveStarted`, with the OS
/// error as its source, the child is torn down and reaped, and the cause does not say the program did
/// not run.
///
/// Mutants: the failure answers not started without looking at the root's thread; the child is not
/// torn down; the cause claims the program did not run.
#[skuld::test]
fn a_strict_spawn_whose_root_was_resumed_before_the_failed_assignment_may_have_started() {
    for raw in BACKENDS {
        // A child that stays alive once it runs, so the check finds a running thread, not a gone one.
        let (stdin, _writer) = crate::test_child::held_writer_stdin();
        let watch = ChildWatch::arm_then(|pid| {
            let previous = InitialThread::of(pid).release_one();
            assert_eq!(previous, 1, "the root was created suspended");
        });
        let _forced = force_next(Step::Assign, ERROR_ACCESS_DENIED);
        let blocker: &[&str] = *crate::test_child::BLOCKER_ARGV;
        let mut cmd = crate::test_child::command(Console::Hidden);
        cmd.args(blocker)
            .stdin(stdin)
            .expect("stdin")
            .contain_with(ContainMode::Strongest);
        if raw {
            cmd.executable(blocker[0]);
        }

        let Err(error) = cmd.spawn() else {
            panic!("raw {raw}: a failed Job assignment must fail a strict spawn");
        };

        assert!(
            matches!(error, Error::MayHaveStarted { .. }),
            "raw {raw}: a root that was resumed may have run: {error:?}"
        );
        assert_eq!(
            crate::error::first_os_code(&error),
            Some(ERROR_ACCESS_DENIED as i32),
            "raw {raw}: {error:?}"
        );
        assert_eq!(error.fate(), Some(ChildFate::Reaped), "raw {raw}: {error:?}");
        assert!(
            !crate::error::said(&error).contains("did not run"),
            "raw {raw}: the cause claims the program did not run: {error:?}"
        );
        assert!(
            watch.into_child().is_dead_now(),
            "raw {raw}: the child was torn down before the spawn returned"
        );
    }
}

/// A strict spawn whose suspended root has a second thread (as an EDR agent or a debugger starts
/// one) cannot say the program did not run, though the root's own thread is still suspended: it is
/// `MayHaveStarted`, and the child is torn down. (The proof's thread count is pinned apart: the
/// injected thread's loader run races the proof's read here.)
#[skuld::test]
fn a_strict_spawn_whose_root_has_a_second_thread_may_have_started() {
    for raw in BACKENDS {
        let dir = tempfile::tempdir().expect("tempdir");
        let marker = dir.path().join("ran");
        let watch = ChildWatch::arm_then(|pid| _ = crate::test_frozen::inject_running_thread_into_pid(pid));
        let _forced = force_next(Step::Assign, ERROR_ACCESS_DENIED);

        let Err(error) = writes_marker(&marker, ContainMode::Strongest, raw).spawn() else {
            panic!("raw {raw}: a failed Job assignment must fail a strict spawn");
        };

        assert!(matches!(error, Error::MayHaveStarted { .. }), "raw {raw}: {error:?}");
        assert!(
            !crate::error::said(&error).contains("did not run"),
            "raw {raw}: {error:?}"
        );
        assert!(watch.into_child().is_dead_now(), "raw {raw}: the child was torn down");
    }
}

/// A strict spawn whose proof cannot be taken (the read of the root's thread, or of its loader's
/// state, fails) cannot say the program did not run: it is `MayHaveStarted`, the child is torn down,
/// and the spawn warns naming why.
///
/// Mutant: a failed read is taken as proof that the program did not run.
#[skuld::test]
fn a_strict_spawn_whose_proof_cannot_be_read_may_have_started_and_warns() {
    crate::log_capture::install();
    for raw in BACKENDS {
        for unreadable in [Step::ResumeOpen, Step::LoaderRead] {
            let dir = tempfile::tempdir().expect("tempdir");
            let marker = dir.path().join("ran");
            let watch = ChildWatch::arm();
            let _assign = force_next(Step::Assign, ERROR_ACCESS_DENIED);
            let _unreadable = force_next(unreadable, ERROR_ACCESS_DENIED);
            let mark = crate::log_capture::mark();

            let Err(error) = writes_marker(&marker, ContainMode::Strongest, raw).spawn() else {
                panic!("raw {raw}, {unreadable:?}: a failed Job assignment must fail a strict spawn");
            };

            let which = format!("raw {raw}, {unreadable:?}: {error:?}");
            assert!(matches!(error, Error::MayHaveStarted { .. }), "{which}");
            assert!(!crate::error::said(&error).contains("did not run"), "{which}");
            assert!(watch.into_child().is_dead_now(), "{which}");
            let warns = crate::log_capture::warns_since(mark, "may have run");
            assert_eq!(warns.len(), 1, "{which}: {warns:?}");
            let os_text = std::io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32).to_string();
            assert!(warns[0].contains(&os_text), "the warn names why: {which}: {warns:?}");
        }
    }
}

/// The same failure under `BestEffort`: the spawn degrades to a tree walk, says so at `warn`, and
/// the program runs.
///
/// Mutants: the degrade is silent; the child is not resumed.
#[skuld::test]
fn a_best_effort_spawn_whose_job_assignment_fails_degrades_to_a_tree_walk_and_warns() {
    crate::log_capture::install();
    for raw in BACKENDS {
        let dir = tempfile::tempdir().expect("tempdir");
        let marker = dir.path().join("ran");
        let _forced = force_next(Step::Assign, ERROR_ACCESS_DENIED);
        let mark = crate::log_capture::mark();

        let child = writes_marker(&marker, ContainMode::BestEffort, raw)
            .spawn()
            .unwrap_or_else(|e| panic!("raw {raw}: BestEffort degrades: {e}"));
        let pid = child.pid();

        assert_eq!(child.containment(), Containment::TreeWalk, "raw {raw}");
        child.wait().expect("wait");
        assert!(marker.exists(), "raw {raw}: the program ran");
        let warns = crate::log_capture::warns_since(mark, "Job Object");
        assert_eq!(warns.len(), 1, "raw {raw}: {warns:?}");
        assert!(
            warns[0].contains(&format!("pid {pid}")),
            "raw {raw}: the warn names the child: {warns:?}"
        );
        let os_text = std::io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32).to_string();
        assert!(
            warns[0].contains(&os_text),
            "raw {raw}: the warn carries the OS error: {warns:?}"
        );
    }
}

/// `spawn_suspended` keeps its answer: a failed assignment is a `Containment` cause inside
/// `MayHaveStarted`, with the child's fate.
#[skuld::test]
fn a_suspended_spawn_whose_job_assignment_fails_keeps_its_answer() {
    for raw in BACKENDS {
        let dir = tempfile::tempdir().expect("tempdir");
        let marker = dir.path().join("ran");
        let _forced = force_next(Step::Assign, ERROR_ACCESS_DENIED);

        let Err(error) = writes_marker(&marker, ContainMode::Strongest, raw).spawn_suspended() else {
            panic!("raw {raw}: a failed Job assignment must fail a frozen spawn");
        };

        assert!(matches!(error, Error::MayHaveStarted { .. }), "raw {raw}: {error:?}");
        assert_eq!(
            crate::error::first_os_code(&error),
            Some(ERROR_ACCESS_DENIED as i32),
            "raw {raw}: {error:?}"
        );
        assert!(!marker.exists(), "raw {raw}: the program ran");
    }
}
