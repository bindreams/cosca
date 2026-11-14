//! Windows: what a spawn gets when its Job Object assignment fails. `Strongest` fails the spawn
//! and the program never runs; `BestEffort` degrades to a tree walk, warns, and the program runs.
//! Both spawn backends are driven: the std one, and the raw `CreateProcessW` one (a command with an
//! `executable()`).

use crate::child::spawn::fault::{self, SpawnPoint};
use crate::containment::windows::fault::{force_next, Step};
use crate::error::Error;
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
        let remote = std::rc::Rc::new(std::cell::RefCell::new(None));
        let _armed = fault::set_at(SpawnPoint::BeforeAttach, {
            let remote = std::rc::Rc::clone(&remote);
            move || *remote.borrow_mut() = Some(Remote::open(fault::spawn_pid()))
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
/// and the program wrote nothing.
///
/// Mutants: the spawn degrades to a tree walk; the child is resumed before it is torn down (the
/// program's marker is written, or the child is not gone); the child is left; the failure answers
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
/// error as its source, and the child is torn down.
///
/// Mutants: the failure answers not started without looking at the root's thread.
#[skuld::test]
fn a_strict_spawn_whose_root_was_resumed_before_the_failed_assignment_may_have_started() {
    for raw in BACKENDS {
        // A child that stays alive once it runs, so the check finds a running thread, not a gone one.
        let (stdin, _writer) = crate::test_child::held_writer_stdin();
        let _resumed = fault::set_at(SpawnPoint::BeforeAttach, || {
            let previous = InitialThread::of(fault::spawn_pid()).release_one();
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
        assert!(
            warns[0].contains("os error 5") || warns[0].contains(&ERROR_ACCESS_DENIED.to_string()),
            "raw {raw}: the warn carries the OS error: {warns:?}"
        );
    }
}

/// `spawn_suspended` keeps its answer: a failed assignment is a `Containment` cause inside
/// `MayHaveStarted`, with the child's fate, as before.
#[skuld::test]
fn a_suspended_spawn_whose_job_assignment_fails_keeps_its_answer() {
    for raw in BACKENDS {
        let dir = tempfile::tempdir().expect("tempdir");
        let marker = dir.path().join("ran");
        let _forced = force_next(Step::Assign, ERROR_ACCESS_DENIED);

        let Err(error) = writes_marker(&marker, ContainMode::Strongest, raw).spawn_suspended() else {
            panic!("raw {raw}: a failed Job assignment must fail a frozen spawn");
        };

        assert!(
            matches!(error, Error::MayHaveStarted { .. }),
            "raw {raw}: the answer is unchanged: {error:?}"
        );
        assert_eq!(
            crate::error::first_os_code(&error),
            Some(ERROR_ACCESS_DENIED as i32),
            "raw {raw}: {error:?}"
        );
        assert!(!marker.exists(), "raw {raw}: the program ran");
    }
}
