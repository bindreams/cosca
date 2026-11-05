//! The teardowns of a Windows child over a real `CREATE_SUSPENDED` process, whose calls a
//! [`FakeProcess`] answers where a test must make the OS refuse, fail or slow down: a failed raw
//! spawn's ([`teardown_spawned`]) and the drop's ([`OwnedChild::tear_down`]).

use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::time::Duration;

use windows::core::HRESULT;
use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, HANDLE};
use windows::Win32::System::Threading::{
    OpenProcess, TerminateProcess, CREATE_SUSPENDED, EXTENDED_STARTUPINFO_PRESENT, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE, STARTUPINFOEXW,
};

use super::proc::create_process;
use super::teardown_spawned;
use crate::child::owned::teardown::{Disposition, TeardownKind};
use crate::child::owned::{ChildWaitOutcome, OwnedChild};
use crate::error::ChildFate;
use crate::identity::ProcessId;
use crate::os_process::child::ExitRecord;
use crate::os_process::fake::{FakeProcess, ReapAnswer};
use crate::os_process::windows::WindowsProcess;
use crate::test_spawn::console_flags::NO_WINDOW;

const KIND: std::io::ErrorKind = std::io::ErrorKind::Other;

/// A `CREATE_SUSPENDED` process that never exits on its own; dropped, it is killed and reaped by a
/// direct `TerminateProcess`, so a test of a no-op kill cannot hang.
struct Suspended {
    owned: OwnedChild,
    pid: u32,
}

impl Suspended {
    fn spawn() -> Suspended {
        let mut cmdline: Vec<u16> = "cmd /C exit 0\0".encode_utf16().collect();
        let mut si = STARTUPINFOEXW::default();
        let (proc, pid) = create_process(
            None,
            &mut cmdline,
            &mut si,
            None,
            &None,
            EXTENDED_STARTUPINFO_PRESENT.0 | CREATE_SUSPENDED.0 | NO_WINDOW,
        )
        .expect("spawn suspended");
        Suspended {
            owned: OwnedChild::new(Box::new(WindowsProcess::for_child(proc, pid))),
            pid,
        }
    }

    fn handle(&self) -> HANDLE {
        HANDLE(self.owned.os_handle().as_raw_handle())
    }

    fn id(&self) -> ProcessId {
        ProcessId::of(self.pid).found().expect("identity")
    }

    /// A second handle with every right, for a teardown to consume while `self` stays the way to
    /// end the process.
    fn duplicate(&self) -> OwnedHandle {
        self.owned
            .os_handle()
            .try_clone_to_owned()
            .expect("duplicate the process handle")
    }

    /// A handle that lacks `PROCESS_TERMINATE`, so its `TerminateProcess` is denied.
    fn without_terminate_right(&self) -> OwnedHandle {
        // SAFETY: plain `OpenProcess` on the live pid `self` pins.
        let h = unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, false, self.pid) }
            .expect("open without PROCESS_TERMINATE");
        // SAFETY: `h` is a fresh owned handle from `OpenProcess`.
        unsafe { OwnedHandle::from_raw_handle(h.0) }
    }

    /// End the process with exit code 0, which only a process no earlier `TerminateProcess` has
    /// claimed takes: a real kill (exit 1) has already marked the thread terminated, so a later
    /// call cannot change the exit code. That call returns success or `ERROR_ACCESS_DENIED`
    /// depending on timing.
    fn end_with_code_zero(&self) -> impl FnOnce() + 'static {
        let handle = self.handle();
        move || {
            // SAFETY: `self` outlives every use of the hook, and holds the handle open.
            match unsafe { TerminateProcess(handle, 0) } {
                Ok(()) => {}
                Err(e) if e.code() == HRESULT::from_win32(ERROR_ACCESS_DENIED.0) => {}
                Err(e) => panic!("TerminateProcess(handle, 0) failed: {e:?}"),
            }
        }
    }

    /// Block until the process has exited, through `self`'s own wait.
    fn wait_for_exit(&self) -> std::process::ExitStatus {
        match self.owned.wait(None) {
            Ok(crate::child::owned::ChildWaitOutcome::Exited(crate::os_process::child::ExitRecord::Status(s))) => s,
            other => panic!("expected an exit status, got {other:?}"),
        }
    }
}

impl Drop for Suspended {
    fn drop(&mut self) {
        // SAFETY: `self` holds the process handle open.
        _ = unsafe { TerminateProcess(self.handle(), 1) };
        _ = self.owned.wait(None);
    }
}

/// A fake that answers from its tables and, past them, from the real `handle` of the process `pid`.
fn real(handle: OwnedHandle, pid: u32) -> FakeProcess {
    FakeProcess::over(Box::new(WindowsProcess::for_child(handle, pid)))
}

/// An [`OwnedChild`] over `fake`, and `fake` for the test to read what it was asked.
fn owned(fake: FakeProcess) -> (OwnedChild, FakeProcess) {
    (OwnedChild::new(Box::new(fake.clone())), fake)
}

// A failed raw spawn's teardown =====

/// A failed spawn's teardown whose `TerminateProcess` is refused because the process has exited (the
/// handle lacks `PROCESS_TERMINATE`, so only its signalled state shows it) leaves the only wait to
/// `wait_warning`: the kill itself does not look at the exit, so the wait is warned about once,
/// naming the pid.
///
/// Mutants: the warned wait is skipped, so there is no look; the warn drops the pid.
#[cfg(feature = "tokio")]
#[skuld::test]
fn raw_spawn_teardown_with_a_denied_terminate_waits_only_inside_wait_warning() {
    let owner = Suspended::spawn();
    let id = owner.id();
    let (child, fake) = owned(real(owner.without_terminate_right(), owner.pid));
    // Ends the process, so the wait after the denied kill returns at once.
    owner.end_with_code_zero()();
    owner.wait_for_exit();

    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let _late = crate::child::spawn::fault::set_late_exit();
    let fate = teardown_spawned(&child, owner.pid, Some(id), Some(Duration::from_secs(1)));

    assert_eq!(
        fake.looks(),
        1,
        "the kill must not look at the exit: the one wait is the warned one"
    );
    let warns = crate::log_capture::records_since_on_current_thread(mark, "still waiting");
    assert_eq!(warns.len(), 1, "one warn, and the wait goes on: {warns:?}");
    assert!(
        warns[0].1.contains(&format!("child {} ", owner.pid)),
        "the warn names the child: {warns:?}"
    );
    assert_eq!(fate, ChildFate::Reaped);
}

/// A failed spawn's teardown with warnings on, whose child has already exited by the time it looks,
/// does not warn. The handle lacks `PROCESS_TERMINATE`, so only its signalled state shows the exit.
///
/// Mutant: the look at the child's exit finds it late whatever its handle says.
#[skuld::test]
fn raw_spawn_teardown_of_an_exited_child_with_warnings_on_does_not_warn() {
    let owner = Suspended::spawn();
    let id = owner.id();
    let (child, _fake) = owned(real(owner.without_terminate_right(), owner.pid));
    owner.end_with_code_zero()();
    owner.wait_for_exit();

    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let fate = teardown_spawned(&child, owner.pid, Some(id), Some(Duration::from_secs(1)));

    assert_eq!(fate, ChildFate::Reaped);
    let warns = crate::log_capture::records_since_on_current_thread(mark, "still waiting");
    assert!(warns.is_empty(), "{warns:?}");
}

/// A failed spawn's teardown with warnings on whose child is still running when it looks (the kill is
/// forced to be refused as an exit under way, so nothing ends it until the wait blocks) warns once,
/// naming the pid, and goes on to the wait. The child is really unsignalled: nothing overrides the
/// look.
///
/// Mutants: the look finds the child exited whatever its handle says; the warn drops the pid.
#[skuld::test]
fn raw_spawn_teardown_of_a_running_child_with_warnings_on_warns_once_naming_it() {
    let owner = Suspended::spawn();
    let (child, _fake) = owned(real(owner.duplicate(), owner.pid));
    crate::identity::windows_fault::refuse_next_terminate_as_exiting();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    // Ends the process once the wait blocks, which is after the look.
    let _end = crate::wait::block_probe::on_blocking(owner.end_with_code_zero());
    let fate = teardown_spawned(&child, owner.pid, None, Some(Duration::ZERO));

    assert_eq!(fate, ChildFate::Reaped, "the wait goes on past the warn");
    let warns = crate::log_capture::records_since_on_current_thread(mark, "still waiting");
    assert_eq!(warns.len(), 1, "one warn: {warns:?}");
    assert!(
        warns[0].1.contains(&format!("child {} ", owner.pid)),
        "the warn names the child: {warns:?}"
    );
}

/// A failed spawn's teardown whose kill was refused as a termination under way (the refusal is
/// forced, so the process stays alive) and whose wait then fails says `Killed`: the child is dead or
/// dying. One scripted answer, so a second wait would be the real one and fail the count.
///
/// Mutant: the teardown answers `Unknown` for a failed wait after a refusal.
#[skuld::test]
fn raw_spawn_teardown_with_an_exit_under_way_and_a_failed_wait_is_killed() {
    let owner = Suspended::spawn();
    let (child, fake) = owned(real(owner.duplicate(), owner.pid).reaps([ReapAnswer::Err(KIND)]));
    crate::identity::windows_fault::refuse_next_terminate_as_exiting();
    let fate = teardown_spawned(&child, owner.pid, None, None);
    assert_eq!(fate, ChildFate::Killed);
    assert_eq!(fake.looks(), 1, "the teardown made the wait that failed");
}

/// A failed spawn's teardown whose `TerminateProcess` is denied on a live child (the handle lacks
/// `PROCESS_TERMINATE`) asked nothing to exit: it looks once, never waits, answers `Running { id }`
/// and warns of the refusal once.
///
/// Mutants: the failed-kill arm falls through to the wait; it answers without the look; the failed
/// `TerminateProcess` is warned of where it is made, as well as by the teardown.
#[skuld::test]
fn raw_spawn_teardown_with_a_denied_terminate_is_running_and_does_not_wait() {
    let owner = Suspended::spawn();
    let id = owner.id();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let (child, fake) = owned(real(owner.without_terminate_right(), owner.pid));
    // Ends the process once a wait blocks, so a teardown that waits fails the checks below instead of
    // hanging.
    crate::wait::block_probe::take();
    let _end = crate::wait::block_probe::on_blocking(owner.end_with_code_zero());
    let fate = teardown_spawned(&child, owner.pid, Some(id), None);
    assert_eq!(fate, ChildFate::Running { id: Some(id) });
    assert_eq!(fake.looks(), 1, "one look, and no wait");
    assert_eq!(
        crate::wait::block_probe::take(),
        [],
        "a failed kill is never followed by a wait"
    );
    let warned = crate::log_capture::records_since_on_current_thread(mark, &owner.pid.to_string())
        .into_iter()
        .filter(|(level, _)| *level <= log::Level::Warn)
        .collect::<Vec<_>>();
    assert_eq!(warned.len(), 1, "one warn for one refusal: {warned:?}");
}

/// A failed spawn's teardown whose kill fails on a child that has exited collects it from the look
/// and warns of nothing.
///
/// Mutant: the failed-kill arm answers `Running` without looking, and warns.
#[skuld::test]
fn raw_spawn_teardown_with_a_failed_terminate_of_an_exited_child_is_reaped_silently() {
    let owner = Suspended::spawn();
    let id = owner.id();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let fake = FakeProcess::new([])
        .reaps([ReapAnswer::Reaped(ExitRecord::Status(
            std::process::ExitStatus::default(),
        ))])
        .signals([Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))]);
    let (child, fake) = owned(fake);
    let fate = teardown_spawned(&child, owner.pid, Some(id), None);
    assert_eq!(fate, ChildFate::Reaped);
    assert_eq!(fake.looks(), 1);
    let warned = crate::log_capture::records_since_on_current_thread(mark, &owner.pid.to_string())
        .into_iter()
        .filter(|(level, _)| *level <= log::Level::Warn)
        .collect::<Vec<_>>();
    assert_eq!(warned, [], "nothing is left running");
}

/// The kill is delivered to a live process: the fate is `Killed`, and the kill is what ended it (exit
/// code 1).
///
/// Mutants: the teardown answers `Unknown` for any failed wait; the kill sends nothing, so the
/// process never exits and the owner's wait hangs; the teardown waits a second time.
#[skuld::test]
fn raw_spawn_teardown_with_a_delivered_terminate_and_a_failed_wait_is_killed() {
    let owner = Suspended::spawn();
    let (child, fake) = owned(real(owner.duplicate(), owner.pid).reaps([ReapAnswer::Err(KIND)]));
    let fate = teardown_spawned(&child, owner.pid, None, None);
    assert_eq!(fate, ChildFate::Killed);
    assert_eq!(fake.looks(), 1, "the teardown made the wait that failed");
    assert_eq!(
        owner.wait_for_exit().code(),
        Some(1),
        "the teardown's kill must have ended it"
    );
}

// The drop's teardown =====

/// An [`OwnedChild`] over a duplicate of `owner`'s handle, and the fake under it.
fn handle_over(owner: &Suspended, script: impl FnOnce(FakeProcess) -> FakeProcess) -> (OwnedChild, FakeProcess) {
    owned(script(real(owner.duplicate(), owner.pid)))
}

/// The kill is delivered and the teardown waits for the exit it started, then answers `Reaped`.
///
/// Mutants: `TerminateProcess` a no-op reporting `Ok` or `ERROR_ACCESS_DENIED`, so the process is
/// ended with code 0 once the wait blocks; the wait after an accepted terminate dropped.
#[skuld::test]
fn a_kill_teardown_of_a_child_waits_for_the_exit_it_started() {
    let owner = Suspended::spawn();
    let (handle, _fake) = handle_over(&owner, |fake| fake);
    // Keeps a no-op terminate from hanging the wait; see `Suspended::end_with_code_zero`.
    let _end = crate::wait::block_probe::on_blocking(owner.end_with_code_zero());
    let torn = handle.tear_down(
        Some(owner.id()),
        TeardownKind::Kill {
            disposition: Disposition::Leave,
            tree: None,
        },
        None,
    );
    assert_eq!(torn.fate, ChildFate::Reaped, "{torn:?}");
    assert!(matches!(torn.clause, Some((log::Level::Debug, _))), "{torn:?}");
    assert!(handle.is_reaped(), "teardown must wait for the exit it started");
    let outcome = handle.wait(None).expect("wait after teardown");
    let ChildWaitOutcome::Exited(ExitRecord::Status(status)) = outcome else {
        panic!("the reaped child answers its status: {outcome:?}");
    };
    assert_eq!(
        status.code(),
        Some(1),
        "teardown must end it with TerminateProcess(1): {status:?}"
    );
}

/// A handle without `PROCESS_TERMINATE` to a live child (a higher-integrity runas child): the
/// teardown looks once, never waits, and leaves it running. What it could not do comes back for the
/// caller's one warn.
///
/// Mutants: wait for the exit when the kill is refused; a refusal on a handle without the right
/// reads as the exit; the failed `TerminateProcess` is warned of where it is made, as well as by
/// the caller.
#[skuld::test]
fn a_kill_teardown_never_blocks_on_a_handle_without_terminate() {
    let owner = Suspended::spawn();
    let id = owner.id();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let (child, fake) = owned(real(owner.without_terminate_right(), owner.pid));
    let handle = child;
    // Ends the owner's process once a wait blocks, so a teardown that waits fails the checks below
    // instead of hanging.
    let _end = crate::wait::block_probe::on_blocking(owner.end_with_code_zero());
    let torn = handle.tear_down(
        Some(id),
        TeardownKind::Kill {
            disposition: Disposition::Leave,
            tree: None,
        },
        None,
    );
    assert_eq!(torn.fate, ChildFate::Running { id: Some(id) }, "{torn:?}");
    assert!(
        matches!(&torn.clause, Some((log::Level::Warn, text)) if text.contains(&owner.pid.to_string())),
        "{torn:?}"
    );
    assert_eq!(fake.looks(), 1, "teardown looked once and did not wait");
    let warned = crate::log_capture::records_since_on_current_thread(mark, &owner.pid.to_string())
        .into_iter()
        .filter(|(level, _)| *level <= log::Level::Warn)
        .collect::<Vec<_>>();
    assert_eq!(warned, [], "the teardown leaves the one warn to its caller");
    assert!(
        matches!(
            handle.wait(Some(crate::wait::now())),
            Ok(ChildWaitOutcome::DeadlinePassed)
        ),
        "nothing ended the child"
    );
}

/// A handle without `PROCESS_TERMINATE` to a child that has exited: its signalled state is the exit,
/// so the child is `Reaped` and nothing is left running.
///
/// Mutant: the teardown reads the refusal by the handle's rights alone, so it leaves a dead child as
/// `Running`.
#[skuld::test]
fn teardown_of_a_handle_without_terminate_to_an_exited_child_reaps_it() {
    let owner = Suspended::spawn();
    let (child, _fake) = owned(real(owner.without_terminate_right(), owner.pid));
    let handle = child;
    owner.end_with_code_zero()();
    owner.wait_for_exit();
    let torn = handle.tear_down(
        Some(owner.id()),
        TeardownKind::Kill {
            disposition: Disposition::Leave,
            tree: None,
        },
        None,
    );
    assert_eq!(torn.fate, ChildFate::Reaped, "{torn:?}");
    assert!(matches!(torn.clause, Some((log::Level::Debug, _))), "{torn:?}");
}

/// A child whose exit is under way but not signalled yet, on a handle that holds
/// `PROCESS_TERMINATE`: the refusal is the exit, and the teardown waits for it.
///
/// Mutant: a refusal is the exit only for a signalled process, so the child is left `Running`.
#[skuld::test]
fn teardown_of_an_exiting_unsignalled_child_reaps_it() {
    let owner = Suspended::spawn();
    let (handle, _fake) = handle_over(&owner, |fake| fake);
    let _end = crate::wait::block_probe::on_blocking(owner.end_with_code_zero());
    crate::identity::windows_fault::refuse_next_terminate_as_exiting();
    let torn = handle.tear_down(
        Some(owner.id()),
        TeardownKind::Kill {
            disposition: Disposition::Leave,
            tree: None,
        },
        None,
    );
    assert_eq!(torn.fate, ChildFate::Reaped, "{torn:?}");
    assert!(matches!(torn.clause, Some((log::Level::Debug, _))), "{torn:?}");
}

/// The kill delivered nothing (the exit was under way), so, as on every OS, a failed wait shows
/// nothing of what became of the child: `Unknown`. One scripted
/// answer, so a second wait would be the real one and fail the count.
///
/// Mutant: a failed wait is `Killed` whatever the kill did.
#[skuld::test]
fn teardown_of_an_exiting_child_with_a_failed_wait_is_unknown() {
    let owner = Suspended::spawn();
    let (handle, fake) = handle_over(&owner, |fake| fake.reaps([ReapAnswer::Err(KIND)]));
    crate::identity::windows_fault::refuse_next_terminate_as_exiting();
    let torn = handle.tear_down(
        Some(owner.id()),
        TeardownKind::Kill {
            disposition: Disposition::Leave,
            tree: None,
        },
        None,
    );
    assert_eq!(torn.fate, ChildFate::Unknown, "{torn:?}");
    assert_eq!(fake.looks(), 1, "the teardown made the wait that failed");
}
