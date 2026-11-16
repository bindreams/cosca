//! The teardowns of a Windows child over a real `CREATE_SUSPENDED` process, whose calls a
//! [`FakeProcess`] answers where a test must make the OS refuse, fail or slow down: a failed
//! spawn's ([`tear_down_failed_spawn`]) and the drop's ([`OwnedChild::tear_down`]).
//!
//! A "UAC handle" is one a UAC elevation returned, opened without `PROCESS_TERMINATE`, so its
//! `TerminateProcess` is denied. A `CreateProcess` handle is never refused and never fails a wait,
//! so a row where "a fake answers" needs an answer no real handle gives.

use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::sync::Arc;
use std::time::Duration;

use windows::core::HRESULT;
use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, HANDLE};
use windows::Win32::System::Threading::{
    OpenProcess, TerminateProcess, CREATE_SUSPENDED, EXTENDED_STARTUPINFO_PRESENT, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE, STARTUPINFOEXW,
};

use super::proc::create_process;
use crate::child::drop_teardown::Torn;
use crate::child::lifecycle::Wording;
use crate::child::owned::owned_tests::teardown_lines::{HANDED_BACK, LEFT};
use crate::child::owned::teardown::{Disposition, Kill, Past};
use crate::child::owned::{ChildWaitOutcome, OwnedChild};
use crate::child::spawn::held_teardown::tear_down_failed_spawn;
use crate::child::spawn::policy::SpawnPolicy;
use crate::child::spawn::Diagnosis;
use crate::elevation::front::TrackedKind;
use crate::error::ChildFate;
use crate::identity::{refusing_the_next_terminate, HostKernel, Kernel, ProcessId};
use crate::os_process::child::{ExitRecord, KillRefusal, OsChild};
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
            owned: OwnedChild::new(
                Box::new(WindowsProcess::for_child(HostKernel, proc, pid)),
                TrackedKind::Own,
            ),
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

/// A fake that answers from its tables and, past them, from the real `handle` of the process `pid`,
/// as a `CreateProcess` handle is built.
fn real(handle: OwnedHandle, pid: u32) -> FakeProcess {
    real_over(HostKernel, handle, pid)
}

/// [`real`] whose handle's box owns `kernel`, which a test states rows of.
fn real_over(kernel: impl Kernel + Send + 'static, handle: OwnedHandle, pid: u32) -> FakeProcess {
    FakeProcess::over(Box::new(WindowsProcess::for_child(kernel, handle, pid)))
}

/// A [`WindowsProcess`] over a handle a UAC elevation returned, which allows what it was granted.
fn uac_process(handle: OwnedHandle, pid: u32) -> WindowsProcess<HostKernel> {
    WindowsProcess::for_uac(HostKernel, handle, Some(pid))
}

/// [`real`] for a handle a UAC elevation returned.
fn uac(handle: OwnedHandle, pid: u32) -> FakeProcess {
    FakeProcess::over(Box::new(uac_process(handle, pid)))
}

/// An [`OwnedChild`] over `fake`, and `fake` for the test to read what it was asked.
fn owned(fake: FakeProcess) -> (OwnedChild, FakeProcess) {
    (OwnedChild::new(Box::new(fake.clone()), TrackedKind::Own), fake)
}

/// An [`OwnedChild`] over a duplicate of `owner`'s handle whose box owns `kernel`, and the fake
/// under it, which `script` states rows of.
fn handle_over(
    owner: &Suspended,
    kernel: impl Kernel + Send + 'static,
    script: impl FnOnce(FakeProcess) -> FakeProcess,
) -> (OwnedChild, FakeProcess) {
    owned(script(real_over(kernel, owner.duplicate(), owner.pid)))
}

// A failed spawn's teardown =====

/// Both ways a caller disposes of a child its failed spawn's teardown could not collect.
const DISPOSITIONS: [Disposition; 2] = [Disposition::Leave, Disposition::HandBack];

/// A failed spawn's teardown of `child`, as a caller that knows `past` of its handle and disposes of
/// an uncollected child as `disposition` says, with the wait for a killed child warning past
/// `warn_after`; its fate, and the child if it was handed back.
fn after_a_failed_spawn(
    child: OwnedChild,
    id: Option<ProcessId>,
    past: Past,
    disposition: Disposition,
    warn_after: Option<Duration>,
) -> (ChildFate, Option<crate::Unreaped>) {
    let torn = tear_down_failed_spawn(
        child,
        id,
        past,
        disposition,
        SpawnPolicy {
            teardown_warn_after: warn_after,
            ..SpawnPolicy::SYNC
        },
        &mut Diagnosis::default(),
    );
    (torn.fate, torn.unreaped)
}

/// A failed spawn's teardown with warnings on, whose child has already exited by the time it looks,
/// does not warn, under either disposition. The handle is a UAC handle, so only its signalled state
/// shows the exit.
///
/// Mutant: the look at the child's exit finds it late whatever its handle says.
#[skuld::test]
fn a_failed_spawn_teardown_of_an_exited_child_with_warnings_on_does_not_warn() {
    for disposition in DISPOSITIONS {
        let owner = Suspended::spawn();
        let id = owner.id();
        let (child, _fake) = owned(uac(owner.without_terminate_right(), owner.pid));
        owner.end_with_code_zero()();
        owner.wait_for_exit();

        crate::log_capture::install();
        let mark = crate::log_capture::mark();
        let (fate, unreaped) =
            after_a_failed_spawn(child, Some(id), Past::Clean, disposition, Some(Duration::from_secs(1)));

        assert_eq!(fate, ChildFate::Reaped, "{disposition:?}");
        assert!(
            unreaped.is_none(),
            "a collected child is handed back by none: {disposition:?}"
        );
        let warns = crate::log_capture::records_since_on_current_thread(mark, "still waiting");
        assert!(warns.is_empty(), "{disposition:?}: {warns:?}");
    }
}

/// A failed spawn's teardown with warnings on whose child is still running when it looks (the kill is
/// forced to be refused as an exit under way, so nothing ends it until the wait blocks) warns once,
/// naming the pid, and goes on to the wait, under either disposition. The child is really
/// unsignalled: nothing overrides the look.
///
/// Mutants: the look finds the child exited whatever its handle says; the warn drops the pid.
#[skuld::test]
fn a_failed_spawn_teardown_of_a_running_child_with_warnings_on_warns_once_naming_it() {
    for disposition in DISPOSITIONS {
        let owner = Suspended::spawn();
        let kernel = Arc::new(refusing_the_next_terminate());
        let (child, _fake) = handle_over(&owner, Arc::clone(&kernel), |fake| fake);
        crate::log_capture::install();
        let mark = crate::log_capture::mark();
        // Ends the process once the wait blocks, which is after the look.
        let _end = crate::wait::block_probe::on_blocking(owner.end_with_code_zero());
        let (fate, unreaped) = after_a_failed_spawn(child, None, Past::Clean, disposition, Some(Duration::ZERO));

        assert!(
            kernel.all_rows_taken(),
            "the kill reached TerminateProcess to be refused"
        );
        assert_eq!(
            fate,
            ChildFate::Reaped,
            "the wait goes on past the warn: {disposition:?}"
        );
        assert!(
            unreaped.is_none(),
            "a collected child is handed back by none: {disposition:?}"
        );
        let warns = crate::log_capture::records_since_on_current_thread(mark, "still waiting");
        assert_eq!(warns.len(), 1, "one warn: {disposition:?}: {warns:?}");
        assert!(
            warns[0].1.contains(&format!("child {} ", owner.pid)),
            "the warn names the child: {warns:?}"
        );
    }
}

/// A failed spawn's teardown whose `TerminateProcess` is denied on a live child (a UAC handle) asked
/// nothing to exit: it looks once, never waits, answers `Running { id }` and warns of the refusal
/// once. A UAC handle may be refused for permission, so the contract holds.
///
/// Mutants: the failed-kill arm falls through to the wait; it answers without the look; the failed
/// `TerminateProcess` is warned of where it is made, as well as by the teardown.
#[skuld::test]
fn a_failed_spawn_teardown_with_a_denied_terminate_is_running_and_does_not_wait() {
    let owner = Suspended::spawn();
    let id = owner.id();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let (child, fake) = owned(uac(owner.without_terminate_right(), owner.pid));
    // Ends the process once a wait blocks, so a teardown that waits fails the checks below instead of
    // hanging.
    crate::wait::block_probe::take();
    let _end = crate::wait::block_probe::on_blocking(owner.end_with_code_zero());
    let (fate, unreaped) = after_a_failed_spawn(child, Some(id), Past::Clean, Disposition::Leave, None);
    assert!(unreaped.is_none(), "a teardown that leaves its child hands none back");
    assert_eq!(fate, ChildFate::Running { id: Some(id) });
    assert_eq!(fake.looks(), 1, "one look, and no wait");
    assert_eq!(
        crate::wait::block_probe::take(),
        [],
        "a failed kill is never followed by a wait"
    );
    let warned = crate::log_capture::warns_since(mark, "");
    assert_eq!(warned.len(), 1, "one warn for one refusal: {warned:?}");
    assert!(
        warned[0].starts_with(&format!(
            "teardown after a failed spawn: child {} could not be terminated",
            owner.pid
        )),
        "{warned:?}"
    );
}

/// A failed spawn's teardown whose kill fails on a child that has exited collects it from the look
/// and warns of nothing, under either disposition: the child is collected, so none is handed back.
/// The handle may be refused for permission, as a UAC handle's is.
///
/// Mutant: the failed-kill arm answers `Running` without looking, and warns.
#[skuld::test]
fn a_failed_spawn_teardown_with_a_failed_terminate_of_an_exited_child_is_reaped_silently() {
    for disposition in DISPOSITIONS {
        let owner = Suspended::spawn();
        let id = owner.id();
        crate::log_capture::install();
        let mark = crate::log_capture::mark();
        let fake = FakeProcess::new([])
            .with_kill_refusal(KillRefusal::Permission)
            .reaps([ReapAnswer::Exited(ExitRecord::Status(
                std::process::ExitStatus::default(),
            ))])
            .signals([Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))]);
        let (child, fake) = owned(fake);
        let (fate, unreaped) = after_a_failed_spawn(child, Some(id), Past::Clean, disposition, None);
        assert_eq!(fate, ChildFate::Reaped, "{disposition:?}");
        assert!(
            unreaped.is_none(),
            "a collected child is handed back by none: {disposition:?}"
        );
        assert_eq!(fake.looks(), 1);
        let warned = crate::log_capture::warns_since(mark, "");
        assert_eq!(warned, Vec::<String>::new(), "nothing is left running: {disposition:?}");
    }
}

/// The kill is delivered to a live process and the wait after it fails (a caller that expects
/// anything of its handle, as when a look on it failed): the fate is `Killed`, and the kill is what
/// ended it (exit code 1). The child is uncollected: handed back under `HandBack`, warned of as left
/// under `Leave`.
///
/// The test ends the process with code 0 itself, on the same thread after the teardown returned and
/// before it waits: the teardown's kill is the only earlier call that can end it, so the exit code
/// says who did, and the wait is on a process that is ending either way.
///
/// Mutants: the teardown answers `Unknown` for any failed wait; the kill sends nothing, so the
/// process exits with code 0 and the exit code assertion fails; the teardown waits a second time;
/// `HandBack` drops the child, or says it is left.
#[skuld::test]
fn a_failed_spawn_teardown_with_a_delivered_terminate_and_a_failed_wait_is_killed() {
    for disposition in DISPOSITIONS {
        let owner = Suspended::spawn();
        let (child, fake) = owned(real(owner.duplicate(), owner.pid).reaps([ReapAnswer::Err(KIND)]));
        crate::log_capture::install();
        let mark = crate::log_capture::mark();
        let (fate, unreaped) = after_a_failed_spawn(child, None, Past::WaitMayFail, disposition, None);
        assert_eq!(fate, ChildFate::Killed, "{disposition:?}");
        assert_eq!(
            unreaped.is_some(),
            disposition == Disposition::HandBack,
            "an uncollected child is handed back by HandBack alone: {disposition:?}"
        );
        assert_eq!(fake.looks(), 1, "the teardown made the wait that failed");
        owner.end_with_code_zero()();
        assert_eq!(
            owner.wait_for_exit().code(),
            Some(1),
            "the teardown's kill must have ended it"
        );
        // Said as every teardown says a failed wait, under the failed spawn's name.
        let warns = crate::log_capture::records_since_on_current_thread(mark, "");
        let where_it_went = match disposition {
            Disposition::Leave => LEFT,
            Disposition::HandBack => HANDED_BACK,
        };
        assert_eq!(
            warns,
            [(
                log::Level::Warn,
                format!(
                    "teardown after a failed spawn: teardown of child {}: the wait failed: {}{where_it_went}",
                    owner.pid,
                    crate::child::owned::owned_tests::teardown_lines::wait_error(),
                )
            )],
            "{disposition:?}"
        );
    }
}

/// A caller that expects a wait on its handle to succeed is told when it did not: a failed wait after
/// a delivered kill is a breach of the contract, asserted where the warn is logged, after it. A fake
/// answers the failed wait.
///
/// Mutant: `warn_teardown` asserts nothing.
#[cfg(debug_assertions)]
#[skuld::test]
#[should_panic(expected = "a wait on a child's own handle failed")]
fn a_failed_wait_on_a_handle_the_spawn_expected_to_wait_on_breaks_the_contract() {
    let owner = Suspended::spawn();
    let (child, _fake) = owned(real(owner.duplicate(), owner.pid).reaps([ReapAnswer::Err(KIND)]));
    crate::log_capture::install();
    after_a_failed_spawn(child, None, Past::Clean, Disposition::Leave, None);
}

// A UAC child that could not be tracked =====

/// A launched UAC child whose pid or identity could not be read is ended as any failed spawn ends
/// its child: its kill is waited for (`Reaped`, not `Killed`: the exit is collected), and one whose
/// kill is refused, which a UAC handle without `PROCESS_TERMINATE` is, comes back in the failure as
/// an `Unreaped`, not left running with nothing to name it. A child whose pid could not be read
/// (`GetProcessId` failed: a box with no pid) is ended the same, and its error and detail name no pid.
///
/// Mutants: the child is killed and not waited for; the refused child is not handed back; the error of
/// a child with no pid names the process's pid.
#[skuld::test]
fn an_untracked_uac_child_is_waited_for_and_a_refused_kill_hands_it_back() {
    use crate::elevation::windows::{end_untracked, Unread};

    let read_failure = || windows::core::Error::from_hresult(HRESULT::from_win32(6));
    // The rows: the identity could not be resolved (the box has its pid), or the pid could not be read.
    for pid_read in [true, false] {
        let unread = |pid: u32| -> Unread {
            if pid_read {
                Ok((pid, read_failure()))
            } else {
                Err(read_failure())
            }
        };
        let process = |handle, pid: u32| WindowsProcess::for_uac(HostKernel, handle, pid_read.then_some(pid));
        let ended = |child, pid| {
            crate::child::spawn::failure::error_parts(end_untracked(child, unread(pid), SpawnPolicy::SYNC).into())
        };

        let owner = Suspended::spawn();
        let child = OwnedChild::new(
            Box::new(process(owner.duplicate(), owner.pid)),
            TrackedKind::AnotherUser,
        );
        let (cause, fate, unreaped) = ended(child, owner.pid);
        assert_eq!(
            fate,
            ChildFate::Reaped,
            "the kill was waited for (pid read: {pid_read})"
        );
        assert!(unreaped.is_none(), "a collected child is handed back by none");
        assert!(
            !owner.wait_for_exit().success(),
            "the process was terminated, not left to run"
        );
        if !pid_read {
            assert!(
                !format!("{cause:?}").contains(&owner.pid.to_string()),
                "a child with no pid is named by none: {cause:?}"
            );
        }

        let owner = Suspended::spawn();
        let child = OwnedChild::new(
            Box::new(process(owner.without_terminate_right(), owner.pid)),
            TrackedKind::AnotherUser,
        );
        let (cause, fate, unreaped) = ended(child, owner.pid);
        assert_eq!(fate, ChildFate::Running { id: None }, "(pid read: {pid_read})");
        if !pid_read {
            assert!(
                !format!("{cause:?}").contains(&owner.pid.to_string()),
                "a refused child with no pid is named by none: {cause:?}"
            );
        }
        unreaped.expect("a child whose kill was refused is handed back").leak();
    }
}

// What each handle kind allows: the contract of a kill's refusal =====

/// Each kind of Windows handle states what its kill may be refused for, from how its constructor
/// built it: a `CreateProcess` handle holds `PROCESS_TERMINATE`, so never; a UAC elevation's handle
/// from the access it was granted.
///
/// Mutants: `for_uac` takes the handle for a `CreateProcess` one, or a granted right for a missing one.
#[skuld::test]
fn each_windows_handle_kind_states_what_its_kill_may_be_refused_for() {
    let owner = Suspended::spawn();
    let kind = |process: WindowsProcess<HostKernel>| process.kill_refusal();
    assert_eq!(
        kind(WindowsProcess::for_child(HostKernel, owner.duplicate(), owner.pid)),
        KillRefusal::Never
    );
    assert_eq!(
        kind(uac_process(owner.duplicate(), owner.pid)),
        KillRefusal::Never,
        "a UAC handle granted PROCESS_TERMINATE"
    );
    assert_eq!(
        kind(uac_process(owner.without_terminate_right(), owner.pid)),
        KillRefusal::Permission,
        "a UAC handle that was not"
    );
}

/// A `CreateProcess` handle holds `PROCESS_TERMINATE`, so its kill is never refused: a refusal for
/// want of permission breaks the contract too. A fake answers the refusal.
///
/// Mutant: `for_child` allows a refusal of permission.
#[cfg(debug_assertions)]
#[skuld::test]
#[should_panic(expected = "never refused")]
fn a_kill_of_a_createprocess_handle_refused_for_permission_breaks_the_contract() {
    let owner = Suspended::spawn();
    let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    let (child, _fake) = owned(real(owner.duplicate(), owner.pid).signals([Err(denied)]));
    crate::log_capture::install();
    after_a_failed_spawn(child, None, Past::Clean, Disposition::Leave, None);
}

/// The same for a UAC elevation's handle that was granted `PROCESS_TERMINATE`.
///
/// Mutant: `for_uac` allows a refusal of permission whatever it was granted.
#[cfg(debug_assertions)]
#[skuld::test]
#[should_panic(expected = "never refused")]
fn a_kill_of_a_uac_handle_granted_terminate_refused_for_permission_breaks_the_contract() {
    let owner = Suspended::spawn();
    let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    let (child, _fake) = owned(uac(owner.duplicate(), owner.pid).signals([Err(denied)]));
    crate::log_capture::install();
    after_a_failed_spawn(child, None, Past::Clean, Disposition::Leave, None);
}

/// A kill of a handle that may be refused for permission (a UAC handle) is refused only for that: any
/// other refusal breaks the contract. A fake answers the refusal.
///
/// Mutant: `warn_teardown` does not read the refusal's kind.
#[cfg(debug_assertions)]
#[skuld::test]
#[should_panic(expected = "refused for a reason other than permission")]
fn a_kill_refused_for_another_reason_than_permission_breaks_the_contract() {
    crate::log_capture::install();
    let fake = FakeProcess::new([])
        .with_kill_refusal(KillRefusal::Permission)
        .reaps([ReapAnswer::Exited(ExitRecord::Status(
            std::process::ExitStatus::default(),
        ))])
        .signals([Err(std::io::Error::from(std::io::ErrorKind::Other))]);
    let (child, _fake) = owned(fake);
    after_a_failed_spawn(child, None, Past::Clean, Disposition::Leave, None);
}

/// What a handle may be refused for is its constructor's, not its past's: a look that failed excuses a
/// failed wait, and no refusal against the handle's allowance.
///
/// Mutant: `Past::WaitMayFail` waives the check of a refusal against what the handle allows.
#[cfg(debug_assertions)]
#[skuld::test]
#[should_panic(expected = "never refused")]
fn a_failed_look_does_not_excuse_a_refusal_of_a_handle_that_is_never_refused() {
    crate::log_capture::install();
    let fake = FakeProcess::new([])
        .with_kill_refusal(KillRefusal::Never)
        .reaps([ReapAnswer::Exited(ExitRecord::Status(
            std::process::ExitStatus::default(),
        ))])
        .signals([Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))]);
    let (child, _fake) = owned(fake);
    after_a_failed_spawn(child, None, Past::WaitMayFail, Disposition::Leave, None);
}

/// The same for a refusal for a reason other than permission, of a handle that may be refused for
/// permission.
///
/// Mutant: `Past::WaitMayFail` waives the check of a refusal's kind.
#[cfg(debug_assertions)]
#[skuld::test]
#[should_panic(expected = "refused for a reason other than permission")]
fn a_failed_look_does_not_excuse_a_refusal_for_another_reason_than_permission() {
    crate::log_capture::install();
    let fake = FakeProcess::new([])
        .with_kill_refusal(KillRefusal::Permission)
        .reaps([ReapAnswer::Exited(ExitRecord::Status(
            std::process::ExitStatus::default(),
        ))])
        .signals([Err(std::io::Error::from(std::io::ErrorKind::Other))]);
    let (child, _fake) = owned(fake);
    after_a_failed_spawn(child, None, Past::WaitMayFail, Disposition::Leave, None);
}

/// A failed spawn that hands its child back, whose `TerminateProcess` is denied on a live child (a UAC
/// handle), comes back with the child, still running and nothing sent to it, and says so once.
///
/// Mutants: the child is dropped, or reported reaped; the kill is sent anyway (the child exits 1);
/// the warn says the child is left.
#[skuld::test]
fn a_failed_spawn_teardown_with_a_denied_terminate_hands_the_child_back() {
    let owner = Suspended::spawn();
    let id = owner.id();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let child = OwnedChild::new(
        Box::new(uac_process(owner.without_terminate_right(), owner.pid)),
        TrackedKind::AnotherUser,
    );

    let (fate, unreaped) = after_a_failed_spawn(child, Some(id), Past::Clean, Disposition::HandBack, None);

    assert_eq!(fate, ChildFate::Running { id: Some(id) });
    let unreaped = unreaped.expect("a refused kill under HandBack hands the child back");
    assert_eq!((unreaped.pid(), unreaped.id()), (Some(owner.pid), Some(id)));
    let warns = crate::log_capture::records_since_on_current_thread(mark, "handed back to the caller");
    assert_eq!(warns.len(), 1, "{warns:?}");
    // Ends it with code 0, which a process the teardown had killed (code 1) would not report.
    owner.end_with_code_zero()();
    let status = unreaped.wait().expect("wait for the handed-back child");
    assert_eq!(status.code(), Some(0), "nothing was sent to the child: {status:?}");
}

/// What failed in a failed spawn's teardown of `child` (a refused kill, a failed wait), as the
/// `cleanup` of the error the spawn returns, with the child's fate and the child it handed back.
fn failed_spawn_cleanup(child: OwnedChild, id: Option<ProcessId>, past: Past) -> crate::child::drop_teardown::Torn {
    tear_down_failed_spawn(
        child,
        id,
        past,
        Disposition::HandBack,
        SpawnPolicy::SYNC,
        &mut Diagnosis::default(),
    )
}

/// A kill the OS refuses is a failure of the spawn's teardown: it is in the error's `cleanup`, with
/// the refusal's code, beside the fate and the child handed back.
///
/// Mutant: the teardown reports the refusal to the log alone.
#[skuld::test]
fn a_failed_spawn_teardown_with_a_denied_terminate_reports_the_refusal_as_its_cleanup() {
    let owner = Suspended::spawn();
    let id = owner.id();
    let child = OwnedChild::new(
        Box::new(uac_process(owner.without_terminate_right(), owner.pid)),
        TrackedKind::AnotherUser,
    );

    let Torn {
        fate,
        unreaped,
        cleanup,
    } = failed_spawn_cleanup(child, Some(id), Past::Clean);

    assert_eq!(fate, ChildFate::Running { id: Some(id) });
    let cleanup = cleanup.expect("the refused kill is the teardown's failure");
    assert_eq!(cleanup.iter().len(), 1, "{cleanup:?}");
    assert_eq!(
        crate::error::first_os_code(&**cleanup.first()),
        Some(ERROR_ACCESS_DENIED.0 as i32),
        "{cleanup:?}"
    );
    assert!(
        crate::error::said(&**cleanup.first()).starts_with(&crate::error::io_said("killing the child: ")),
        "{cleanup:?}"
    );
    owner.end_with_code_zero()();
    unreaped
        .expect("handed back")
        .wait()
        .expect("wait for the handed-back child");
}

/// A wait that fails after a delivered kill is a failure of the teardown: it is the `cleanup`.
///
/// Mutant: the failed wait is in the clause's text alone.
#[skuld::test]
fn a_failed_spawn_teardown_with_a_failed_wait_reports_the_wait_as_its_cleanup() {
    let owner = Suspended::spawn();
    let (child, _fake) = owned(real(owner.duplicate(), owner.pid).reaps([ReapAnswer::Err(KIND)]));

    let Torn {
        fate,
        unreaped,
        cleanup,
    } = failed_spawn_cleanup(child, None, Past::WaitMayFail);

    assert_eq!(fate, ChildFate::Killed);
    let cleanup = cleanup.expect("the failed wait is the teardown's failure");
    assert_eq!(cleanup.iter().len(), 1, "{cleanup:?}");
    assert!(
        matches!(&**cleanup.first(), crate::error::Error::Io(e) if e.kind() == KIND)
            && crate::error::said(&**cleanup.first()).starts_with(&crate::error::io_said("waiting for the child: ")),
        "{cleanup:?}"
    );
    drop(unreaped);
}

/// A teardown that ended the child with no failure has no `cleanup`.
///
/// Mutant: an empty list is reported where there is nothing.
#[skuld::test]
fn a_failed_spawn_teardown_that_failed_in_nothing_has_no_cleanup() {
    let owner = Suspended::spawn();
    let (child, _fake) = owned(real(owner.duplicate(), owner.pid));

    let Torn {
        fate,
        unreaped,
        cleanup,
    } = failed_spawn_cleanup(child, None, Past::Clean);

    assert_eq!(fate, ChildFate::Reaped);
    assert!(unreaped.is_none());
    assert!(cleanup.is_none(), "{cleanup:?}");
}

// The drop's teardown =====

/// The kill is delivered and the teardown waits for the exit it started, then answers `Reaped`.
///
/// Mutants: `TerminateProcess` a no-op reporting `Ok` or `ERROR_ACCESS_DENIED`, so the process is
/// ended with code 0 once the wait blocks; the wait after an accepted terminate dropped.
#[skuld::test]
fn a_kill_teardown_of_a_child_waits_for_the_exit_it_started() {
    let owner = Suspended::spawn();
    let (handle, _fake) = handle_over(&owner, HostKernel, |fake| fake);
    // Keeps a no-op terminate from hanging the wait; see `Suspended::end_with_code_zero`.
    let _end = crate::wait::block_probe::on_blocking(owner.end_with_code_zero());
    let torn = handle.tear_down(
        Some(owner.id()),
        Kill {
            disposition: Disposition::Leave,
            tree: None,
        },
        None,
    );
    assert_eq!(torn.fate(), ChildFate::Reaped, "{torn:?}");
    assert!(
        matches!(torn.said(), Some(Wording::Collected(log::Level::Debug, _))),
        "{torn:?}"
    );
    assert!(handle.exit_seen(), "teardown must wait for the exit it started");
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

/// A UAC handle to a live child: the teardown looks once, never waits, and leaves it running. What it
/// could not do comes back for the caller's one warn.
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
    let (child, fake) = owned(uac(owner.without_terminate_right(), owner.pid));
    let handle = child;
    // Ends the owner's process once a wait blocks, so a teardown that waits fails the checks below
    // instead of hanging.
    let _end = crate::wait::block_probe::on_blocking(owner.end_with_code_zero());
    let torn = handle.tear_down(
        Some(id),
        Kill {
            disposition: Disposition::Leave,
            tree: None,
        },
        None,
    );
    assert_eq!(torn.fate(), ChildFate::Running { id: Some(id) }, "{torn:?}");
    assert!(
        matches!(torn.said(), Some(Wording::Uncollected(text)) if text.contains(&owner.pid.to_string())),
        "{torn:?}"
    );
    assert_eq!(fake.looks(), 1, "teardown looked once and did not wait");
    let warned = crate::log_capture::warns_since(mark, "");
    assert_eq!(
        warned,
        Vec::<String>::new(),
        "the teardown leaves the one warn to its caller"
    );
    assert!(
        matches!(
            handle.wait(Some(crate::wait::now())),
            Ok(ChildWaitOutcome::DeadlinePassed)
        ),
        "nothing ended the child"
    );
}

/// A UAC handle to a child that has exited: its signalled state is the exit, so the child is `Reaped`
/// and nothing is left running.
///
/// Mutant: the teardown reads the refusal by the handle's rights alone, so it leaves a dead child as
/// `Running`.
#[skuld::test]
fn teardown_of_a_handle_without_terminate_to_an_exited_child_reaps_it() {
    let owner = Suspended::spawn();
    let (child, _fake) = owned(uac(owner.without_terminate_right(), owner.pid));
    let handle = child;
    owner.end_with_code_zero()();
    owner.wait_for_exit();
    let torn = handle.tear_down(
        Some(owner.id()),
        Kill {
            disposition: Disposition::Leave,
            tree: None,
        },
        None,
    );
    assert_eq!(torn.fate(), ChildFate::Reaped, "{torn:?}");
    assert!(
        matches!(torn.said(), Some(Wording::Collected(log::Level::Debug, _))),
        "{torn:?}"
    );
}

/// A child whose exit is under way but not signalled yet, on a handle that holds
/// `PROCESS_TERMINATE`: the refusal is the exit, and the teardown waits for it.
///
/// Mutant: a refusal is the exit only for a signalled process, so the child is left `Running`.
#[skuld::test]
fn teardown_of_an_exiting_unsignalled_child_reaps_it() {
    let owner = Suspended::spawn();
    let kernel = Arc::new(refusing_the_next_terminate());
    let (handle, _fake) = handle_over(&owner, Arc::clone(&kernel), |fake| fake);
    let _end = crate::wait::block_probe::on_blocking(owner.end_with_code_zero());
    let torn = handle.tear_down(
        Some(owner.id()),
        Kill {
            disposition: Disposition::Leave,
            tree: None,
        },
        None,
    );
    assert!(
        kernel.all_rows_taken(),
        "the kill reached TerminateProcess to be refused"
    );
    assert_eq!(torn.fate(), ChildFate::Reaped, "{torn:?}");
    assert!(
        matches!(torn.said(), Some(Wording::Collected(log::Level::Debug, _))),
        "{torn:?}"
    );
}

/// The kill delivered nothing (the exit was under way), so, as on every OS, a failed wait shows
/// nothing of what became of the child: `Unknown`. One scripted
/// answer, so a second wait would be the real one and fail the count.
///
/// Mutants: a failed wait is `Killed` whatever the kill did; the teardown skips its kill.
#[skuld::test]
fn teardown_of_an_exiting_child_with_a_failed_wait_is_unknown() {
    let owner = Suspended::spawn();
    let kernel = Arc::new(refusing_the_next_terminate());
    let (handle, fake) = handle_over(&owner, Arc::clone(&kernel), |fake| fake.reaps([ReapAnswer::Err(KIND)]));
    let torn = handle.tear_down(
        Some(owner.id()),
        Kill {
            disposition: Disposition::Leave,
            tree: None,
        },
        None,
    );
    assert!(
        kernel.all_rows_taken(),
        "the kill reached TerminateProcess to be refused"
    );
    assert_eq!(torn.fate(), ChildFate::Unknown, "{torn:?}");
    assert_eq!(fake.looks(), 1, "the teardown made the wait that failed");
}
