//! The settle rule's classification of a thread's run state and flags.

use super::{all_parked, parked, threads_with, verdict, Stop, Thread};

const NO_FLAGS: i32 = 0;

/// Mutant: an uninterruptible thread counts as parked. A traced stop's thread blocks
/// uninterruptibly on a kernel lock, keeping its kernel stack, between setting `SSTOP` and
/// waiting on `sigwait`.
#[test]
fn an_uninterruptible_thread_is_not_parked() {
    assert!(!parked(libc::TH_STATE_UNINTERRUPTIBLE, NO_FLAGS));
}

/// Mutant: no exemption, so a stop with a never-started thread never settles.
#[test]
fn an_uninterruptible_thread_without_a_kernel_stack_is_parked() {
    assert!(parked(libc::TH_STATE_UNINTERRUPTIBLE, libc::TH_FLAGS_SWAPPED));
}

/// Mutants: a running thread counts as parked; so does any thread without a kernel stack.
#[test]
fn a_running_thread_is_not_parked() {
    assert!(!parked(libc::TH_STATE_RUNNING, NO_FLAGS));
    assert!(!parked(libc::TH_STATE_RUNNING, libc::TH_FLAGS_SWAPPED));
}

/// Mutant: one of these states is rejected, so a stop with such a thread never settles.
#[test]
fn a_waiting_suspended_or_halted_thread_is_parked() {
    assert!(parked(libc::TH_STATE_WAITING, NO_FLAGS));
    assert!(parked(libc::TH_STATE_STOPPED, NO_FLAGS));
    assert!(parked(libc::TH_STATE_HALTED, NO_FLAGS));
    assert!(parked(libc::TH_STATE_WAITING, libc::TH_FLAGS_SWAPPED));
}

/// A listed thread in `run_state`, with no flags.
fn thread(run_state: i32) -> Thread {
    // SAFETY: `proc_threadinfo` is plain data; all-zero is a valid value.
    let mut thread: libc::proc_threadinfo = unsafe { std::mem::zeroed() };
    thread.pth_run_state = run_state;
    (0, Some(thread))
}

/// A thread that exited between the listing and its read.
const VANISHED: Thread = (0, None);

/// Mutants: the verdict reads only the first thread, or only the last, so a stop whose stopping
/// thread is listed elsewhere settles while that thread still runs.
#[test]
fn a_stop_settles_only_once_every_thread_is_parked() {
    let waiting = thread(libc::TH_STATE_WAITING);
    let running = thread(libc::TH_STATE_RUNNING);
    let uninterruptible = thread(libc::TH_STATE_UNINTERRUPTIBLE);
    assert!(!all_parked(&[waiting, running]));
    assert!(!all_parked(&[waiting, running, waiting]));
    assert!(!all_parked(&[waiting, waiting, uninterruptible]));
    assert!(all_parked(&[waiting, thread(libc::TH_STATE_STOPPED)]));
}

/// A thread that exited between the listing and its read leaves the stop unsettled, so every
/// state peeks again under its backoff. Mutant: it counts as parked.
#[test]
fn a_thread_that_vanished_mid_read_is_not_parked() {
    let waiting = thread(libc::TH_STATE_WAITING);
    assert!(!all_parked(&[waiting, VANISHED, waiting]));
}

/// A listed thread's read meeting `ESRCH` names that thread, not the process. Mutant: `threads`
/// propagates it, `stop` answers `Running`, and S3 then waits for a `SIGCHLD` it already
/// consumed.
#[test]
fn a_thread_read_meeting_esrch_is_a_vanished_thread() {
    let read = |id| match id {
        2 => Err(libc::ESRCH),
        3 => Err(libc::EPERM),
        _ => Ok(id),
    };
    assert_eq!(threads_with(|| Ok(vec![1, 2]), read), Ok(vec![(1, Some(1)), (2, None)]));
    assert_eq!(threads_with(|| Ok(vec![1, 3]), read), Err(libc::EPERM));
    assert_eq!(threads_with(|| Err(libc::ESRCH), read), Err(libc::ESRCH));
}

/// A stop peek, `si_pid` 0 for none.
fn peeked(si_pid: libc::pid_t) -> libc::siginfo_t {
    // SAFETY: `siginfo_t` is plain data; all-zero is a valid value.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    info.si_pid = si_pid;
    info.si_status = libc::SIGSTOP;
    info
}

/// Mutants: a vanished thread ends the peek as `Running`, or the process being gone reads as
/// settling or as an error.
#[test]
fn a_vanished_thread_reads_as_settling_and_a_vanished_process_as_running() {
    let waiting = thread(libc::TH_STATE_WAITING);
    let stopped = peeked(1);
    assert_eq!(
        verdict(&stopped, || Ok(vec![waiting])),
        Ok(Stop::Stopped(libc::SIGSTOP))
    );
    assert_eq!(verdict(&stopped, || Ok(vec![waiting, VANISHED])), Ok(Stop::Settling));
    assert_eq!(verdict(&stopped, || Err(libc::ESRCH)), Ok(Stop::Running));
    assert_eq!(verdict(&stopped, || Err(libc::EPERM)), Err(libc::EPERM));
    assert_eq!(
        verdict(&peeked(0), || -> Result<_, i32> {
            panic!("no stop, so no thread read")
        }),
        Ok(Stop::Running)
    );
}

/// Mutant: an unknown run state counts as parked.
#[test]
#[should_panic(expected = "pth_run_state 0 is no TH_STATE_*")]
fn an_unknown_run_state_fails_loudly() {
    parked(0, NO_FLAGS);
}

/// A raw Mach thread, created but never started, terminated on drop.
struct UnstartedMachThread(mach2::mach_types::thread_act_t);

unsafe extern "C" {
    /// `<mach/thread_act.h>`; not in `mach2`.
    fn thread_terminate(target_act: mach2::mach_types::thread_act_t) -> mach2::kern_return::kern_return_t;
}

impl UnstartedMachThread {
    fn new() -> UnstartedMachThread {
        let mut thread = 0;
        // SAFETY: a valid out-pointer; the thread belongs to this task and is never started.
        let kr = unsafe { mach2::task::thread_create(mach2::traps::mach_task_self(), &mut thread) };
        assert_eq!(kr, mach2::kern_return::KERN_SUCCESS, "thread_create");
        UnstartedMachThread(thread)
    }

    /// Its unique thread id (`THREAD_IDENTIFIER_INFO`).
    fn id(&self) -> u64 {
        // SAFETY: `thread_identifier_info` is plain data; all-zero is a valid value.
        let mut info: libc::thread_identifier_info = unsafe { std::mem::zeroed() };
        let mut count = libc::THREAD_IDENTIFIER_INFO_COUNT;
        // SAFETY: `info` is writable for `count` words.
        let kr = unsafe {
            libc::thread_info(
                self.0,
                libc::THREAD_IDENTIFIER_INFO as libc::thread_flavor_t,
                (&raw mut info).cast(),
                &mut count,
            )
        };
        assert_eq!(kr, libc::KERN_SUCCESS, "thread_info");
        info.thread_id
    }
}

impl Drop for UnstartedMachThread {
    fn drop(&mut self) {
        // SAFETY: this task's own thread, which never ran.
        let kr = unsafe { thread_terminate(self.0) };
        assert_eq!(kr, mach2::kern_return::KERN_SUCCESS, "thread_terminate");
        // SAFETY: the send right `thread_create` returned.
        unsafe { mach2::mach_port::mach_port_deallocate(mach2::traps::mach_task_self(), self.0) };
    }
}

/// Raw Mach threads never set a TSD base, so a listing keyed by it (`PROC_PIDLISTTHREADS`) names
/// every one of them 0, and a read of 0 returns only the first. Two never-started ones must each
/// be listed and read. Mutant: threads listed by TSD base.
#[test]
fn threads_without_a_tsd_base_read_as_distinct_threads() {
    let mach_threads = [UnstartedMachThread::new(), UnstartedMachThread::new()];
    let listed = super::threads(std::process::id()).expect("list this process's threads");
    for id in mach_threads.iter().map(UnstartedMachThread::id) {
        let info = listed
            .iter()
            .find_map(|&(listed_id, info)| (listed_id == id).then_some(info))
            .unwrap_or_else(|| panic!("thread {id} is not listed"))
            .unwrap_or_else(|| panic!("thread {id} vanished"));
        assert_eq!(
            (info.pth_run_state, info.pth_flags & libc::TH_FLAGS_SWAPPED),
            (libc::TH_STATE_UNINTERRUPTIBLE, libc::TH_FLAGS_SWAPPED),
            "thread {id} does not read as never started"
        );
    }
}
