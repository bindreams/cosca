use super::assert_may_block;
use super::Section;

#[skuld::test]
fn outside_a_section_a_wait_is_allowed() {
    assert_may_block("a test wait");
}

#[skuld::test]
#[should_panic(expected = "a test wait would block inside an async Drop")]
fn inside_a_section_a_wait_panics() {
    let _section = Section::enter();
    assert_may_block("a test wait");
}

#[skuld::test]
fn a_section_ends_when_dropped_and_nests() {
    let outer = Section::enter();
    let inner = Section::enter();
    drop(inner);
    assert!(
        std::panic::catch_unwind(|| assert_may_block("outer")).is_err(),
        "the outer section still covers this thread"
    );
    drop(outer);
    assert_may_block("after both");
}

#[skuld::test]
fn a_section_is_per_thread() {
    let _section = Section::enter();
    std::thread::spawn(|| assert_may_block("another thread"))
        .join()
        .expect("a thread outside the section may block");
}

// Every wait refuses to run inside a section -----
//
// One test per wait. Each uses a resource that returns at once if the assert is missing, so a
// regression fails on "did not panic" rather than hanging.

mod waits {
    use super::Section;

    /// `os_process::drive::exited_by`, which every platform's process-exit wait sits behind.
    ///
    /// Mutant: drop the assert from `os_process::drive::exited_by`.
    #[skuld::test]
    #[should_panic(expected = "would block inside an async Drop")]
    fn exited_by_id_refuses_inside_a_section() {
        let _section = Section::enter();
        _ = crate::os_process::drive::exited_by_id(
            crate::identity::ProcessId::current(),
            Some(std::time::Duration::ZERO),
        );
    }

    /// `Attached::wait_drained`, on a mechanism with no drain edge: refused all the same.
    ///
    /// Mutant: drop the assert from `Attached::wait_drained`.
    #[skuld::test]
    #[should_panic(expected = "would block inside an async Drop")]
    fn attached_wait_drained_refuses_inside_a_section() {
        let _section = Section::enter();
        _ = crate::containment::Attached::None.wait_drained(Some(Some(std::time::Instant::now())));
    }

    /// `CgroupLeaf::wait_drained`, on a fake leaf that never drains.
    ///
    /// Mutant: drop the assert from `CgroupLeaf::wait_drained`.
    #[cfg(target_os = "linux")]
    #[skuld::test(labels = [crate::test_harness::CGROUP])]
    #[should_panic(expected = "would block inside an async Drop")]
    fn cgroup_wait_drained_refuses_inside_a_section() {
        use crate::containment::cgroup::test_support::{entered_leaf_at, FakeLeaf};

        let fake = FakeLeaf::new("cosca-bounded-cgroup-wait-drained", true);
        let leaf = entered_leaf_at(fake.leaf.clone());
        // Disarmed: the fake never drains, so an armed `Drop` would block forever.
        leaf.disarm();
        let _section = Section::enter();
        _ = leaf.wait_drained(Some(Some(std::time::Instant::now())));
    }

    /// The macOS marker's `wait_drained`, on a marker whose write end nothing holds.
    ///
    /// Mutant: drop the assert from `Marker::wait_drained`.
    #[cfg(target_os = "macos")]
    #[skuld::test]
    #[should_panic(expected = "would block inside an async Drop")]
    fn marker_wait_drained_refuses_inside_a_section() {
        use crate::containment::fdmarker::{pipe_handle_of, Marker, PreparedMarker};
        use std::os::fd::{AsFd, OwnedFd};

        let (read, _write) = std::io::pipe().expect("pipe");
        let read = OwnedFd::from(read);
        let handle = pipe_handle_of(read.as_fd()).expect("handle");
        let marker = Marker::new(
            PreparedMarker {
                read,
                handle,
                read_handle: handle,
                fd: 3,
            },
            crate::containment::fdmarker::fdmarker_tests::inert_root(),
            None,
        );
        let _section = Section::enter();
        _ = marker.wait_drained(Some(Some(std::time::Instant::now())));
    }

    /// `JobHandle::wait_drained`, before it looks at the handle.
    ///
    /// Mutant: drop the assert from `JobHandle::wait_drained`.
    #[cfg(windows)]
    #[skuld::test]
    #[should_panic(expected = "would block inside an async Drop")]
    fn job_wait_drained_refuses_inside_a_section() {
        let job = crate::containment::windows::JobHandle::create_empty_for_test();
        let _section = Section::enter();
        _ = job.wait_drained(Some(Some(std::time::Instant::now())), None);
    }

    /// `wait_drained_raw`, the loop the async wrapper hands to a blocking thread.
    ///
    /// Mutant: drop the assert from `wait_drained_raw`.
    #[cfg(windows)]
    #[skuld::test]
    #[should_panic(expected = "would block inside an async Drop")]
    fn job_wait_drained_raw_refuses_inside_a_section() {
        let job = crate::containment::windows::JobHandle::create_empty_for_test();
        let raw = job.as_handle().expect("a live job handle");
        let _section = Section::enter();
        _ = crate::containment::windows::wait_drained_raw(raw, Some(Some(std::time::Instant::now())), None);
    }

    /// `wait_process_or_cancel`, the cancellable twin.
    ///
    /// Mutant: drop the assert from `wait_process_or_cancel`.
    #[cfg(windows)]
    #[skuld::test]
    #[should_panic(expected = "would block inside an async Drop")]
    fn wait_process_or_cancel_refuses_inside_a_section() {
        let cancel = crate::wait::backend::new_cancel_event().expect("event");
        use crate::os_process::{Exit, WaitFor};

        let mut process = crate::os_process::open(crate::identity::ProcessId::current(), crate::os_process::Op::Wait)
            .expect("open")
            .expect("the current process opens");
        let Exit::Running(WaitFor::Signalled(handle)) = process.exited().expect("look") else {
            panic!("the current process is running");
        };
        let _section = Section::enter();
        _ = crate::wait::backend::wait_process_or_cancel(handle, Some(std::time::Instant::now()), &cancel);
    }
}
