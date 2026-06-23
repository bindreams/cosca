//! Unit tests for Windows Job Object containment helpers.
//! Substantive runtime coverage is in the integration tests (tests/spawn_io.rs).

#[test]
fn job_handle_debug_does_not_panic() {
    // Verify the Debug impl compiles and runs cleanly for a consumed handle.
    use super::JobHandle;
    use std::sync::atomic::AtomicPtr;
    // Construct a consumed (null) JobHandle to verify the Debug impl path.
    // SAFETY: this is test-only; we do NOT pass this to any Win32 call.
    let h = JobHandle {
        raw: AtomicPtr::new(std::ptr::null_mut()),
    };
    let s = format!("{h:?}");
    assert!(s.contains("JobHandle"), "debug output: {s}");
}
