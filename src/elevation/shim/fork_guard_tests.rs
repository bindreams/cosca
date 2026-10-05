use super::{ForkGuard, Origin};
#[cfg(target_os = "linux")]
use crate::test_groups::{namespaces, Group};

#[skuld::test]
fn the_creator_is_the_original() {
    assert_eq!(ForkGuard::new().unwrap().origin(), Origin::Original);
}

/// A real fork copy reads `false`. Mutants: Linux, the page is not marked `MADV_WIPEONFORK` (the copy
/// reads the marker); macOS, `origin` is always `Original`.
#[skuld::test]
fn a_fork_copy_is_not_the_original() {
    let guard = ForkGuard::new().unwrap();
    // SAFETY: the child only reads the guard and `_exit`s.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork");
    if pid == 0 {
        // SAFETY: `_exit` never returns.
        unsafe { libc::_exit(if guard.origin() == Origin::Copy { 0 } else { 1 }) };
    }
    let mut status = 0;
    // SAFETY: `pid` is this test's own unreaped child.
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "the copy saw itself as the original (status {status:#x})"
    );
    assert_eq!(guard.origin(), Origin::Original, "the fork did not change the original");
}

/// Checking needs no descriptor: with none to spare, it still answers.
#[skuld::test]
fn checking_with_a_full_fd_table_works() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(checking_with_a_full_fd_table_works),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let guard = ForkGuard::new().unwrap();
    let _restore = crate::test_child::exhaust_fds(&done);
    assert!(
        std::fs::File::open("/dev/null").is_err(),
        "the precondition: no descriptor can be opened"
    );
    assert_eq!(guard.origin(), Origin::Original);
}

#[skuld::test]
fn a_guard_that_cannot_say_answers_unknown() {
    let guard = ForkGuard::new().unwrap();
    guard.make_unreadable();
    assert_eq!(guard.origin(), Origin::Unknown);
}

#[cfg(target_os = "macos")]
extern "C" {
    fn sandbox_init(profile: *const libc::c_char, flags: u64, errorbuf: *mut *mut libc::c_char) -> libc::c_int;
}

/// Seatbelt entered after creation denies `proc_pidinfo` on the process itself, which the audit
/// token does not need. Mutant: the guard reads its unique id with `proc_pidinfo`.
#[cfg(target_os = "macos")]
#[skuld::test]
fn macos_the_original_is_still_the_original_inside_a_sandbox() {
    let Some(_done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(macos_the_original_is_still_the_original_inside_a_sandbox),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let guard = ForkGuard::new().unwrap();
    let profile = std::ffi::CString::new("(version 1)(allow default)(deny process-info*)").unwrap();
    let mut error = std::ptr::null_mut();
    // SAFETY: a profile text (flags 0), and a pointer for the error text.
    let entered = unsafe { sandbox_init(profile.as_ptr(), 0, &mut error) };
    assert_eq!(entered, 0, "sandbox_init");
    assert_eq!(guard.origin(), Origin::Original);
}

/// In another pid namespace a fork copy has the owner's pid (1, for an init). Only the guard tells
/// them apart. Mutant: the guard compares pids.
#[cfg(target_os = "linux")]
#[skuld::test]
fn namespaces_a_copy_with_the_owners_pid_is_not_the_original(#[fixture(namespaces)] _group: &Group) {
    crate::test_child::namespaces::run(crate::test_child::fixture_path!(fixture_owner_is_pid_1));
}

#[cfg(target_os = "linux")]
#[skuld::test]
fn fixture_owner_is_pid_1() {
    use crate::test_child::namespaces as ns;
    if !ns::is_child() {
        return;
    }
    ns::enter_new_pid_ns_for_children();
    ns::run(crate::test_child::fixture_path!(fixture_owner_in_its_namespace));
}

#[cfg(target_os = "linux")]
#[skuld::test]
fn fixture_owner_in_its_namespace() {
    use crate::test_child::namespaces as ns;
    if !ns::is_child_in_new_pid_ns() {
        return;
    }
    assert_eq!(std::process::id(), 1, "the owner is pid 1 of its namespace");
    let guard = ForkGuard::new().unwrap();
    // The next fork's child is pid 1 of a namespace of its own.
    ns::enter_new_pid_ns_for_children();
    // SAFETY: the child only reads the guard and `_exit`s.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork");
    if pid == 0 {
        let same_pid = std::process::id() == 1;
        // SAFETY: `_exit` never returns.
        unsafe {
            libc::_exit(if same_pid && guard.origin() == Origin::Copy {
                0
            } else {
                1
            })
        };
    }
    let mut status = 0;
    // SAFETY: `pid` is this test's own unreaped child.
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "a copy with the owner's pid must not be the original (status {status:#x})"
    );
}
