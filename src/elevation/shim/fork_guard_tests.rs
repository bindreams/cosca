use super::ForkGuard;
#[cfg(target_os = "linux")]
use crate::test_groups::{namespaces, Group};

#[skuld::test]
fn the_creator_is_the_original() {
    assert!(ForkGuard::new().unwrap().is_original());
}

/// A real fork copy reads `false`. Mutants: Linux, the page is not marked `MADV_WIPEONFORK` (the copy
/// reads the marker); macOS, `is_original` is always true.
#[skuld::test]
fn a_fork_copy_is_not_the_original() {
    let guard = ForkGuard::new().unwrap();
    // SAFETY: the child only reads the guard and `_exit`s.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork");
    if pid == 0 {
        // SAFETY: `_exit` never returns.
        unsafe { libc::_exit(if guard.is_original() { 1 } else { 0 }) };
    }
    let mut status = 0;
    // SAFETY: `pid` is this test's own unreaped child.
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "the copy saw itself as the original (status {status:#x})"
    );
    assert!(guard.is_original(), "the fork did not change the original");
}

/// Checking needs no descriptor: with none to spare, it still answers.
#[skuld::test]
fn checking_with_a_full_fd_table_works() {
    let fixture = crate::test_child::fixture_path!(fixture_check_with_a_full_fd_table);
    crate::test_child::run_fixture_command(fixture, crate::test_child::fixture_command(fixture));
}

#[skuld::test]
fn fixture_check_with_a_full_fd_table() {
    if !crate::test_child::is_fixture_reexec() {
        return;
    }
    let guard = ForkGuard::new().unwrap();
    crate::test_child::exhaust_fds();
    assert!(
        std::fs::File::open("/dev/null").is_err(),
        "the precondition: no descriptor can be opened"
    );
    assert!(guard.is_original());
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
        unsafe { libc::_exit(if same_pid && !guard.is_original() { 0 } else { 1 }) };
    }
    let mut status = 0;
    // SAFETY: `pid` is this test's own unreaped child.
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "a copy with the owner's pid must not be the original (status {status:#x})"
    );
}
