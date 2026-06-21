use super::{is_running, start_token};

#[test]
fn start_token_of_current_process_is_stable() {
    let pid = std::process::id();
    let a = start_token(pid).expect("the current process has a start token");
    let b = start_token(pid).expect("re-read should also succeed");
    assert_eq!(a, b); // raw creation FILETIME is fixed for a process's lifetime
}

#[test]
fn current_process_reads_as_running() {
    let pid = std::process::id();
    let tok = start_token(pid).expect("token");
    assert!(is_running(pid, tok), "we are obviously running");
    // A wrong token (PID reuse) must not read as running, even for a live pid.
    let wrong = super::StartToken::from_raw(tok.raw().wrapping_add(1));
    assert!(!is_running(pid, wrong));
}
