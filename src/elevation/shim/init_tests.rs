#[skuld::test]
fn init_marks_the_process_installed() {
    // The lib's test binary calls `init_with_test_hooks` first thing in `main`.
    assert!(super::installed());
}
