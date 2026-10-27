#[skuld::test]
fn test_hooks_reach_the_lib_unit_tests() {
    assert!(crate::audit::enabled(), "__test_hooks is off in the lib's unit tests");
}
