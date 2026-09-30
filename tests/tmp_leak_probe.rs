//! THROWAWAY probe (do not merge): a test that leaks a process holding its stdout/stderr must
//! fail under `--profile ci`.
#[test]
fn leaks_a_process_holding_the_test_pipes() {
    // Inherits this test's stdout/stderr and outlives the test.
    std::process::Command::new("sleep").arg("30").spawn().expect("spawn sleeper");
}
