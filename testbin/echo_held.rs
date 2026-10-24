//! Env vars shared by the testbin and `tests/common/member.rs`.

/// Set (to any value) in a member's environment to make the `control-block` family answer each
/// byte the test writes instead of leaving on the first one, so a test can tell a killed member
/// from one that is alive. The `control-echo-pid` members echo regardless.
pub const ECHO_HELD_ENV: &str = "COSCA_TEST_ECHO_HELD";

/// Set (to an integer) in a member's environment to make a `control-echo-pid` member that leaves
/// because the test closed its socket exit with that code, not `0`. A test whose kill has an
/// unmeasured exit code uses it to tell a member that was released from one that was killed,
/// without depending on the kill's code.
pub const RELEASED_EXIT_ENV: &str = "COSCA_TEST_RELEASED_EXIT";
