use crate::test_reexec::{command, SCRUBBED_ENV};
use std::ffi::OsStr;

#[test]
fn reexec_command_scrubs_skuld_env() {
    let cmd = command("x");
    let envs: Vec<_> = cmd.get_envs().collect();
    for var in ["SKULD_LABELS", "SKULD_NEXTEST_METADATA_PATH"] {
        assert!(
            envs.contains(&(OsStr::new(var), None)),
            "{var} must be removed from the child's environment: {envs:?}"
        );
    }
}

#[test]
fn the_scrubbed_list_is_what_the_builder_removes() {
    let cmd = command("x");
    let removed: Vec<_> = cmd.get_envs().filter(|(_, v)| v.is_none()).map(|(k, _)| k).collect();
    assert_eq!(removed, SCRUBBED_ENV.map(OsStr::new));
}
