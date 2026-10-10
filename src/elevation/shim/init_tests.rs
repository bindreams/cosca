use std::process::Command;

#[skuld::test]
fn init_marks_the_process_installed() {
    // The test binary's `main` calls `init`, so only a fresh process can show `installed` going from
    // false to true; it asks (`testbin/shim_hooks.rs`) and exits.
    let mut command = Command::new(std::env::current_exe().expect("the test binary's path"));
    command.env_clear().env("COSCA_TEST_INIT_PROBE", "1");
    let out = crate::test_spawn::output_captured(&mut command).expect("the probe runs");
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "installed before=false after=true\n",
        "`init` returns in a process that is not a shim, having marked it installed"
    );
}
