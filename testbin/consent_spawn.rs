//! The `consent-spawn <report> <envdump> <dir>` mode: elevate `cosca_testbin_image --report-to
//! <report> --dump-env-to <envdump>` through the consent route, in `<dir>`, and exit with its code.

/// Run the elevated image and exit with its exit code. The image is the one built beside this
/// testbin.
pub fn run(report: &str, env_dump: &str, dir: &str) {
    // An elevated caller takes the already-elevated route, which never reaches `ShellExecuteExW`.
    assert!(
        !cosca::elevation::is_elevated(),
        "consent-spawn must run unelevated to take the consent route"
    );
    let image = std::env::current_exe()
        .expect("current_exe")
        .with_file_name("cosca_testbin_image.exe");
    let mut cmd = cosca::Command::new();
    cmd.args([
        image.as_os_str(),
        "--report-to".as_ref(),
        report.as_ref(),
        "--dump-env-to".as_ref(),
        env_dump.as_ref(),
    ])
    .current_dir(dir)
    .elevate();
    let status = cmd.status().expect("the elevated image");
    std::process::exit(status.code().expect("a Windows exit code"));
}
