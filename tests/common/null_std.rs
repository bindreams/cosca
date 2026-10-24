//! Runs the testbin's `spawn-with-null-std` mode and checks what each grandchild received.

use std::os::windows::process::CommandExt;

/// `CREATE_NO_WINDOW`: the intermediate gets a console of its own whether or not the test runner
/// has one, so the grandchildren's std handles do not depend on the runner's console.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// The `<route>=<report>` lines of `spawn-with-null-std <backend> <nulled>`.
pub fn reports(backend: &str, nulled: &str) -> Vec<String> {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cmd = std::process::Command::new(super::testbin());
    cmd.args(["spawn-with-null-std", backend, nulled])
        .arg(dir.path())
        .creation_flags(CREATE_NO_WINDOW);
    let out = super::output_locked(&mut cmd).expect("spawn the intermediate");
    assert!(
        out.status.success(),
        "intermediate failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .expect("UTF-8 report")
        .lines()
        .map(str::to_owned)
        .collect()
}

/// Every route spawned, and its grandchild got the std handles that `nulled` implies (`all`, or
/// std handle names joined by `+`), saw fd 3 as expected, and inherited the stray handle only where
/// the route listed it. The std and argv routes inherit every inheritable handle (std's behavior),
/// so their stray state is not checked.
pub fn assert_every_route(backend: &str, nulled: &str) {
    let is_null = |name: &str| nulled == "all" || nulled.split('+').any(|n| n == name);
    let kind = |name: &str, live: &'static str| if is_null(name) { "null" } else { live };
    let want = |route: &str| {
        let (stdin, stdout) = (kind("stdin", "char"), kind("stdout", "pipe"));
        // `exe_merge` merges stderr into stdout.
        let stderr = if route == "exe_merge" {
            stdout
        } else {
            kind("stderr", "pipe")
        };
        // `merge_live` merges every live slot from a nulled one: all three ends are null.
        let (stdin, stdout, stderr) = if route == "merge_live" {
            ("null", "null", "null")
        } else {
            (stdin, stdout, stderr)
        };
        let fd3 = match route {
            "fd3" | "listed" => "open",
            "merge3" if stdout != "null" => "open",
            _ => "closed",
        };
        // The flag is set whenever this process holds a live handle for a slot: a child end that
        // is null there (a merge from a null slot) takes its null only through the flag.
        let used = nulled != "all";
        format!("{route}=usestdhandles={used},stdin={stdin},stdout={stdout},stderr={stderr},fd3={fd3}")
    };
    let got = reports(backend, nulled);
    let routes = [
        "std",
        "argv",
        "exe",
        "fd3",
        "exe_merge",
        "listed",
        "merge3",
        "merge_live",
    ];
    assert_eq!(got.len(), routes.len(), "{got:?}");
    for (route, line) in routes.iter().zip(&got) {
        let (head, stray) = line.rsplit_once(",stray=").unwrap_or((line, "<missing>"));
        assert_eq!(head, want(route), "route {route} with {nulled} nulled: {line}");
        match *route {
            "std" | "argv" => {}
            "listed" => assert_eq!(stray, "true", "route {route} with {nulled} nulled: {line}"),
            _ => assert_eq!(stray, "false", "route {route} with {nulled} nulled: {line}"),
        }
    }
}
