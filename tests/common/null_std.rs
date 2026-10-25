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

/// Every route spawned, and its grandchild got the std handles that `set` implies (`all`, or std
/// handle names joined by `+`, each optionally prefixed `invalid:`), saw fd 3 as expected, and
/// inherited the stray handle: every route hands the child every inheritable handle.
pub fn assert_every_route(backend: &str, set: &str) {
    // `invalid:` sets `INVALID_HANDLE_VALUE` rather than null; the child must see the same.
    let nulled = set.strip_prefix("invalid:").unwrap_or(set);
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
        let (stdin, stdout, stderr) = match route {
            "merge_live" => ("null", "null", "null"),
            // The caller configures these ends: they are real whatever this process's are.
            "pipe_out" | "pipe_fd3" => (stdin, "pipe", stderr),
            "null_io" => ("char", "char", stderr),
            _ => (stdin, stdout, stderr),
        };
        let fd3 = match route {
            "fd3" | "stray_fd3" | "pipe_fd3" => "open",
            "merge3" if stdout != "null" => "open",
            _ => "closed",
        };
        // The flag is set whenever a child end is non-null, and whenever this process holds a live
        // handle for a slot: a child end that is null there (a merge from a null slot) takes its null
        // only through the flag.
        let used = nulled != "all" || matches!(route, "pipe_out" | "null_io" | "pipe_fd3");
        // With no flag the child gets this process's own values, which `invalid:` made -1, on the
        // raw routes as on `std`'s.
        let blank = if set.starts_with("invalid:") && !used {
            "invalid"
        } else {
            "null"
        };
        let name = |kind: &'static str| if kind == "null" { blank } else { kind };
        let (stdin, stdout, stderr) = (name(stdin), name(stdout), name(stderr));
        format!("{route}=usestdhandles={used},stdin={stdin},stdout={stdout},stderr={stderr},fd3={fd3}")
    };
    let got = reports(backend, set);
    let routes = [
        "std",
        "argv",
        "exe",
        "fd3",
        "exe_merge",
        "stray_fd3",
        "merge3",
        "merge_live",
        "pipe_out",
        "null_io",
        "pipe_fd3",
    ];
    assert_eq!(got.len(), routes.len(), "{got:?}");
    for (route, line) in routes.iter().zip(&got) {
        let (head, stray) = line.rsplit_once(",stray=").unwrap_or((line, "<missing>"));
        assert_eq!(head, want(route), "route {route} with {nulled} nulled: {line}");
        // Every route hands the grandchild every inheritable handle, the stray file included.
        assert_eq!(stray, "true", "route {route} with {nulled} nulled: {line}");
    }
}
