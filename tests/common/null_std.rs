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
/// inherited the stray handle only where the route listed it. The std and argv routes inherit every
/// inheritable handle (std's behavior), so their stray state is not checked.
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
            "fd3" | "listed" | "pipe_fd3" => "open",
            "merge3" if stdout != "null" => "open",
            _ => "closed",
        };
        // The flag is set whenever a child end is non-null, and whenever this process holds a live
        // handle for a slot: a child end that is null there (a merge from a null slot) takes its null
        // only through the flag.
        let used = nulled != "all" || matches!(route, "pipe_out" | "null_io" | "pipe_fd3");
        // `std`'s route has no flag and inherits blanket, so the child gets this process's own
        // values, which `invalid:` made -1. The raw backend passes no handle to inherit: null.
        let blank = if set.starts_with("invalid:") && !used && matches!(route, "std" | "argv") {
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
        "listed",
        "merge3",
        "merge_live",
        "pipe_out",
        "null_io",
        "pipe_fd3",
    ];
    assert_eq!(got.len(), routes.len(), "{got:?}");
    for (route, line) in routes.iter().zip(&got) {
        let (line_no_nul, nul) = line.rsplit_once(",nul=").unwrap_or((line, "<missing>"));
        let (head, stray) = line_no_nul.rsplit_once(",stray=").unwrap_or((line_no_nul, "<missing>"));
        assert_eq!(head, want(route), "route {route} with {nulled} nulled: {line}");
        if *route == "merge_live" {
            // All three child ends are null, so the only handle the grandchild can hold that names
            // the NUL device is the one that spawn adds to make the inheritance list non-empty. With
            // no flag (all of this process's handles null) there is no list and no such handle.
            let want_nul = if nulled == "all" { "0" } else { "1" };
            assert_eq!(nul, want_nul, "route {route} with {nulled} nulled: {line}");
        }
        match *route {
            "std" | "argv" => {}
            "listed" => assert_eq!(stray, "true", "route {route} with {nulled} nulled: {line}"),
            _ => assert_eq!(stray, "false", "route {route} with {nulled} nulled: {line}"),
        }
    }
}
