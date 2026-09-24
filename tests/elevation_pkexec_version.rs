//! `Backend::Pkexec` end to end, through the production `detect()`: a testbin child, whose `PATH`
//! holds only a fake `pkexec`, runs a cosca elevated spawn and reports the outcome. The fake is
//! testbin itself, copied to `real/pkexec-impl` (an ELF, as the pinned exec needs), which logs
//! what it was run as and prints a version; it never elevates. A root run's child drops to an id the
//! user namespace maps, so detection sees a non-root caller; where no such id exists the test fails
//! and names the cause.
//!
//! Linux only: cosca launches pkexec on Linux alone, and that pkexec is never run elsewhere is
//! pinned by `detect_opens_and_probes_only_for_a_request_that_launches_pkexec` and the planner.
#![cfg(target_os = "linux")]

#[path = "common/mod.rs"]
mod common;

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// What the testbin reported, each line the fake `pkexec` logged (empty: never run; see
/// `fake_pkexec` in testbin), the fake's real file, and the directory the launch named.
struct Outcome {
    report: String,
    pkexec_argvs: Vec<String>,
    real: String,
}

/// What the elevated spawn names: an absolute program, or a relative `raw_executable("tool")` in
/// a `target/` directory holding `tool`.
#[derive(Clone, Copy)]
enum Launch {
    BinTrue,
    RelativeRaw,
}

/// Run the `elevate-pkexec-report` mode with a fake `pkexec` that prints `version_line`.
///
/// This process may be root, so it never writes through a path another user could swap. The
/// temp root is its own, under a root-owned sticky `/tmp` (traversable by every uid, where
/// `TMPDIR` may be private), and is made 0o755 through a descriptor. The log and the fake are
/// created fresh (`O_EXCL`, `O_NOFOLLOW`), the fake relative to a held descriptor for `bin`.
/// The log is 0o600 and owned by the uid the child runs as, so no other user can rewrite it.
fn elevate_with_fake_pkexec(version_line: &str, launch: Launch) -> Outcome {
    use std::os::unix::fs::OpenOptionsExt;
    // SAFETY: geteuid has no preconditions.
    let as_root = unsafe { libc::geteuid() } == 0;
    // First: in a user namespace the ids below are not what they seem, and this names that cause.
    let drop_to = as_root.then(drop_target);
    let tmp = std::fs::canonicalize("/tmp").expect("canonicalize /tmp");
    if as_root {
        assert_root_owned_and_sticky(&tmp);
    }
    let root_guard = tempfile::Builder::new()
        .prefix("cosca-pkexec-")
        .tempdir_in(&tmp)
        .expect("tempdir under /tmp");
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(root_guard.path())
        .and_then(|d| d.set_permissions(std::fs::Permissions::from_mode(0o755)))
        .expect("chmod the temp root through a descriptor");
    let root = std::fs::canonicalize(root_guard.path()).expect("canonicalize root");
    if as_root {
        assert_traversable_by_everyone(&root);
    }
    let (bin, real_dir, target) = (root.join("bin"), root.join("real"), root.join("target"));
    for dir in [&bin, &real_dir, &target] {
        std::fs::create_dir(dir).expect("mkdir");
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        assert_eq!(
            &std::fs::canonicalize(dir).expect("canonicalize"),
            dir,
            "stays in the temp root"
        );
    }
    let log = root.join("pkexec.log");
    let log_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(&log)
        .expect("create the log");
    if let Some((uid, gid)) = drop_to {
        // Appendable by the uid the testbin drops to, and by no other.
        std::os::unix::fs::fchown(&log_file, Some(uid), Some(gid)).expect("chown the log");
    }
    log_file
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .expect("chmod the log");
    drop(log_file);
    {
        // No fork in this binary may hold the fake open for writing when it is exec'd.
        let _guard = cosca::test_spawn_lock();
        let testbin = std::fs::read(common::testbin()).expect("read testbin");
        let mut fake = create_in(&real_dir, c"pkexec-impl", 0o755);
        fake.write_all(&testbin).expect("write the fake pkexec");
        fake.set_permissions(std::fs::Permissions::from_mode(0o755))
            .expect("chmod pkexec");
        let mut version = create_in(&real_dir, c"version", 0o644);
        writeln!(version, "{version_line}").expect("write the version");
        version
            .set_permissions(std::fs::Permissions::from_mode(0o644))
            .expect("chmod version");
        let mut tool = create_in(&target, c"tool", 0o644);
        writeln!(tool, "#!/bin/sh").expect("write tool");
        tool.set_permissions(std::fs::Permissions::from_mode(0o644))
            .expect("chmod tool");
    }
    std::os::unix::fs::symlink("../real/pkexec-impl", bin.join("pkexec")).expect("link bin/pkexec");
    assert_eq!(
        std::fs::canonicalize(bin.join("pkexec")).expect("canonicalize pkexec"),
        real_dir.join("pkexec-impl"),
        "the fake stays in the temp root"
    );
    let mut testbin = std::process::Command::new(common::testbin());
    testbin.arg("elevate-pkexec-report").env("PATH", &bin);
    match launch {
        Launch::BinTrue => testbin.arg("/bin/true"),
        Launch::RelativeRaw => testbin.args(["tool".as_ref(), target.as_os_str()]),
    };
    if let Some((uid, gid)) = drop_to {
        testbin.env("COSCA_TEST_DROP_TO", format!("{uid}:{gid}"));
    }
    let out = common::output_locked(&mut testbin).expect("run the testbin");
    assert!(
        out.status.success(),
        "testbin failed: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    Outcome {
        report: String::from_utf8(out.stdout)
            .expect("utf-8 report")
            .trim_end()
            .to_owned(),
        pkexec_argvs: read_log(&log),
        real: real_dir.join("pkexec-impl").display().to_string(),
    }
}

/// A new file `name` in `dir`, created relative to a descriptor held on `dir` itself
/// (`O_CREAT | O_EXCL | O_NOFOLLOW`), so no path component is resolved twice.
fn create_in(dir: &Path, name: &std::ffi::CStr, mode: libc::c_uint) -> std::fs::File {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::OpenOptionsExt;
    let dir = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(dir)
        .expect("open the directory");
    // SAFETY: a valid directory fd and a NUL-terminated name; the result is checked.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    assert!(fd >= 0, "openat {name:?}: {}", std::io::Error::last_os_error());
    // SAFETY: `fd` was just opened and is owned by nothing else.
    unsafe { std::fs::File::from_raw_fd(fd) }
}

/// `S_ISVTX`, the same bit everywhere; `libc`'s constant differs in type between Linux and macOS.
const STICKY: u32 = 0o1000;

/// The uid and gid a root run's testbin drops to: 65534 where this user namespace maps it, else
/// the first other id it maps. Fails, naming the cause, where it maps none (`unshare -r`, a
/// rootless container with no subordinate ids): no non-root caller can exist there.
fn drop_target() -> (u32, u32) {
    let pick = |file: &str| {
        let map = std::fs::read_to_string(file).unwrap_or_else(|e| panic!("read {file}: {e}"));
        mapped_non_root(&map).unwrap_or_else(|| {
            panic!(
                "{file} maps no id but 0 ({map:?}): this root run is in a user namespace with no \
                 unprivileged id to drop to, so the pkexec test cannot run as a non-root caller"
            )
        })
    };
    (pick("/proc/self/uid_map"), pick("/proc/self/gid_map"))
}

/// `nobody`, preferred wherever it is mapped.
const NOBODY: u32 = 65534;

/// A non-zero id `map` (a `/proc/self/{uid,gid}_map`: lines of `inside outside count`) maps:
/// [`NOBODY`] if it does, else the lowest non-zero one.
fn mapped_non_root(map: &str) -> Option<u32> {
    let ranges: Vec<(u64, u64)> = map
        .lines()
        .map(|line| {
            let f: Vec<u64> = line
                .split_whitespace()
                .map(|n| n.parse().expect("an id map number"))
                .collect();
            assert_eq!(f.len(), 3, "an id map line is `inside outside count`: {line:?}");
            (f[0], f[0] + f[2])
        })
        .collect();
    if ranges.iter().any(|&(lo, hi)| (lo..hi).contains(&u64::from(NOBODY))) {
        return Some(NOBODY);
    }
    ranges
        .iter()
        .filter_map(|&(lo, hi)| (lo.max(1) < hi).then_some(lo.max(1)))
        .min()
        .map(|id| u32::try_from(id).expect("a mapped id fits in u32"))
}

#[test]
fn mapped_non_root_prefers_nobody_then_the_lowest_other_id() {
    assert_eq!(mapped_non_root("         0          0 4294967295\n"), Some(NOBODY));
    assert_eq!(mapped_non_root("         0       1000          1\n"), None);
    assert_eq!(mapped_non_root("0 1000 1\n1 100000 65536\n"), Some(NOBODY));
    assert_eq!(mapped_non_root("0 1000 1\n1 100000 100\n"), Some(1));
    assert_eq!(mapped_non_root("0 0 5\n"), Some(1));
    assert_eq!(mapped_non_root("500 1000 10\n0 0 1\n"), Some(500));
    assert_eq!(mapped_non_root(""), None);
}

/// `dir` is owned by root and sticky, so no other user can rename or replace an entry this
/// process creates in it.
fn assert_root_owned_and_sticky(dir: &Path) {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(dir).expect("lstat");
    assert!(
        meta.is_dir() && meta.uid() == 0 && meta.mode() & STICKY != 0,
        "{} is uid {} mode {:o}: a root test run needs it root-owned and sticky, or another user could \
         swap the fixture's entries",
        dir.display(),
        meta.uid(),
        meta.mode()
    );
}

/// Every directory from `/` to `dir` lets any uid through, so the child can reach the fake once
/// it has dropped root.
fn assert_traversable_by_everyone(dir: &Path) {
    for d in dir.ancestors() {
        let mode = std::fs::metadata(d).expect("stat").permissions().mode();
        assert!(
            mode & 0o001 != 0,
            "{} is mode {mode:o}: the unprivileged uid the testbin drops to cannot reach the fake pkexec",
            d.display()
        );
    }
}

fn read_log(log: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(log).unwrap_or_else(|e| panic!("read {}: {e}", log.display()));
    text.lines().map(str::to_owned).collect()
}

/// A pkexec older than polkit 121 is asked only its version, and the spawn is refused.
#[test]
fn an_old_pkexec_is_refused_after_only_being_asked_its_version() {
    let o = elevate_with_fake_pkexec("pkexec version 0.105", Launch::BinTrue);
    assert!(o.report.starts_with("UNSUPPORTED "), "{}", o.report);
    assert!(o.report.contains("reports version 0.105"), "{}", o.report);
    assert_eq!(o.pkexec_argvs, [format!("argv0={0} exe={0} args=--version", o.real)]);
}

/// A pkexec of polkit 121 or later is launched with `--keep-cwd`: the same file the probe ran
/// (`exe`), with the canonical path as `argv[0]`.
#[test]
fn a_new_pkexec_is_launched_with_keep_cwd() {
    let o = elevate_with_fake_pkexec("pkexec version 121", Launch::BinTrue);
    assert_eq!(o.report, "OK", "the fake pkexec exits 0");
    let cwd = std::env::current_dir().expect("cwd").display().to_string();
    assert_eq!(
        o.pkexec_argvs,
        [
            format!("argv0={0} exe={0} args=--version", o.real),
            format!(
                "argv0={0} exe={0} args=--disable-internal-agent --keep-cwd /bin/true f_ok=true x_ok=true cwd={cwd}",
                o.real
            )
        ]
    );
}

/// A relative `raw_executable()` is refused before detection, so pkexec is never run, not even to
/// ask its version.
#[test]
fn a_relative_raw_executable_is_refused_before_pkexec_runs() {
    let o = elevate_with_fake_pkexec("pkexec version 121", Launch::RelativeRaw);
    assert!(o.report.starts_with("UNSUPPORTED "), "{}", o.report);
    assert!(o.report.contains("absolute program path"), "{}", o.report);
    assert!(o.pkexec_argvs.is_empty(), "{:?}", o.pkexec_argvs);
}
