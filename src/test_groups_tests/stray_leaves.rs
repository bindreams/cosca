//! The `cgroup` group's removal of the leaves a test leaves behind, and the helpers it shares with the integration
//! tests' `LeafGuard`.

use std::path::{Path, PathBuf};

use crate::test_groups::cgroup_leaf::{is_mount_point, mount_state, own_cgroup_in, remove_tree, LeafGuard};
use crate::test_groups::{cgroup, namespaces, Group, StrayLeaves};

fn leaf_of_pid(dir: &Path, pid: u32) -> PathBuf {
    let leaf = dir.join(format!("cosca-{pid}-0-abc"));
    std::fs::create_dir(&leaf).unwrap();
    leaf
}

/// A leaf with a child cgroup two levels down, as a plain directory tree.
fn nested_leaf(dir: &Path) -> PathBuf {
    let leaf = leaf_of_pid(dir, std::process::id());
    std::fs::create_dir_all(leaf.join("child/grandchild")).unwrap();
    leaf
}

fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
        .unwrap_or_default()
}

// StrayLeaves -----

/// A leaf of this pid left in the cgroup fails the test that ended with it, and the check removes it, child cgroups
/// included. Mutants: the check is deleted; it only reports; it removes the leaf before its children.
#[skuld::test]
fn a_leaf_left_behind_is_removed_and_fails_the_test() {
    let dir = tempfile::tempdir().unwrap();
    let leaf = nested_leaf(dir.path());
    let stray = StrayLeaves::of(Ok(dir.path().to_path_buf()));
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(stray)));
    let payload = outcome.expect_err("a leaf was left behind and the check passed");
    assert!(
        panic_text(&*payload).contains("left cgroup leaves behind"),
        "{}",
        panic_text(&*payload)
    );
    assert!(!leaf.exists(), "the leaf was reported and left in place");
}

/// A test that is already failing gets the leaves removed and printed, not a second panic (which aborts the binary).
#[skuld::test]
fn a_failing_test_has_its_leaf_removed_without_a_second_panic() {
    let dir = tempfile::tempdir().unwrap();
    let leaf = nested_leaf(dir.path());
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _stray = StrayLeaves::of(Ok(dir.path().to_path_buf()));
        panic!("the test fails first");
    }));
    assert_eq!(
        panic_text(&*outcome.expect_err("the test panicked")),
        "the test fails first"
    );
    assert!(!leaf.exists(), "the leaf was left in place");
}

/// Another process's leaf, and an unrelated cgroup, are not this test's: they stay.
#[skuld::test]
fn only_this_pids_leaves_are_removed() {
    let dir = tempfile::tempdir().unwrap();
    let other = leaf_of_pid(dir.path(), std::process::id() + 1);
    let unrelated = dir.path().join("unrelated");
    std::fs::create_dir(&unrelated).unwrap();
    drop(StrayLeaves::of(Ok(dir.path().to_path_buf())));
    assert!(other.exists() && unrelated.exists());
}

/// An own cgroup that cannot be listed fails the test: the check does not turn itself off. Mutant: a silent return.
#[skuld::test]
fn an_unlistable_own_cgroup_fails_the_test() {
    let dir = tempfile::tempdir().unwrap();
    let stray = StrayLeaves::of(Ok(dir.path().join("missing")));
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(stray)));
    let payload = outcome.expect_err("the cgroup could not be listed and the check passed");
    assert!(
        panic_text(&*payload).contains("cannot list"),
        "{}",
        panic_text(&*payload)
    );
}

/// An own cgroup that cannot be determined fails at once. Mutant: the check is built empty.
#[skuld::test]
fn an_unknown_own_cgroup_fails_the_fixture() {
    let outcome = std::panic::catch_unwind(|| StrayLeaves::of(Err("no cgroup v2".to_owned())));
    assert!(outcome.is_err(), "a check that watches nothing was built");
}

/// The own cgroup comes from the `0::` line only: a cgroup v1 listing has none, which `cgroup` group refuses.
#[skuld::test]
fn the_own_cgroup_is_the_unified_line() {
    assert_eq!(
        own_cgroup_in("12:cpu:/legacy\n0::/user.slice/x\n").unwrap(),
        Path::new("/sys/fs/cgroup/user.slice/x")
    );
    assert_eq!(own_cgroup_in("0::/\n").unwrap(), Path::new("/sys/fs/cgroup"));
    assert!(own_cgroup_in("12:cpu:/legacy\n11:memory:/legacy\n").is_err());
}

// remove_tree and LeafGuard -----

/// A directory on another filesystem under the leaf is a mount over a cgroup: it is reported and left alone, with
/// everything on it. Mutant: the removal crosses into it.
#[skuld::test]
fn remove_tree_never_crosses_a_mount(#[fixture(namespaces)] _group: &Group) {
    use std::ffi::CString;

    let dir = tempfile::tempdir().unwrap();
    let leaf = nested_leaf(dir.path());
    let mounted = leaf.join("child");
    let leaf_in_thread = leaf.clone();
    let outcome = std::thread::spawn(move || {
        let c = |p: &Path| CString::new(p.as_os_str().as_encoded_bytes()).expect("no NUL");
        // SAFETY: plain syscalls on valid NUL-terminated strings. `unshare` gives this thread alone a mount
        // namespace, which dies with it; making it private first keeps the mount below inside it.
        unsafe {
            assert_eq!(
                libc::unshare(libc::CLONE_NEWNS),
                0,
                "unshare: {}",
                std::io::Error::last_os_error()
            );
            assert_eq!(
                libc::mount(
                    std::ptr::null(),
                    c(Path::new("/")).as_ptr(),
                    std::ptr::null(),
                    libc::MS_REC | libc::MS_PRIVATE,
                    std::ptr::null()
                ),
                0,
                "make / private: {}",
                std::io::Error::last_os_error()
            );
            assert_eq!(
                libc::mount(
                    c(Path::new("tmpfs")).as_ptr(),
                    c(&leaf_in_thread.join("child")).as_ptr(),
                    c(Path::new("tmpfs")).as_ptr(),
                    0,
                    std::ptr::null()
                ),
                0,
                "mount tmpfs over the child: {}",
                std::io::Error::last_os_error()
            );
        }
        std::fs::write(leaf_in_thread.join("child/keep"), "").unwrap();
        let outcome = remove_tree(&leaf_in_thread);
        (outcome, leaf_in_thread.join("child/keep").exists())
    })
    .join()
    .expect("the removing thread");
    let (outcome, survived) = outcome;
    assert!(survived, "the removal crossed the mount");
    let why = outcome.expect_err("a mount over a cgroup is reported");
    assert!(why.contains("mounted over"), "{why}");
    assert!(mounted.is_dir(), "the mount point was removed");
}

/// The guard removes a leaf with child cgroups. Mutant: it removes the leaf alone.
#[skuld::test]
fn a_leaf_guard_removes_the_leaf_and_its_children() {
    let dir = tempfile::tempdir().unwrap();
    let leaf = nested_leaf(dir.path());
    drop(LeafGuard::new(leaf.clone()));
    assert!(!leaf.exists());
}

/// A leaf that is already gone is accepted. Mutant: the guard fails on `NotFound`.
#[skuld::test]
fn a_leaf_guard_accepts_a_leaf_that_is_already_gone() {
    let dir = tempfile::tempdir().unwrap();
    drop(LeafGuard::new(dir.path().join("cosca-gone")));
}

/// A leaf that cannot be removed fails the test, naming it. Mutant: the failure is only printed.
#[skuld::test]
fn a_leaf_guard_fails_the_test_when_the_leaf_stays() {
    let dir = tempfile::tempdir().unwrap();
    let leaf = leaf_of_pid(dir.path(), std::process::id());
    // A regular file under the leaf is not a cgroup: `rmdir` of the leaf fails with ENOTEMPTY.
    std::fs::write(leaf.join("stuck"), "").unwrap();
    let guard = LeafGuard::new(leaf.clone());
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(guard)));
    let payload = outcome.expect_err("the leaf stayed and the guard passed");
    assert!(
        panic_text(&*payload).contains(&leaf.display().to_string()),
        "{}",
        panic_text(&*payload)
    );
}

/// While the test is already failing, a leaf that stays is printed and the test's own panic is what surfaces.
#[skuld::test]
fn a_leaf_guard_in_a_failing_test_does_not_abort() {
    let dir = tempfile::tempdir().unwrap();
    let leaf = leaf_of_pid(dir.path(), std::process::id());
    std::fs::write(leaf.join("stuck"), "").unwrap();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = LeafGuard::new(leaf.clone());
        panic!("the test fails first");
    }));
    assert_eq!(
        panic_text(&*outcome.expect_err("the test panicked")),
        "the test fails first"
    );
}

// mountinfo -----

const MOUNTINFO: &str = "\
36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
37 35 98:0 /x /with\\040space rw - ext3 /dev/root rw
";

/// A mount point is the fifth field, exactly. Mutants: a substring match takes a mount below the path or one whose name
/// extends it.
#[skuld::test]
fn a_mount_point_is_matched_exactly() {
    assert!(is_mount_point(MOUNTINFO, Path::new("/mnt2")));
    assert!(
        !is_mount_point(MOUNTINFO, Path::new("/mnt")),
        "a prefix of a mount point"
    );
    assert!(
        !is_mount_point(MOUNTINFO, Path::new("/mnt2/sub")),
        "below a mount point"
    );
    assert!(
        !is_mount_point(MOUNTINFO, Path::new("/mnt1")),
        "the root field is not the mount point"
    );
    assert!(
        is_mount_point(MOUNTINFO, Path::new("/with space")),
        "octal escapes are decoded"
    );
}

/// Mountinfo that cannot be read is an error, not "no mount". Mutant: `unwrap_or_default`.
#[skuld::test]
fn unreadable_mountinfo_is_not_no_mount() {
    let unreadable = Err(std::io::Error::from_raw_os_error(libc::EACCES));
    assert!(mount_state(unreadable, Path::new("/mnt2")).is_err());
    assert_eq!(mount_state(Ok(MOUNTINFO.to_owned()), Path::new("/mnt2")), Ok(true));
    assert_eq!(mount_state(Ok(String::new()), Path::new("/mnt2")), Ok(false));
}

// The wiring -----

/// Written by the fixture below to say which leaf it left.
const FIXTURE_ENV: &str = "COSCA_TEST_STRAY_LEAF_FIXTURE";

/// A real `cgroup` group test that leaves a leaf, with a child cgroup holding a live process, and removes nothing.
/// It acts only when [`a_cgroup_test_that_leaves_a_leaf_fails_and_the_leaf_is_gone`] re-executes it (the environment
/// names that driver's pid); in an ordinary run it does nothing.
#[skuld::test]
fn fixture_a_cgroup_test_that_leaves_a_leaf(#[fixture(cgroup)] _group: &Group) {
    let Some(value) = std::env::var_os(FIXTURE_ENV) else {
        return;
    };
    let value = value.into_string().expect("UTF-8");
    let (driver, report) = value.split_once(':').expect("<driver pid>:<report file>");
    if std::os::unix::process::parent_id().to_string() != driver {
        return;
    }
    let own = crate::test_groups::cgroup_leaf::own_cgroup().expect("cgroup v2");
    let leaf = own.join(format!("cosca-{}-0-fixture", std::process::id()));
    std::fs::create_dir(&leaf).expect("make the leaf");
    let child = leaf.join("child");
    std::fs::create_dir(&child).expect("make a child cgroup");
    let member = crate::test_spawn::spawn(
        std::process::Command::new("sleep")
            .arg("3600")
            // The driver reads this test's output to its end: a member holding the pipe would hold the driver.
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null()),
    )
    .expect("spawn a member");
    std::fs::write(child.join("cgroup.procs"), member.id().to_string()).expect("place the member in the child");
    std::fs::write(report, leaf.as_os_str().as_encoded_bytes()).expect("report the leaf");
}

/// A `cgroup` group test that leaves a leaf fails, and the leaf is gone afterwards, a live member and a child cgroup
/// included. Mutants: the group is not wired to the check (`watching_leaves` dropped from its row), or the check
/// only reports.
#[skuld::test]
fn a_cgroup_test_that_leaves_a_leaf_fails_and_the_leaf_is_gone(#[fixture(cgroup)] _group: &Group) {
    use crate::test_reexec::{command, fixture_args, suite_outcome, with_json_events};

    let report = tempfile::NamedTempFile::new().unwrap();
    let mut cmd = command(std::env::current_exe().expect("current_exe"));
    // A misspelled name runs no test, and the assertion on the report below says so.
    cmd.args(fixture_args(crate::test_child::strip_crate_prefix(concat!(
        module_path!(),
        "::fixture_a_cgroup_test_that_leaves_a_leaf"
    ))));
    with_json_events(&mut cmd);
    cmd.env(
        FIXTURE_ENV,
        format!("{}:{}", std::process::id(), report.path().display()),
    );
    let output = crate::test_spawn::output_captured(&mut cmd).expect("re-exec this test binary");
    let stdout = String::from_utf8_lossy(&output.stdout);

    let outcome = suite_outcome(&output.stdout).expect("the child reports its suite");
    let leaf = PathBuf::from(std::fs::read_to_string(report.path()).expect("read the report"));
    assert!(!leaf.as_os_str().is_empty(), "the fixture did not run: {stdout}");
    assert_eq!(
        (outcome.passed, outcome.failed),
        (0, 1),
        "the leaf was left and the test passed: {stdout}"
    );
    assert!(stdout.contains("left cgroup leaves behind"), "{stdout}");
    assert!(!leaf.exists(), "the leaf {} is still there", leaf.display());
}
