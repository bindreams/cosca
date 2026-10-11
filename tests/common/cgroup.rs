//! cgroup v2 helpers for the Linux cgroup lane.

/// The cgroup v2 leaf `pid` is in, as an absolute path. Mirrors the join
/// `containment::cgroup` makes for itself: `/proc/<pid>/cgroup`'s `0::` line is relative to
/// this process's cgroup namespace, whose root is `/sys/fs/cgroup`.
pub fn cgroup_of(pid: u32) -> std::path::PathBuf {
    let contents = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).expect("read /proc/<pid>/cgroup");
    let rel = contents
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .expect("a cgroup v2 unified (`0::`) line")
        .to_string();
    std::path::Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/'))
}

/// This process's own cgroup directory, from the `0::` line of `/proc/self/cgroup`. `Err` when the line is missing: the
/// host is not on cgroup v2, which the `cgroup` group requires.
pub fn own_cgroup() -> Result<std::path::PathBuf, String> {
    let text = std::fs::read_to_string("/proc/self/cgroup").map_err(|e| format!("read /proc/self/cgroup: {e}"))?;
    own_cgroup_in(&text)
}

/// [`own_cgroup`] for the given text of `/proc/self/cgroup`.
pub fn own_cgroup_in(text: &str) -> Result<std::path::PathBuf, String> {
    let rel = text
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| format!("no cgroup v2 `0::` line in /proc/self/cgroup: {text:?}"))?;
    Ok(std::path::Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/')))
}

/// The text of a caught panic's payload.
fn payload_text(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
        .unwrap_or_else(|| "a panic with a non-text payload".to_owned())
}

/// Removes `leaf` when dropped, so a test that fails before its own [`drain_and_remove_leaf`] leaves no leaf behind.
/// Members still in the leaf are killed first (`cgroup.kill`), because the handles that would release them drop after
/// this guard, and the child cgroups under it go with it ([`remove_tree`]). A leaf already gone is accepted. Any other
/// failure fails the test, or is printed if the test is already panicking.
///
/// A panic inside the removal is caught and reported with its payload: a second panic during unwinding aborts the
/// test binary.
pub struct LeafGuard(std::path::PathBuf);

impl LeafGuard {
    pub fn new(leaf: std::path::PathBuf) -> LeafGuard {
        LeafGuard(leaf)
    }
}

impl Drop for LeafGuard {
    fn drop(&mut self) {
        let leaf = &self.0;
        let failure = match std::panic::catch_unwind(|| remove_tree(leaf)) {
            Ok(Ok(())) => return,
            Ok(Err(why)) => why,
            Err(payload) => format!("the removal panicked: {}", payload_text(&*payload)),
        };
        super::fail_unless_panicking(format!("could not remove the leaf {}: {failure}", leaf.display()));
    }
}

/// Kills what is still in `leaf` (`cgroup.kill`), waits for it to drain, removes the child cgroups under it deepest
/// first, then the leaf. A directory on another filesystem than the leaf is a mount over a cgroup: it is left alone
/// and reported. `NotFound` and `ENODEV` mean the cgroup is gone, which is the goal.
pub fn remove_tree(leaf: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    // Absent on the success path (the leaf is gone) and on a plain directory.
    match std::fs::OpenOptions::new().write(true).open(leaf.join("cgroup.kill")) {
        Ok(mut kill) => {
            use std::io::Write as _;
            if let Err(e) = kill.write_all(b"1") {
                if !is_gone(&e) {
                    return Err(format!("write cgroup.kill: {e}"));
                }
            }
        }
        Err(e) if is_gone(&e) => {}
        Err(e) => return Err(format!("open cgroup.kill: {e}")),
    }
    try_wait_drained(leaf)?;
    let dev = match std::fs::metadata(leaf) {
        Ok(meta) => meta.dev(),
        Err(e) if is_gone(&e) => return Ok(()),
        Err(e) => return Err(format!("stat the leaf: {e}")),
    };
    let mut failures = Vec::new();
    remove_dir_deepest_first(leaf, dev, &mut failures);
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

fn is_gone(e: &std::io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::ENOENT) | Some(libc::ENODEV))
}

fn remove_dir_deepest_first(dir: &std::path::Path, dev: u64, failures: &mut Vec<String>) {
    use std::os::unix::fs::MetadataExt as _;

    match std::fs::read_dir(dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                // A cgroup's control files are files; its child cgroups are directories.
                let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
                    continue;
                };
                if !meta.is_dir() {
                    continue;
                }
                if meta.dev() != dev {
                    failures.push(format!("{} is mounted over; left alone", entry.path().display()));
                    continue;
                }
                remove_dir_deepest_first(&entry.path(), dev, failures);
            }
        }
        Err(e) if is_gone(&e) => return,
        Err(e) => {
            failures.push(format!("list {}: {e}", dir.display()));
            return;
        }
    }
    match std::fs::remove_dir(dir) {
        Ok(()) => {}
        Err(e) if is_gone(&e) => {}
        Err(e) => failures.push(format!("remove {}: {e}", dir.display())),
    }
}

/// `path` is a mount point in `mountinfo` (the text of `/proc/self/mountinfo`): the fifth field of a line equals it
/// exactly. A substring match would also take a mount below `path`, or one whose name extends it.
pub fn is_mount_point(mountinfo: &str, path: &std::path::Path) -> bool {
    mountinfo.lines().any(|line| {
        line.split(' ')
            .nth(4)
            .is_some_and(|field| unescape_mountinfo(field) == path.as_os_str().as_encoded_bytes())
    })
}

/// `\040`-style octal escapes of a mountinfo field.
fn unescape_mountinfo(field: &str) -> Vec<u8> {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let octal = bytes.get(i + 1..i + 4).and_then(|d| {
            let text = std::str::from_utf8(d).ok()?;
            (bytes[i] == b'\\' && d.iter().all(|b| (b'0'..=b'7').contains(b)))
                .then(|| u8::from_str_radix(text, 8).ok())
                .flatten()
        });
        match octal {
            Some(byte) => {
                out.push(byte);
                i += 4;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    out
}

/// Is `path` a mount point of this process's mount namespace? `Err` when mountinfo cannot be read: an unreadable
/// mountinfo is not "no mount".
pub fn is_mounted(path: &std::path::Path) -> Result<bool, String> {
    mount_state(std::fs::read_to_string("/proc/self/mountinfo"), path)
}

/// [`is_mounted`] for the result of reading mountinfo.
pub fn mount_state(mountinfo: std::io::Result<String>, path: &std::path::Path) -> Result<bool, String> {
    mountinfo
        .map(|text| is_mount_point(&text, path))
        .map_err(|e| format!("read /proc/self/mountinfo: {e}"))
}

/// Wait for `leaf` to drain, then remove it, unless something else removes it first.
///
/// A tree whose handle opted out of teardown, still running when the handle drops, leaves its leaf
/// behind, and cosca does not come back for it. Removing it is the test's job, so the lane that counts stray
/// `cosca-*` leaves counts none of the tests' own.
///
/// The wait is on kernel events, never on a clock, and wakes on either of two, armed before the
/// first read: `cgroup.events` changing, and the leaf's removal (`IN_DELETE` on its parent). The
/// second matters because removing a cgroup can cancel the `populated` notification the kernel
/// postponed (see cosca's `DrainWatch`), and the handle's own `Drop` may remove the leaf
/// concurrently: an async drop may remove a drained leaf. `ENOENT` or `ENODEV` from any step
/// means it is gone, which is the goal.
pub fn drain_and_remove_leaf(leaf: &std::path::Path) {
    wait_drained(leaf);
    match std::fs::remove_dir(leaf) {
        Ok(()) => {}
        Err(e) if is_gone(&e) => {}
        Err(e) => panic!("remove the drained leaf: {e}"),
    }
}

/// Block until `leaf` has no live member: `populated` reads 0, or the leaf is gone. See
/// [`drain_and_remove_leaf`] for the wait.
pub fn wait_drained(leaf: &std::path::Path) {
    if let Err(why) = try_wait_drained(leaf) {
        panic!("{why}");
    }
}

/// [`wait_drained`], reporting a failure instead of panicking.
pub fn try_wait_drained(leaf: &std::path::Path) -> Result<(), String> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    use rustix::fs::inotify;

    let name = leaf.file_name().ok_or("a leaf has a name")?.to_os_string();
    let watch = inotify::init(inotify::CreateFlags::CLOEXEC).map_err(|e| format!("create an inotify instance: {e}"))?;
    let parent = inotify::add_watch(
        &watch,
        leaf.parent().ok_or("a leaf has a parent")?,
        inotify::WatchFlags::DELETE,
    )
    .map_err(|e| format!("watch the leaf's parent: {e}"))?;
    match inotify::add_watch(&watch, leaf.join("cgroup.events"), inotify::WatchFlags::MODIFY) {
        Ok(_) => {}
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(e) => return Err(format!("watch cgroup.events: {e}")),
    }
    let mut events = match std::fs::File::open(leaf.join("cgroup.events")) {
        Ok(f) => f,
        Err(e) if is_gone(&e) => return Ok(()),
        Err(e) => return Err(format!("open the leaf's cgroup.events: {e}")),
    };
    let mut buf = String::new();
    loop {
        buf.clear();
        match events
            .seek(SeekFrom::Start(0))
            .and_then(|_| events.read_to_string(&mut buf))
        {
            Ok(_) => {}
            Err(e) if is_gone(&e) => return Ok(()),
            Err(e) => return Err(format!("read cgroup.events: {e}")),
        }
        if buf.lines().any(|l| l.trim() == "populated 0") {
            return Ok(());
        }
        // Blocks for at least one event. `read` is never restarted after a signal handler, and a
        // tokio runtime in this process handles SIGCHLD: an interrupted read re-reads `populated`.
        let mut raw = [std::mem::MaybeUninit::<u8>::uninit(); 4096];
        let mut reader = inotify::Reader::new(&watch, &mut raw);
        loop {
            match reader.next() {
                Ok(event) => {
                    let named = event
                        .file_name()
                        .is_some_and(|n| n.to_bytes() == name.as_encoded_bytes());
                    if event.wd() == parent && named {
                        return Ok(());
                    }
                }
                Err(rustix::io::Errno::INTR) => {}
                Err(e) => return Err(format!("read the inotify watch: {e}")),
            }
            if reader.is_buffer_empty() {
                break;
            }
        }
    }
}
