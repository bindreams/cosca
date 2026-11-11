//! The one table of what a test asks of containment and gets. Also compiled into the library's
//! tests (`src/test_child.rs`), which cannot share `tests/common/mod.rs`.

/// The mechanism `contain_without_cgroup` gets on this platform: a session on Linux, the
/// inherited-fd marker on macOS, a Job Object on Windows. A test that asks for it asserts exactly
/// this, never a set. Any other platform is rejected at compile time by the crate itself.
pub const fn contain_without_cgroup_gives() -> cosca::Containment {
    #[cfg(target_os = "linux")]
    return cosca::Containment::Session;
    #[cfg(target_os = "macos")]
    return cosca::Containment::FdMarker;
    #[cfg(windows)]
    return cosca::Containment::JobObject;
}

/// The mechanism an explicit `ContainMode::Session` request gets: a session on Linux, promoted to
/// the fd marker on macOS, which installs it for every contained root.
#[cfg(unix)]
pub const fn session_gives() -> cosca::Containment {
    #[cfg(target_os = "linux")]
    return cosca::Containment::Session;
    #[cfg(target_os = "macos")]
    return cosca::Containment::FdMarker;
}

/// The mechanism an explicit `ContainMode::TreeWalk` request gets: the identity walk on Linux and
/// Windows, promoted to the fd marker on macOS.
pub const fn tree_walk_gives() -> cosca::Containment {
    #[cfg(target_os = "macos")]
    return cosca::Containment::FdMarker;
    #[cfg(not(target_os = "macos"))]
    return cosca::Containment::TreeWalk;
}

/// The mechanism whose tree a test can wait on to drain: a cgroup leaf on Linux, the same one
/// `contain_without_cgroup` gets elsewhere. On Linux the cgroup leaf exists only for a test that
/// takes the `cgroup` fixture and asks `.contain()`; without both, `.contain()` degrades.
pub const fn drainable_gives() -> cosca::Containment {
    #[cfg(target_os = "linux")]
    return cosca::Containment::CgroupV2;
    #[cfg(not(target_os = "linux"))]
    return contain_without_cgroup_gives();
}
