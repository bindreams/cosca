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

/// The mechanism whose tree a test can wait on to drain: a cgroup leaf on Linux (the test takes
/// the `cgroup` fixture and `.contain()`), the same one `contain_without_cgroup` gets elsewhere.
pub const fn drainable_gives() -> cosca::Containment {
    #[cfg(target_os = "linux")]
    return cosca::Containment::CgroupV2;
    #[cfg(not(target_os = "linux"))]
    return contain_without_cgroup_gives();
}
