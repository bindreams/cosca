//! The one table of what `contain_without_cgroup` gets. Also compiled into the library's tests
//! (`src/test_child.rs`), which cannot share `tests/common/mod.rs`.

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
