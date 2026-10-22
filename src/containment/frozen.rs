//! A frozen child's containment state: what keeps it from being stranded while the caller holds
//! it before it ran, and what releases it.
//!
//! Windows only. `Frozen` is uninhabited elsewhere, so the types that carry one need no `cfg`.

#[cfg(windows)]
#[path = "frozen/windows.rs"]
mod windows;
#[cfg(all(test, windows))]
pub(crate) use windows::observe;
#[cfg(windows)]
pub(crate) use windows::Frozen;

/// Off Windows nothing can be frozen: `Command::spawn_suspended` is `Unsupported` there, and this
/// type has no value.
#[cfg(not(windows))]
#[derive(Debug)]
pub(crate) enum Frozen {}

#[cfg(not(windows))]
impl Frozen {
    /// Unreachable: no value of this type exists.
    pub(crate) fn release(self, _child: &crate::child::Child) -> std::io::Result<()> {
        match self {}
    }
}
