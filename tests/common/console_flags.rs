//! The one place that decides which console a Windows test child gets.
//!
//! A console child spawned by a process that has no console opens a visible window of its own, so
//! every test child is spawned `CREATE_NO_WINDOW` unless its test asks for a console. Included by
//! `#[path]` into `src/test_spawn.rs` and `tests/common/locked.rs`, the two raw-spawn wrappers, and
//! used by the `src/test_child` helpers that build a `cosca::Command`.

/// Which console a test child gets. Off Windows it changes nothing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Console {
    /// A console of its own with no window (`CREATE_NO_WINDOW`), added to the caller's flags. The
    /// default for every test child.
    Hidden,
    /// The caller's flags are the whole word: the test decides which console the child gets, as
    /// when it sends `CTRL_BREAK` to the child's console group or measures console membership.
    Asked,
}

impl Console {
    /// Whether a `cosca::Command` for this child asks for `no_window()` (a no-op off Windows).
    pub const fn hides_window(self) -> bool {
        matches!(self, Console::Hidden)
    }
}

/// `CREATE_NO_WINDOW`, for a `CreateProcessW` fixture that builds its own flag word.
#[cfg(windows)]
pub const NO_WINDOW: u32 = windows::Win32::System::Threading::CREATE_NO_WINDOW.0;

/// The `dwCreationFlags` word for a raw spawn that sets `flags` and wants `console`.
///
/// `std`'s `creation_flags` replaces the word and cannot read it back, so a raw spawn names every
/// flag here, in one call, instead of setting some on the command first.
#[cfg(windows)]
pub const fn word(flags: u32, console: Console) -> u32 {
    match console {
        Console::Hidden => flags | NO_WINDOW,
        Console::Asked => flags,
    }
}
