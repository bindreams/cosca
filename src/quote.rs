//! Argv quoting/splitting. POSIX operates on bytes; Windows on UTF-16 code units;
//! AppleScript on UTF-8 text. All three are pure and unit-testable on any host.

pub mod applescript;
pub mod posix;
pub mod windows;
