//! Argv quoting/splitting. POSIX operates on bytes; Windows on UTF-16 code units.
//! Both are pure and unit-testable on any host.

pub mod posix;
pub mod windows;
