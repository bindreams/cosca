//! The path canary's own logic — its string and buffer handling (`windows_path_resolution/pure.rs`)
//! and its verdict (`windows_path_resolution/verdict.rs`) — tested on every host: none of it
//! depends on Win32, so it need not wait for a Windows runner.

// See `src/lib.rs`'s header for why: this integration test crate is its own clippy-linted
// crate root, so it needs its own copy of the deny.
#![deny(clippy::allow_attributes_without_reason)]

#[path = "windows_path_resolution/pure.rs"]
mod pure;
#[path = "windows_path_resolution/pure_tests.rs"]
mod pure_tests;
#[path = "windows_path_resolution/verdict.rs"]
mod verdict;
#[path = "windows_path_resolution/verdict_tests.rs"]
mod verdict_tests;
