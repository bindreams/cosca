//! The path canary's own string and buffer logic (`windows_path_resolution/pure.rs`), tested on
//! every host: it has no Win32 dependency, so it need not wait for a Windows runner.

#[path = "windows_path_resolution/pure.rs"]
mod pure;
#[path = "windows_path_resolution/pure_tests.rs"]
mod pure_tests;
