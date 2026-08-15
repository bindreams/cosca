//! macOS pid-snapshot tests, split by topic into one file per section: buffer arithmetic,
//! interpreting the kernel's return value, the real glue (not synthetic seams), the grow
//! loop, the live pid list, failure fallback branches, and the ppid join.

#[path = "macos_tests/buffer_arithmetic.rs"]
mod buffer_arithmetic;

#[path = "macos_tests/interpreting_written.rs"]
mod interpreting_written;

#[path = "macos_tests/real_glue.rs"]
mod real_glue;

#[path = "macos_tests/grow_loop.rs"]
mod grow_loop;

#[path = "macos_tests/live_pid_list.rs"]
mod live_pid_list;

#[path = "macos_tests/failure_fallback.rs"]
mod failure_fallback;

#[path = "macos_tests/ppid_join.rs"]
mod ppid_join;

#[path = "macos_tests/snapshot.rs"]
mod snapshot;
