//! macOS pid-listing tests, split by topic into one file per section: buffer arithmetic,
//! interpreting the kernel's return value, the real glue (not synthetic seams), the grow
//! loop, and the live pid list.

#[path = "pids_tests/buffer_arithmetic.rs"]
mod buffer_arithmetic;

#[path = "pids_tests/interpreting_written.rs"]
mod interpreting_written;

#[path = "pids_tests/real_glue.rs"]
mod real_glue;

#[path = "pids_tests/grow_loop.rs"]
mod grow_loop;

#[path = "pids_tests/live_pid_list.rs"]
mod live_pid_list;
