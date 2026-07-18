//! Windows raw `CreateProcessW` spawn backend (Plan 12).
//!
//! Lands incrementally. This root currently exposes only the MSVCRT
//! `lpReserved2` fd-table encoder plus a `GetFileType` device classifier
//! (`crt_fds`); the sync/async spawn paths that consume them arrive in later
//! tasks.
#![allow(dead_code)] // the fd-table API is consumed by the Task 5+ spawn paths; not yet wired to a production caller

#[path = "windows_raw/crt_fds.rs"]
mod crt_fds;

#[path = "windows_raw/resolve.rs"]
mod resolve;
