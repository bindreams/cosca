//! A stand-in for the console-event proxy, for tests of the caller's side that must not send an event.
//!
//! A copy of the testbin named `cosca-proxy-fixture-<code>.exe` answers `<code>` to whatever it is
//! asked, and before it exits it records what it was started with in `<its path>.ran`: whether it
//! had a console, and its argv. The code is in the name so that each test chooses its own with no state
//! shared between tests. The testbin's `main` runs this before anything else, so the copy never plays
//! the real proxy, which a `cosca::init()` first in `main` would.
//!
//! A fixture that finds `<its path>.port` holds its answer until it is told: it connects to that port on
//! the loopback, reports its pid as a line, and exits with its code once the test writes a byte (or closes
//! the connection). A test that must see the proxy running, to act while the caller waits for it, uses this.
//!
//! Compiled into the testbin, which runs it, and into the lib's unit tests, which name the copies and
//! read the records.

#![allow(
    dead_code,
    reason = "the testbin runs the fixture, and the lib's tests name and read it"
)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// What the name of a fixture's executable starts with, before the code it answers.
const PREFIX: &str = "cosca-proxy-fixture-";

/// The file name of a fixture that answers `code`.
pub fn exe_name(code: i32) -> String {
    format!("{PREFIX}{code}{}", std::env::consts::EXE_SUFFIX)
}

/// Where the fixture at `exe` records that it ran.
pub fn record_path(exe: &Path) -> PathBuf {
    let mut path = exe.as_os_str().to_owned();
    path.push(".ran");
    PathBuf::from(path)
}

/// Where a test that wants the fixture at `exe` held writes the loopback port it listens on.
pub fn port_path(exe: &Path) -> PathBuf {
    let mut path = exe.as_os_str().to_owned();
    path.push(".port");
    PathBuf::from(path)
}

/// What a fixture that ran recorded.
#[derive(Debug)]
pub struct Ran {
    /// The fixture was attached to a console when it started.
    pub had_console: bool,
    /// Its argv, `argv[0]` included.
    pub argv: Vec<OsString>,
}

/// What the fixture at `exe` recorded; `None` when it never ran.
pub fn read_record(exe: &Path) -> Option<Ran> {
    let text = std::fs::read_to_string(record_path(exe)).ok()?;
    let mut lines = text.lines();
    let had_console = lines.next()? == "console=true";
    Some(Ran {
        had_console,
        argv: lines.map(OsString::from).collect(),
    })
}

/// Plays the fixture and exits when this process is a copy named for one; returns otherwise.
pub fn run_if_named() {
    let Ok(exe) = std::env::current_exe() else { return };
    let Some(code) = exe
        .file_stem()
        .and_then(|stem| stem.to_str())
        .and_then(|stem| stem.strip_prefix(PREFIX))
        .and_then(|code| code.parse::<i32>().ok())
    else {
        return;
    };
    let mut record = format!("console={}\n", has_console());
    for arg in std::env::args_os() {
        record.push_str(&arg.to_string_lossy());
        record.push('\n');
    }
    std::fs::write(record_path(&exe), record).expect("record that the fixture ran");
    if let Ok(port) = std::fs::read_to_string(port_path(&exe)) {
        hold_until_told(port.trim().parse().expect("the port the test listens on"));
    }
    std::process::exit(code);
}

/// Reports this process's pid on `port`, then blocks until the test writes a byte or hangs up.
fn hold_until_told(port: u16) {
    use std::io::{Read as _, Write as _};

    let mut test = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect to the test");
    writeln!(test, "{}", std::process::id()).expect("report the pid");
    let mut told = [0u8; 1];
    // Either answer, a byte or the hang-up, releases the fixture.
    _ = test.read(&mut told);
}

fn has_console() -> bool {
    use windows::Win32::System::Console::GetConsoleProcessList;

    let mut list = [0u32; 1];
    // SAFETY: `list` is a valid writable slice. A buffer smaller than the attached-process count is
    // fine: only whether the count is zero is read.
    unsafe { GetConsoleProcessList(&mut list) != 0 }
}
