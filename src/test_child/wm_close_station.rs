//! The host of the `WM_CLOSE` test on a window station that is not interactive: the lib's test binary re-run as
//! [`ROLE`], dispatched from `main` before the runner starts. A test starts it with `CreateProcessW` and an
//! `lpDesktop` that names a desktop of such a station (a service's station is one), which is the way a parent
//! puts a child there: [`Command`](crate::Command) has no desktop setter, and production code does not grow one
//! for a test, so this vehicle is a last-resort test system. A thread's own `SetThreadDesktop` does not do it: a
//! child with no `lpDesktop` takes the desktop its parent started on, not the one a thread is set to
//! (measured on CI: the child landed on `WinSta0`).
//!
//! The host checks that it is on a station that is not interactive, runs [`asked_lines`], the body the test
//! also runs on the interactive desktop, and prints what it returns on its stdout, one line each. Its GUI
//! process starts on the host's desktop, so the lines say what the send asked there.

use std::ffi::{c_void, OsString};
use std::io::Write as _;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::StationsAndDesktops::{
    GetProcessWindowStation, GetUserObjectInformationW, UOI_FLAGS, USEROBJECTFLAGS,
};
use windows::Win32::UI::WindowsAndMessaging::WSF_VISIBLE;

use super::fixture_role::FixtureRole;
use super::wm_close_gui::{Gui, Plan};
use crate::{stop, StopTarget};

pub(crate) const ROLE: FixtureRole = FixtureRole::new("--cosca-wm-close-host", run);

/// What a [`send_wm_close`](stop::send_wm_close) to a GUI process with every kind of window asks, on this
/// process's desktop: the lines its windows print for the receipts, or the one line `error <the send's
/// error>`. The process is gone when this returns.
pub(crate) fn asked_lines() -> Vec<String> {
    let mut gui = Gui::start(&Plan::every_window(), |_| {});
    match stop::send_wm_close(&StopTarget::from(&gui.child)) {
        Ok(()) => {
            gui.flush();
            gui.lines_until_flushed()
        }
        Err(error) => vec![format!("error {error:?}")],
    }
}

/// Fails unless this process's window station is not interactive (has no `WSF_VISIBLE`), so a vehicle that
/// left the host on `WinSta0` cannot pass the row that is there to run the send on another kind of station.
fn assert_on_a_station_that_is_not_interactive() {
    // SAFETY: the process's own station handle, which is not closed.
    let station = unsafe { GetProcessWindowStation() }.expect("this process's window station");
    let mut flags = USEROBJECTFLAGS::default();
    // SAFETY: `flags` is a live buffer of the size passed; the handle is live.
    unsafe {
        GetUserObjectInformationW(
            HANDLE(station.0),
            UOI_FLAGS,
            Some(&raw mut flags as *mut c_void),
            size_of::<USEROBJECTFLAGS>() as u32,
            None,
        )
    }
    .expect("read the flags of this process's window station");
    assert!(
        flags.dwFlags & WSF_VISIBLE as u32 == 0,
        "the host is on an interactive window station: the vehicle did not put it on the private one"
    );
}

fn run(_rest: &[OsString]) -> ! {
    assert_on_a_station_that_is_not_interactive();
    let mut out = std::io::stdout();
    for line in asked_lines() {
        // A closed stdout is no reason to do anything else.
        _ = writeln!(out, "{line}");
    }
    std::process::exit(0)
}
