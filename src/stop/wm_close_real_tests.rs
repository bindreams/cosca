//! `stop::send_wm_close` against real windows: the lib's test binary re-run as a GUI process
//! ([`crate::test_child::wm_close_gui`]), which creates its windows off screen and prints what each receives.
//! The send posts `WM_CLOSE` to top-level windows of the desktop, and the tests open windows and a console,
//! create desktops and a window station, and start a process on one of them, so these tests are the
//! `WM_CLOSE` group: they run on CI, and a host runs them only after consenting
//! (`COSCA_TEST_WM_CLOSE_CONSENT=1`) or turns them off (`COSCA_TEST_WM_CLOSE=0`).
//!
//! The tests wait on nothing but the process's own message queue: every `PostMessageW` of the send has
//! returned before a test writes `flush`, the process takes its messages in the order they were posted, and it
//! prints `flushed` last (see the module doc of the GUI process). Each test fails its mutant by an assertion on
//! the lines it read.
//!
//! The refusal of a window of higher integrity has no real test here: the fold's table covers it.
//!
//! One row runs on a window station that is not interactive, as a service's is, where no window is visible on
//! screen (`IsWindowVisible` is false for all of them). The vehicle is a last-resort test system: the lib's
//! test binary is started with `CreateProcessW` and an `lpDesktop` that names a desktop of a station the test
//! made ([`crate::test_child::wm_close_station`]), because [`Command`](crate::Command) has no desktop setter
//! and production code does not grow one for a test.

use std::ffi::c_void;
use std::io::{BufRead as _, BufReader};
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
use std::time::Duration;

use windows::core::{HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    SetHandleInformation, SetLastError, ERROR_ALREADY_EXISTS, GENERIC_ALL, HANDLE, HANDLE_FLAG_INHERIT, HWND,
    WAIT_OBJECT_0,
};
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, CloseWindowStation, CreateDesktopW, CreateWindowStationW, GetProcessWindowStation,
    SetProcessWindowStation, SetThreadDesktop, DESKTOP_CONTROL_FLAGS, HDESK, HWINSTA,
};
use windows::Win32::System::Threading::{
    CreateProcessW, GetExitCodeProcess, WaitForSingleObject, CREATE_NO_WINDOW, INFINITE, PROCESS_INFORMATION,
    STARTF_USESTDHANDLES, STARTUPINFOW,
};
use windows::Win32::UI::WindowsAndMessaging::{GetWindowThreadProcessId, WINSTA_ALL_ACCESS};

use super::wm_close_tests::{detail_of, fake_tree, sent_over};
use super::{asked, list_windows, Class};
use crate::containment::{SendAnswer, UnsentKind};
use crate::error::Error;
use crate::identity::{spawn_kernel, FakeKernel};
use crate::os_process::fake::{Answer, FakeProcess};
use crate::stop;
use crate::test_child::over_fake::child_with;
use crate::test_child::wm_close_gui::{Gui, Mode, Plan};
use crate::test_child::wm_close_station::{asked_lines, ROLE as HOST};
use crate::test_groups::{wm_close, Group};
use crate::{ContainMode, StopTarget};

/// The lines, sorted: the order in which the posts were taken is not the test's to rely on.
fn sorted(mut lines: Vec<String>) -> Vec<String> {
    lines.sort();
    lines
}

/// The visible unowned windows are asked, tool window included, and no other: a hidden window, an owned popup
/// and the input-method helper windows that every GUI thread has are not. The same two receipts come on the
/// runner's interactive desktop and on a window station that is not interactive, where a window the program
/// has shown is visible by its own style while `IsWindowVisible` says it is not.
///
/// Mutants: a hidden or an owned window is asked (an extra receipt); the tool window is skipped (a receipt is
/// missing); nothing is posted (both are missing); `IsWindowVisible` is the test of visibility (the
/// non-interactive station answers `Unsupported`, and its line is an `error`); visibility is not tested (the
/// hidden window is asked on both stations).
#[skuld::test]
fn the_visible_unowned_windows_are_asked_and_no_other(#[fixture(wm_close)] _group: &Group) {
    let on_the_interactive_desktop = asked_lines();
    let on_a_station_that_is_not_interactive = lines_from_the_host_on_a_private_station();
    for (station, lines) in [
        ("the interactive desktop", on_the_interactive_desktop),
        (
            "a station that is not interactive",
            on_a_station_that_is_not_interactive,
        ),
    ] {
        assert_eq!(sorted(lines), ["root close main", "root close tool"], "{station}");
    }
}

/// A program that handles `WM_CLOSE` by default closes its main window and exits. Mutant: the main window is
/// not asked, so the process flushes instead of ending ([`Gui::lines_until_gone`] fails at its `flushed`).
#[skuld::test]
fn a_program_that_handles_the_close_by_default_exits(#[fixture(wm_close)] _group: &Group) {
    let mut gui = Gui::start(&Plan::new(Mode::Closing), |_| {});
    stop::send_wm_close(&StopTarget::from(&gui.child)).expect("send WM_CLOSE");
    gui.flush();
    assert_eq!(gui.lines_until_gone(), Vec::<String>::new());
    assert_eq!(gui.child.wait().expect("reap the process").code(), Some(0));
}

/// A process whose only window is hidden is asked nothing, and the answer says why. Mutant: a hidden window is
/// asked (a receipt, and no `Unsupported`).
#[skuld::test]
fn a_process_with_only_a_hidden_window_is_refused_and_asked_nothing(#[fixture(wm_close)] _group: &Group) {
    let plan = Plan {
        hide_main: true,
        ..Plan::new(Mode::Reporting)
    };
    let mut gui = Gui::start(&plan, |_| {});
    let error = stop::send_wm_close(&StopTarget::from(&gui.child)).expect_err("no window is visible");
    let Error::Unsupported { detail, .. } = &error else {
        panic!("{error:?}")
    };
    assert!(
        detail.contains("has no top-level window without an owner that has been shown"),
        "{detail}"
    );
    gui.flush();
    assert_eq!(gui.lines_until_flushed(), Vec::<String>::new());
}

/// A console program with a console of its own: its console window is in the real listing under the console
/// class, the rule selects it under whichever pid it is listed (the child's, its parent's or `OpenConsole.exe`'s)
/// and selects no window for the child, and the send is refused. A
/// post to a console window would be `CTRL_CLOSE_EVENT` for every process on the console. Mutant: the class is
/// not read (the listing holds the console window as an ordinary one).
#[skuld::test]
fn a_consoles_window_is_in_the_listing_as_one_and_is_never_asked(#[fixture(wm_close)] _group: &Group) {
    let gui = Gui::start(&Plan::new(Mode::Console), |_| {});
    let handle: isize = gui
        .startup
        .iter()
        .find_map(|line| line.strip_prefix("root console "))
        .expect("the process printed its console window")
        .parse()
        .expect("a handle");
    assert_ne!(
        handle, 0,
        "this test needs a host whose AllocConsole gives the process a console window"
    );

    // The console window's owner is the child, its parent or `OpenConsole.exe`, depending on the console,
    // and a host process may own windows of its own.
    let mut owner = 0u32;
    // SAFETY: `owner` is a live out-parameter.
    unsafe { GetWindowThreadProcessId(HWND(handle as *mut c_void), Some(&mut owner)) };
    assert_ne!(owner, 0, "the console window the process printed is gone");

    let listing = list_windows(&[owner, gui.child.pid()]).expect("list the windows of the console's owner");
    let console = listing
        .iter()
        .find(|window| window.hwnd == handle)
        .expect("the listing holds the console window the process printed");
    assert_eq!(console.class, Class::Console, "{console:?}");
    assert!(
        asked(&listing, console.pid)
            .iter()
            .all(|asked| asked.window.hwnd != handle),
        "the rule selects the console window under the pid it is listed under: {:?}",
        asked(&listing, console.pid)
    );
    assert!(
        asked(&listing, gui.child.pid()).is_empty(),
        "the rule selects a window of the console program: {:?}",
        asked(&listing, gui.child.pid())
    );

    let error = stop::send_wm_close(&StopTarget::from(&gui.child)).expect_err("the process has no window to ask");
    assert!(matches!(error, Error::Unsupported { .. }), "{error:?}");
}

/// Every member of the contained tree is asked, over each way a tree is contained: a parent and the copy it
/// started both take a close, and each reports its main window. Mutant: only the root is asked (the copy's
/// receipt is missing).
#[skuld::test]
fn a_tree_target_asks_every_member(#[fixture(wm_close)] _group: &Group) {
    for mode in [ContainMode::Strongest, ContainMode::TreeWalk] {
        let plan = Plan {
            with_child: true,
            ..Plan::new(Mode::Reporting)
        };
        let mut gui = Gui::start(&plan, |cmd| {
            cmd.contain_with(mode);
            cmd.graceful_stop(stop::send_wm_close);
        });
        gui.child.terminate_tree().expect("terminate_tree through WM_CLOSE");
        gui.flush();
        assert_eq!(
            sorted(gui.lines_until_flushed()),
            ["child close main", "root close main"],
            "{mode:?}"
        );
    }
}

/// `graceful_shutdown_tree`, end to end: the parent and its copy are closed, and the call returns the parent's
/// exit, which a close made and a kill would not (the exit code is 0). The 30 s grace is a failure bound, not
/// the condition under test. Mutant: nothing is posted, so the sweep ends the tree and the status is a kill's.
#[skuld::test]
fn graceful_shutdown_tree_closes_the_parent_and_its_copy(#[fixture(wm_close)] _group: &Group) {
    let plan = Plan {
        with_child: true,
        ..Plan::new(Mode::Closing)
    };
    let mut gui = Gui::start(&plan, |cmd| {
        cmd.contain();
        cmd.graceful_stop(stop::send_wm_close);
    });
    let status = gui
        .child
        .graceful_shutdown_tree(Duration::from_secs(30))
        .expect("graceful_shutdown_tree through WM_CLOSE");
    assert_eq!(status.code(), Some(0), "{status:?}");
    // Every process of the tree is gone when the stdout they share ends.
    assert_eq!(gui.lines_until_gone(), Vec::<String>::new());
}

/// The handle is held as a number, so the guard can be shared with the thread that is assigned the desktop.
struct Desktop(isize);

impl Desktop {
    /// A fresh, empty desktop named `name` on this process's window station.
    fn create(name: &str) -> Desktop {
        let name = HSTRING::from(name);
        // SAFETY: a NUL-terminated name; no device, mode or security attributes. The handle is closed by `drop`.
        let desktop = unsafe {
            CreateDesktopW(
                &name,
                PCWSTR::null(),
                None,
                DESKTOP_CONTROL_FLAGS(0),
                GENERIC_ALL.0,
                None,
            )
        }
        .expect("create a desktop");
        Desktop(desktop.0 as isize)
    }

    fn handle(&self) -> HDESK {
        HDESK(self.0 as *mut c_void)
    }

    /// Makes the calling thread, which must own no window, run on this desktop.
    fn assign_to_this_thread(&self) {
        // SAFETY: the handle is live; the calling thread owns no window or hook.
        unsafe { SetThreadDesktop(self.handle()) }.expect("assign the desktop to a thread that owns no window");
    }
}

impl Drop for Desktop {
    fn drop(&mut self) {
        // SAFETY: the handle `create` made, closed once.
        let closed = unsafe { CloseDesktop(self.handle()) };
        if !std::thread::panicking() {
            closed.expect("close the desktop");
        }
    }
}

/// A window station made for a test, named for this process and closed on every way out of the test, after the
/// desktops made on it. A station made by a process that is not a service is not interactive: it is no
/// `WinSta0`, so none of its desktops is visible.
struct Station(isize);

impl Station {
    fn create() -> Station {
        let name = HSTRING::from(Self::name());
        // SAFETY: a NUL-terminated name; no security attributes. The handle is closed by `drop`.
        let station =
            unsafe { CreateWindowStationW(&name, 0, WINSTA_ALL_ACCESS as u32, None) }.expect("create a window station");
        Station(station.0 as isize)
    }

    fn name() -> String {
        format!("cosca-test-{}", std::process::id())
    }

    fn handle(&self) -> HWINSTA {
        HWINSTA(self.0 as *mut c_void)
    }

    /// A fresh desktop named `name` on this station. The process is moved to the station while it is made, and
    /// back before this returns.
    fn desktop(&self, name: &str) -> Desktop {
        // SAFETY: a call with no arguments; the handle it returns is the process's own, which is not closed.
        let home = unsafe { GetProcessWindowStation() }.expect("this process's window station");
        // SAFETY: the handle is live.
        unsafe { SetProcessWindowStation(self.handle()) }.expect("move this process to the station");
        let desktop = std::panic::catch_unwind(|| Desktop::create(name));
        // SAFETY: the process's own station, put back.
        unsafe { SetProcessWindowStation(home) }.expect("move this process back to its station");
        desktop.unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    }
}

impl Drop for Station {
    fn drop(&mut self) {
        // SAFETY: the handle `create` made, closed once.
        let closed = unsafe { CloseWindowStation(self.handle()) };
        if !std::thread::panicking() {
            closed.expect("close the window station");
        }
    }
}

/// The lines [`HOST`] prints when it runs on a desktop of a window station of its own, which is not
/// interactive: the test binary started with `CreateProcessW`, `lpDesktop` naming the desktop, its stdout and
/// stderr one pipe the test reads to its end. The host has exited when this returns, and a host that failed is
/// a panic that shows what it printed.
fn lines_from_the_host_on_a_private_station() -> Vec<String> {
    let station = Station::create();
    let desktop_name = "Default";
    let _desktop = station.desktop(desktop_name);

    let (reader, writer) = std::io::pipe().expect("make a pipe");
    let output = HANDLE(writer.as_raw_handle());
    // SAFETY: the handle is live; the host inherits it as its stdout and stderr.
    unsafe { SetHandleInformation(output, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT) }
        .expect("make the pipe's write end inheritable");

    let wide = |text: String| -> Vec<u16> { text.encode_utf16().chain(std::iter::once(0)).collect() };
    let exe = std::env::current_exe().expect("current_exe");
    let argv: Vec<String> = HOST
        .argv(&[])
        .into_iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    let mut command_line = wide(format!("\"{}\" {}", exe.display(), argv.join(" ")));
    let mut desktop = wide(format!("{}\\{desktop_name}", Station::name()));
    let startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        lpDesktop: PWSTR(desktop.as_mut_ptr()),
        dwFlags: STARTF_USESTDHANDLES,
        hStdOutput: output,
        hStdError: output,
        ..STARTUPINFOW::default()
    };
    let mut process = PROCESS_INFORMATION::default();
    // SAFETY: the strings are NUL-terminated and outlive the call; `startup` is complete.
    unsafe {
        CreateProcessW(
            PCWSTR::null(),
            Some(PWSTR(command_line.as_mut_ptr())),
            None,
            None,
            true,
            CREATE_NO_WINDOW,
            None,
            PCWSTR::null(),
            &startup,
            &mut process,
        )
    }
    .expect("start the host on the station's desktop");
    // SAFETY: the two handles `CreateProcessW` made, each owned from here.
    let (host, _thread) = unsafe {
        (
            OwnedHandle::from_raw_handle(process.hProcess.0),
            OwnedHandle::from_raw_handle(process.hThread.0),
        )
    };
    // The host holds the only write end that is left, so the read ends when it and what it started are gone.
    drop(writer);
    let lines: Vec<String> = BufReader::new(reader)
        .lines()
        .collect::<Result<_, _>>()
        .expect("read what the host printed");

    // SAFETY: `host` is a live process handle.
    let waited = unsafe { WaitForSingleObject(HANDLE(host.as_raw_handle()), INFINITE) };
    assert_eq!(waited, WAIT_OBJECT_0, "wait for the host to exit");
    let mut code = 0u32;
    // SAFETY: `host` is a live process handle, `code` a live out-parameter.
    unsafe { GetExitCodeProcess(HANDLE(host.as_raw_handle()), &mut code) }.expect("the host's exit code");
    assert_eq!(code, 0, "the host failed; it printed {lines:?}");
    lines
}

/// A desktop with no top-level window is a send that found no window, which is `Unsupported` with nothing
/// sent. `EnumWindows` answers FALSE with last error 0 there, which is no failure. The child is a console
/// program on another desktop; the thread that sends has made no window, so it can be assigned the desktop.
/// The thread carries a stale last error (`ERROR_ALREADY_EXISTS`) before each call, as a service's does.
///
/// Mutants: the clear of the last error removed (the direct listing answers an error, and so does the send);
/// the listing's FALSE read as a failure (`Io`, from the listing and from the send).
#[skuld::test]
fn a_desktop_with_no_window_is_answered_as_no_window_asked(#[fixture(wm_close)] _group: &Group) {
    let (child, stdin) = crate::test_child::held_contained_blocker(crate::Stdio::null());
    let desktop = Desktop::create(&format!("cosca-wm-close-{}", std::process::id()));
    let (listing, answer) = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                desktop.assign_to_this_thread();
                // SAFETY: sets this thread's last error.
                unsafe { SetLastError(ERROR_ALREADY_EXISTS) };
                let listing = list_windows(&[child.pid()]);
                // SAFETY: as above.
                unsafe { SetLastError(ERROR_ALREADY_EXISTS) };
                (listing, sent_over(&child, false))
            })
            .join()
            .expect("the sending thread")
    });
    let listing = listing.expect("an empty desktop lists as no window");
    assert!(listing.is_empty(), "{listing:?}");
    let SendAnswer::NotSent(error, kind) = answer else {
        panic!("{answer:?}")
    };
    assert!(matches!(error, Error::Unsupported { .. }), "{error:?}");
    assert!(detail_of(&error).contains("has no top-level window"), "{error:?}");
    assert_eq!(kind, UnsentKind::NotSent);
    drop(stdin);
    child.wait().expect("reap the child");
}

/// A look at the root that fails the first time is not the answer: the send goes on, and the look made after it,
/// when no window was asked, gives the answer: `RootExited` for a root that had exited, the refusal for a
/// running one that shows no window. The root is a fake whose pid no process has, so no window is posted to,
/// but the send lists this desktop's windows: the row is in the group.
///
/// Mutants: the first look's failure is the answer (both rows fail); the failure is answered as an exit (the
/// running row fails).
#[skuld::test]
fn a_first_look_that_fails_is_not_the_answer(#[fixture(wm_close)] _group: &Group) {
    for second in [Answer::Exited, Answer::Running] {
        let root = FakeProcess::new([Answer::Err(std::io::ErrorKind::Other), second])
            .with_kernel(spawn_kernel(FakeKernel::new()));
        let child = child_with(&root, fake_tree());
        match (second, sent_over(&child, false)) {
            (Answer::Exited, SendAnswer::RootExited(error)) => {
                assert!(detail_of(&error).contains("had exited when cosca looked"), "{error:?}");
            }
            (Answer::Running, SendAnswer::NotSent(error, _)) => {
                assert!(detail_of(&error).contains("has no top-level window"), "{error:?}");
            }
            (_, other) => panic!("the second look is {second:?}, and the answer is {other:?}"),
        }
    }
}
