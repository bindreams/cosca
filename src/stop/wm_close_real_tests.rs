//! `stop::send_wm_close` against real windows: the lib's test binary re-run as a GUI process
//! ([`crate::test_child::wm_close_gui`]), which creates its windows off screen and prints what each receives.
//! The send posts `WM_CLOSE` to top-level windows of the desktop, and the tests open windows and a console, so
//! these tests are the `WM_CLOSE` group: they run on CI, and a host runs them only after consenting
//! (`COSCA_TEST_WM_CLOSE_CONSENT=1`) or turns them off (`COSCA_TEST_WM_CLOSE=0`).
//!
//! The tests wait on nothing but the process's own message queue: every `PostMessageW` of the send has
//! returned before a test writes `flush`, the process takes its messages in the order they were posted, and it
//! prints `flushed` last (see the module doc of the GUI process). Each test fails its mutant by an assertion on
//! the lines it read.
//!
//! The refusal of a window of higher integrity has no real test here: the fold's table covers it.

use std::ffi::c_void;
use std::time::Duration;

use windows::Win32::Foundation::HWND;
use windows::Win32::UI::WindowsAndMessaging::GetWindowThreadProcessId;

use super::{asked, list_windows, Class};
use crate::error::Error;
use crate::stop;
use crate::test_child::wm_close_gui::{Gui, Mode, Plan};
use crate::test_groups::{wm_close, Group};
use crate::{ContainMode, StopTarget};

/// A reporting process with every kind of window.
fn every_window() -> Plan {
    Plan {
        tool: true,
        hidden: true,
        owned: true,
        ..Plan::new(Mode::Reporting)
    }
}

/// The lines, sorted: the order in which the posts were taken is not the test's to rely on.
fn sorted(mut lines: Vec<String>) -> Vec<String> {
    lines.sort();
    lines
}

/// The visible unowned windows are asked, tool window included, and no other: a hidden window, an owned popup
/// and the input-method helper windows that every GUI thread has are not. Mutants: a hidden or an owned window
/// is asked (an extra receipt); the tool window is skipped (a receipt is missing); nothing is posted (both are
/// missing).
#[skuld::test]
fn the_visible_unowned_windows_are_asked_and_no_other(#[fixture(wm_close)] _group: &Group) {
    let mut gui = Gui::start(&every_window(), |_| {});
    stop::send_wm_close(&StopTarget::from(&gui.child)).expect("send WM_CLOSE");
    gui.flush();
    assert_eq!(
        sorted(gui.lines_until_flushed()),
        ["root close main", "root close tool"]
    );
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
    assert!(detail.contains("visible top-level window"), "{detail}");
    gui.flush();
    assert_eq!(gui.lines_until_flushed(), Vec::<String>::new());
}

/// A child that has exited is answered as every other send answers one: `Ok`, with nothing asked. Mutant: the
/// look at the root is dropped, so the answer is the refusal for a process with no window.
#[skuld::test]
fn an_exited_child_is_answered_ok(#[fixture(wm_close)] _group: &Group) {
    let mut gui = Gui::start(&Plan::new(Mode::Closing), |_| {});
    gui.end_stdin();
    assert_eq!(gui.child.wait().expect("the child exits").code(), Some(0));
    stop::send_wm_close(&StopTarget::from(&gui.child)).expect("an exited child is answered Ok");
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
