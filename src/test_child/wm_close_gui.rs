//! A GUI process that the `WM_CLOSE` tests close: the lib's test binary re-run as [`ROLE`], dispatched from
//! `main` before the runner starts. A test starts it with [`Gui::start`] and reads its stdout line by line;
//! every line is `<tag> <event>`, the tag naming the process (`root`, or `child` for the copy it starts).
//!
//! It creates its windows on one thread, off screen and without activating: `main`, and as the [`Plan`] asks a
//! visible tool window (`tool`), a window that is never shown (`hidden`) and a visible popup owned by `main`
//! (`owned`); `hide-main` leaves `main` hidden. It prints `ready` once they exist and the visible ones are
//! shown, then runs a message loop. A second thread reads its stdin.
//!
//! A [`Mode`] says what a window does with `WM_CLOSE`. `closing` handles it by default, which destroys the
//! window, and the process exits 0 when `main` is destroyed. `reporting` makes every window ignore it and
//! print `close <window>` for each receipt. `console` creates no window: it prints its console window's
//! handle (`console <handle>`, 0 when it has none) and `ready`, and ends at the end of its stdin.
//!
//! The only synchronisation is the message queue's order. The stdin line `flush` makes the stdin thread post
//! a marker to `main`, and the window procedure prints `flushed` when it takes it. Messages posted to one
//! thread are taken in the order they were posted, so a `WM_CLOSE` whose `PostMessageW` returned before the
//! test wrote `flush` is taken, and printed, before `flushed`: in `closing` mode the window it closes is
//! destroyed first, and the marker, posted to it, is then never taken. A copy started with `with-child` gets
//! its stdin from the process, which forwards `flush` to it before it posts its own marker, and shares its
//! stdout. The end of the stdin ends the process (and the copy's).
//!
//! A process that cannot set itself up says why on its stderr and exits with 101.

use std::ffi::{c_void, OsStr, OsString};
use std::io::{BufRead as _, BufReader, Write as _};
use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::{Mutex, OnceLock};

use windows::core::w;
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::Console::{
    AllocConsole, FreeConsole, GetConsoleWindow, GetStdHandle, SetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE,
    STD_OUTPUT_HANDLE,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, PostMessageW, PostQuitMessage, RegisterClassW,
    ShowWindow, MSG, SW_SHOWNOACTIVATE, WINDOW_EX_STYLE, WINDOW_STYLE, WM_APP, WM_CLOSE, WM_DESTROY, WNDCLASSW,
    WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW, WS_OVERLAPPEDWINDOW, WS_POPUP,
};

use super::fixture_role::FixtureRole;

pub(crate) const ROLE: FixtureRole = FixtureRole::new("--cosca-wm-close-gui", run);

/// The marker `flush` posts to `main`.
const FLUSH: u32 = WM_APP + 1;
/// What the end of the stdin posts to `main`: the loop ends.
const QUIT: u32 = WM_APP + 2;
/// The exit code of a process that could not set itself up: a panic's.
const SETUP_FAILED: i32 = 101;
/// Where the windows are put: far off every screen.
const OFF_SCREEN: i32 = -20_000;

/// What a window does with `WM_CLOSE`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Mode {
    Closing,
    Reporting,
    Console,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Mode::Closing => "closing",
            Mode::Reporting => "reporting",
            Mode::Console => "console",
        }
    }
}

/// What a process of the role is started as, and what its windows are.
#[derive(Clone, Debug)]
pub(crate) struct Plan {
    pub(crate) mode: Mode,
    /// A visible tool window with no owner.
    pub(crate) tool: bool,
    /// A window that is never shown.
    pub(crate) hidden: bool,
    /// A visible popup owned by `main`.
    pub(crate) owned: bool,
    /// `main` is created and never shown.
    pub(crate) hide_main: bool,
    /// The process starts one copy of itself, without this flag.
    pub(crate) with_child: bool,
}

impl Plan {
    pub(crate) fn new(mode: Mode) -> Plan {
        Plan {
            mode,
            tool: false,
            hidden: false,
            owned: false,
            hide_main: false,
            with_child: false,
        }
    }

    /// The arguments after the role's flag that start a process with the tag `tag`.
    fn words(&self, tag: &str) -> Vec<String> {
        let mut words = vec![self.mode.name().to_owned(), format!("tag={tag}")];
        for (on, word) in [
            (self.tool, "tool"),
            (self.hidden, "hidden"),
            (self.owned, "owned"),
            (self.hide_main, "hide-main"),
            (self.with_child, "with-child"),
        ] {
            if on {
                words.push(word.to_owned());
            }
        }
        words
    }

    /// Calls `f` with the arguments after the role's flag that start a process with the tag `tag`, as
    /// [`FixtureRole`](super::fixture_role::FixtureRole) takes them.
    fn with_rest<T>(&self, tag: &str, f: impl FnOnce(&[&OsStr]) -> T) -> T {
        let words: Vec<OsString> = self.words(tag).into_iter().map(OsString::from).collect();
        let words: Vec<&OsStr> = words.iter().map(OsString::as_os_str).collect();
        f(&words)
    }

    /// The whole argv of a process started as `root`, program name included.
    fn argv(&self, tag: &str) -> Vec<OsString> {
        std::iter::once(std::env::current_exe().expect("current_exe").into_os_string())
            .chain(self.with_rest(tag, |rest| ROLE.argv(rest)))
            .collect()
    }

    fn parse(rest: &[OsString]) -> (Plan, String) {
        fn word(arg: &OsString) -> &str {
            arg.to_str()
                .unwrap_or_else(|| die(&format!("a non-text argument {arg:?}")))
        }
        let mode = match rest.first().map(word) {
            Some("closing") => Mode::Closing,
            Some("reporting") => Mode::Reporting,
            Some("console") => Mode::Console,
            other => die(&format!("no mode in {other:?}")),
        };
        let mut plan = Plan::new(mode);
        let mut tag = "root".to_owned();
        for arg in &rest[1..] {
            match word(arg) {
                "tool" => plan.tool = true,
                "hidden" => plan.hidden = true,
                "owned" => plan.owned = true,
                "hide-main" => plan.hide_main = true,
                "with-child" => plan.with_child = true,
                other => match other.strip_prefix("tag=") {
                    Some(name) => tag = name.to_owned(),
                    None => die(&format!("no argument {other:?}")),
                },
            }
        }
        (plan, tag)
    }
}

/// Ends the process, not only the calling thread, with [`SETUP_FAILED`].
fn die(message: &str) -> ! {
    // A closed stderr is no reason to do anything else.
    _ = writeln!(std::io::stderr(), "wm close gui: {message}");
    std::process::exit(SETUP_FAILED)
}

/// What the window procedure reads: set once, before the first window exists.
struct State {
    tag: String,
    reporting: bool,
    /// The handle of `main`, set when it exists.
    main: AtomicIsize,
    /// The name each window was created under, by handle.
    names: Mutex<Vec<(isize, &'static str)>>,
}

static STATE: OnceLock<State> = OnceLock::new();

fn state() -> &'static State {
    STATE.get().expect("the state is set before the first window")
}

/// One line on the stdout. A closed stdout is no reason to do anything else.
fn say(event: &str) {
    _ = writeln!(std::io::stdout(), "{} {event}", state().tag);
}

fn run(rest: &[OsString]) -> ! {
    let (plan, tag) = Plan::parse(rest);
    match plan.mode {
        Mode::Console => run_console(&tag),
        Mode::Closing | Mode::Reporting => run_windows(&plan, tag),
    }
}

/// `console`: no window of its own, but a console of its own (a new one with a window, in place of the one
/// it started with), the console window's handle, and the end of the stdin.
fn run_console(tag: &str) -> ! {
    // A new console takes the standard handles of a process; the pipes the test reads and writes are kept.
    let standard = [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE].map(|which| {
        // SAFETY: a call with a plain argument.
        (which, unsafe { GetStdHandle(which) })
    });
    // SAFETY: calls with no arguments.
    unsafe {
        _ = FreeConsole();
        AllocConsole().unwrap_or_else(|e| die(&format!("AllocConsole: {e}")));
    }
    for (which, handle) in standard {
        let handle = handle.unwrap_or_else(|e| die(&format!("GetStdHandle: {e}")));
        // SAFETY: a handle this process had.
        unsafe { SetStdHandle(which, handle) }.unwrap_or_else(|e| die(&format!("SetStdHandle: {e}")));
    }
    // SAFETY: a call with no arguments.
    let console = unsafe { GetConsoleWindow() };
    let mut out = std::io::stdout();
    _ = writeln!(out, "{tag} console {}", console.0 as isize);
    _ = writeln!(out, "{tag} ready");
    // The end of the stdin ends the process.
    for line in std::io::stdin().lock().lines() {
        if line.is_err() {
            break;
        }
    }
    std::process::exit(0)
}

fn run_windows(plan: &Plan, tag: String) -> ! {
    STATE
        .set(State {
            tag,
            reporting: plan.mode == Mode::Reporting,
            main: AtomicIsize::new(0),
            names: Mutex::new(Vec::new()),
        })
        .unwrap_or_else(|_| die("the state was set twice"));
    // The copy is started while this process has one thread, and before its windows exist.
    let child_stdin = plan.with_child.then(|| start_child(plan));

    // SAFETY: `None` names this process's own image.
    let instance = unsafe { GetModuleHandleW(None) }.unwrap_or_else(|e| die(&format!("GetModuleHandleW: {e}")));
    let class = WNDCLASSW {
        lpfnWndProc: Some(window_proc),
        hInstance: instance.into(),
        lpszClassName: w!("CoscaWmCloseGui"),
        ..WNDCLASSW::default()
    };
    // SAFETY: `class` is complete and names a window procedure of this image.
    if unsafe { RegisterClassW(&class) } == 0 {
        die("RegisterClassW failed");
    }
    let create = |name: &'static str, ex: WINDOW_EX_STYLE, style: WINDOW_STYLE, owner: Option<HWND>| -> HWND {
        // SAFETY: the class is registered; `owner`, when there is one, is a window of this thread.
        let window = unsafe {
            CreateWindowExW(
                WS_EX_NOACTIVATE | ex,
                w!("CoscaWmCloseGui"),
                w!("cosca wm close"),
                style,
                OFF_SCREEN,
                OFF_SCREEN,
                200,
                100,
                owner,
                None,
                Some(instance.into()),
                None,
            )
        }
        .unwrap_or_else(|e| die(&format!("CreateWindowExW for {name}: {e}")));
        state()
            .names
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((window.0 as isize, name));
        window
    };
    let show = |window: HWND| {
        // SAFETY: a window of this thread. The return value says whether it was visible before.
        _ = unsafe { ShowWindow(window, SW_SHOWNOACTIVATE) };
    };

    let main = create("main", WINDOW_EX_STYLE(0), WS_OVERLAPPEDWINDOW, None);
    state().main.store(main.0 as isize, Ordering::SeqCst);
    if !plan.hide_main {
        show(main);
    }
    if plan.tool {
        show(create("tool", WS_EX_TOOLWINDOW, WS_OVERLAPPEDWINDOW, None));
    }
    if plan.hidden {
        create("hidden", WINDOW_EX_STYLE(0), WS_OVERLAPPEDWINDOW, None);
    }
    if plan.owned {
        show(create("owned", WINDOW_EX_STYLE(0), WS_POPUP, Some(main)));
    }
    say("ready");

    let main_handle = main.0 as isize;
    std::thread::Builder::new()
        .name("stdin".into())
        .spawn(move || read_stdin(main_handle, child_stdin))
        .unwrap_or_else(|e| die(&format!("the stdin thread: {e}")));

    let mut message = MSG::default();
    loop {
        // SAFETY: `message` is a live out-parameter.
        match unsafe { GetMessageW(&mut message, None, 0, 0) }.0 {
            0 => break,
            -1 => die("GetMessageW failed"),
            // SAFETY: a message `GetMessageW` returned.
            _ => _ = unsafe { DispatchMessageW(&message) },
        }
    }
    std::process::exit(0)
}

/// Starts the copy: this binary as the role again, with the same windows and no copy of its own, its stdin
/// piped and its stdout and stderr this process's.
#[allow(
    clippy::zombie_processes,
    reason = "the copy ends with its stdin, and this process exits when its loop ends: neither waits for the other"
)]
fn start_child(plan: &Plan) -> std::process::ChildStdin {
    let mut command = plan
        .clone()
        .without_child()
        .with_rest("child", |rest| ROLE.command(rest));
    command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());
    let mut child = crate::test_spawn::spawn(&mut command).unwrap_or_else(|e| die(&format!("start the copy: {e}")));
    child.stdin.take().unwrap_or_else(|| die("the copy has no stdin"))
}

impl Plan {
    fn without_child(mut self) -> Plan {
        self.with_child = false;
        self
    }
}

/// The stdin thread: `flush` is forwarded to the copy, then marked on `main`'s queue; the end of the stdin
/// ends the copy's, and the loop.
fn read_stdin(main: isize, mut child: Option<std::process::ChildStdin>) {
    let post = |message: u32| {
        let window = HWND(main as *mut c_void);
        // SAFETY: a handle value; a window that is gone answers an error, which only means the loop is
        // ending.
        _ = unsafe { PostMessageW(Some(window), message, WPARAM(0), LPARAM(0)) };
    };
    for line in BufReader::new(std::io::stdin()).lines() {
        match line {
            Ok(line) if line == "flush" => {
                if let Some(stdin) = child.as_mut() {
                    // A copy that is gone has nothing to flush.
                    _ = writeln!(stdin, "flush").and_then(|()| stdin.flush());
                }
                post(FLUSH);
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    drop(child);
    post(QUIT);
}

unsafe extern "system" fn window_proc(window: HWND, message: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let state = state();
    match message {
        WM_CLOSE if state.reporting => {
            let name = state
                .names
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .find(|(handle, _)| *handle == window.0 as isize)
                .map_or("?", |(_, name)| *name);
            say(&format!("close {name}"));
            LRESULT(0)
        }
        FLUSH => {
            say("flushed");
            LRESULT(0)
        }
        QUIT => {
            // SAFETY: a call with a plain argument.
            unsafe { PostQuitMessage(0) };
            LRESULT(0)
        }
        WM_DESTROY if window.0 as isize == state.main.load(Ordering::SeqCst) => {
            // SAFETY: a call with a plain argument.
            unsafe { PostQuitMessage(0) };
            LRESULT(0)
        }
        // SAFETY: the arguments are the ones this window procedure was called with.
        _ => unsafe { DefWindowProcW(window, message, wparam, lparam) },
    }
}

// The test side -----

/// A running [`ROLE`] process (and its copy), and its stdout read line by line.
pub(crate) struct Gui {
    pub(crate) child: crate::Child,
    stdin: Option<crate::PipeWriter>,
    lines: std::io::Lines<BufReader<crate::PipeReader>>,
    /// The tags that print `flushed` when they are flushed.
    tags: Vec<&'static str>,
    /// The lines printed before the last `ready`, which are the process's own facts (`console <handle>`).
    pub(crate) startup: Vec<String>,
}

impl Gui {
    /// Starts the process as `plan` says, with `configure` applied to its command last, and reads until it and
    /// its copy have printed `ready`. Its command has no console window.
    pub(crate) fn start(plan: &Plan, configure: impl FnOnce(&mut crate::Command)) -> Gui {
        let argv = plan.argv("root");
        let mut command = super::command(super::Console::Hidden);
        command.executable(&argv[0]).args(&argv);
        crate::test_reexec::scrub_env(|var| _ = command.env_remove(var));
        command.stdin(crate::Stdio::pipe()).expect("pipe the stdin");
        command.stdout(crate::Stdio::pipe()).expect("pipe the stdout");
        configure(&mut command);
        let mut child = command.spawn().expect("spawn the GUI process");
        let stdin = child.stdin().expect("a piped stdin");
        let stdout = child.stdout().expect("a piped stdout");
        let mut tags = vec!["root"];
        if plan.with_child {
            tags.push("child");
        }
        let mut gui = Gui {
            child,
            stdin: Some(stdin),
            lines: BufReader::new(stdout).lines(),
            tags,
            startup: Vec::new(),
        };
        let mut waiting: Vec<String> = gui.tags.iter().map(|tag| format!("{tag} ready")).collect();
        while !waiting.is_empty() {
            let line = gui.next_line().expect("the process ended before it was ready");
            match waiting.iter().position(|ready| *ready == line) {
                Some(at) => _ = waiting.remove(at),
                None => gui.startup.push(line),
            }
        }
        gui
    }

    /// The next line of the stdout; `None` at its end.
    fn next_line(&mut self) -> Option<String> {
        self.lines.next().map(|line| line.expect("read the stdout"))
    }

    /// Writes `flush`. A process that has ended has no pipe to take it, which is no failure.
    pub(crate) fn flush(&mut self) {
        let stdin = self.stdin.as_mut().expect("the stdin is still open");
        _ = writeln!(stdin, "flush").and_then(|()| stdin.flush());
    }

    /// The lines up to and including the `flushed` of each process, without the `flushed` lines, after a
    /// [`flush`](Self::flush).
    pub(crate) fn lines_until_flushed(&mut self) -> Vec<String> {
        let mut waiting: Vec<String> = self.tags.iter().map(|tag| format!("{tag} flushed")).collect();
        let mut lines = Vec::new();
        while !waiting.is_empty() {
            let line = self.next_line().expect("the stdout ended before every process flushed");
            if let Some(at) = waiting.iter().position(|flushed| *flushed == line) {
                waiting.remove(at);
            } else {
                lines.push(line);
            }
        }
        lines
    }

    /// The lines up to the end of the stdout, which comes when every process has ended. Panics at a `flushed`
    /// line: a process that flushes is still running.
    pub(crate) fn lines_until_gone(&mut self) -> Vec<String> {
        let mut lines = Vec::new();
        while let Some(line) = self.next_line() {
            assert!(
                !line.ends_with(" flushed"),
                "{line:?}: the process is still running, so it was not closed; the lines before it: {lines:?}"
            );
            lines.push(line);
        }
        lines
    }

    /// Ends the stdin, which ends the process.
    pub(crate) fn end_stdin(&mut self) {
        self.stdin = None;
    }
}
