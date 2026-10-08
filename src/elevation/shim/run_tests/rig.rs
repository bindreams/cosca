//! A real [`ShimLink`](super::super::link::ShimLink) and the real shim as its peer: the lib's own
//! test binary re-executed with the shim's arguments (its `main` calls `init_with_test_hooks`).
//! The seams come from the environment, as `testbin/shim_hooks.rs` reads them.
//!
//! Every wait here is on an event a mutant of the code under test cannot suppress: a line the
//! shim's log receives, or the shim's exit. A FIFO is the log, so that the shim's end of it closing
//! is an event too.

use std::collections::HashMap;
use std::ffi::OsString;
use std::os::fd::OwnedFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use rustix::event::{poll, PollFd, PollFlags};
use rustix::fs::{mknodat, open, FileType, Mode, OFlags, CWD};

use crate::elevation::shim::hooks::{Gate, Inject};
use crate::elevation::shim::link::fake_shim::{my_euid, Rig};
use crate::elevation::shim::protocol::ShimArgs;

/// What a test asks of one shim run.
pub(super) struct Spec {
    program: OsString,
    args: Vec<OsString>,
    gates: Vec<Gate>,
    injects: Vec<Inject>,
    child_gate: bool,
    child_fault: bool,
    loop_failure: bool,
    exhaust_fds: bool,
    cosca_pid: Option<u32>,
    cosca_euid: Option<u32>,
    search_path: Option<OsString>,
    ignore: Vec<libc::c_int>,
    cwd: Option<PathBuf>,
    flag: Option<OsString>,
    dir: Option<PathBuf>,
    stdin_held: bool,
    without_proc: bool,
    shipped: bool,
    raw_seams: Vec<(String, OsString)>,
    exe: Option<PathBuf>,
}

impl Spec {
    pub(super) fn new(program: impl Into<OsString>, args: &[&str]) -> Spec {
        Spec {
            program: program.into(),
            args: args.iter().map(OsString::from).collect(),
            gates: vec![],
            injects: vec![],
            child_gate: false,
            child_fault: false,
            loop_failure: false,
            exhaust_fds: false,
            cosca_pid: None,
            cosca_euid: None,
            search_path: None,
            ignore: vec![],
            cwd: None,
            flag: None,
            dir: None,
            stdin_held: false,
            without_proc: false,
            shipped: false,
            raw_seams: vec![],
            exe: None,
        }
    }

    /// `/bin/sh -c <script>`.
    pub(super) fn sh(script: &str) -> Spec {
        Spec::new("/bin/sh", &["-c", script])
    }

    pub(super) fn gate(mut self, gate: Gate) -> Spec {
        self.gates.push(gate);
        self
    }

    pub(super) fn inject(mut self, what: Inject) -> Spec {
        self.injects.push(what);
        self
    }

    pub(super) fn child_gate(mut self) -> Spec {
        self.child_gate = true;
        self
    }

    pub(super) fn child_fault(mut self) -> Spec {
        self.child_fault = true;
        self
    }

    pub(super) fn loop_failure(mut self) -> Spec {
        self.loop_failure = true;
        self
    }

    pub(super) fn exhaust_fds(mut self) -> Spec {
        self.exhaust_fds = true;
        self
    }

    /// The pid argv names as cosca's.
    pub(super) fn cosca_pid(mut self, pid: u32) -> Spec {
        self.cosca_pid = Some(pid);
        self
    }

    pub(super) fn cosca_euid(mut self, euid: u32) -> Spec {
        self.cosca_euid = Some(euid);
        self
    }

    pub(super) fn search_path(mut self, path: impl Into<OsString>) -> Spec {
        self.search_path = Some(path.into());
        self
    }

    /// The shim starts with this signal ignored, as a caller that ignored it would leave it.
    pub(super) fn ignoring(mut self, signal: libc::c_int) -> Spec {
        self.ignore.push(signal);
        self
    }

    /// The program's stdin is a pipe the test holds: a program that reads it blocks until the test lets go
    /// ([`Run::close_stdin`]).
    pub(super) fn stdin_held(mut self) -> Spec {
        self.stdin_held = true;
        self
    }

    /// The shim runs as a host ships it: through `cosca::init()`, with no hooks, so none of the
    /// seams the other settings ask for exists.
    pub(super) fn shipped(mut self) -> Spec {
        self.shipped = true;
        self
    }

    /// The seam variable `name` set to `value` as written, whatever the settings above made of it: for
    /// the seams that are wrong on purpose.
    pub(super) fn raw_seam(mut self, name: &str, value: impl Into<OsString>) -> Spec {
        self.raw_seams.push((name.to_owned(), value.into()));
        self
    }

    /// The executable that is the shim, in place of this test binary.
    pub(super) fn exe(mut self, exe: &Path) -> Spec {
        self.exe = Some(exe.to_owned());
        self
    }

    /// `argv[1]` in place of the shim's flag.
    pub(super) fn flag(mut self, flag: &str) -> Spec {
        self.flag = Some(flag.into());
        self
    }

    /// The directory argv names, in place of the link's.
    pub(super) fn dir(mut self, dir: &Path) -> Spec {
        self.dir = Some(dir.to_owned());
        self
    }

    /// The shim runs in a mount namespace of its own with `/proc` unmounted. The caller is in the
    /// `namespaces` group: this changes the mount table of a namespace it creates, never the test's.
    pub(super) fn without_proc(mut self) -> Spec {
        self.without_proc = true;
        self
    }

    pub(super) fn cwd(mut self, dir: &Path) -> Spec {
        self.cwd = Some(dir.to_owned());
        self
    }
}

/// The link, the work directory for the FIFOs, and the shim runs made against them.
pub(super) struct ShimRig {
    pub(super) link: Rig,
    work: std::sync::Arc<tempfile::TempDir>,
}

impl ShimRig {
    pub(super) fn new() -> ShimRig {
        ShimRig {
            link: Rig::new(),
            work: std::sync::Arc::new(tempfile::tempdir().expect("a work directory")),
        }
    }

    fn fifo(&self, name: &str) -> PathBuf {
        let path = self.work.path().join(name);
        mknodat(CWD, &path, FileType::Fifo, Mode::from_raw_mode(0o600), 0).expect("a FIFO");
        path
    }

    /// Starts the shim for `spec`, as a child of this process.
    pub(super) fn spawn(&self, spec: Spec) -> Run {
        let work_log = self.fifo("log");
        // The reader exists before the shim opens the log for writing.
        let log_fd = open(
            &work_log,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("the log's read end");
        let args = ShimArgs {
            dir: spec.dir.clone().unwrap_or_else(|| self.link.link.dir().to_owned()),
            cosca_pid: spec.cosca_pid.unwrap_or_else(std::process::id),
            cosca_identity: None,
            cosca_euid: spec.cosca_euid.unwrap_or_else(my_euid),
            search_path: spec.search_path.clone(),
            program: spec.program.clone(),
            args: spec.args.clone(),
        };
        let exe = spec
            .exe
            .clone()
            .unwrap_or_else(|| std::env::current_exe().expect("the test binary's path"));
        let mut argv = args.to_argv(exe.as_os_str(), false);
        if let Some(flag) = &spec.flag {
            argv[1] = flag.clone();
        }
        let mut command = Command::new(&exe);
        command
            .arg0(&argv[0])
            .args(&argv[1..])
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("COSCA_SEAM_LOG", &work_log)
            .stdin(if spec.stdin_held { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut gates = HashMap::new();
        for gate in &spec.gates {
            let fifo = self.fifo(&format!("gate-{}", gate.name()));
            command.env(
                format!("COSCA_SEAM_GATE_{}", gate.name().to_uppercase().replace('-', "_")),
                &fifo,
            );
            gates.insert(*gate, hold_open(&fifo));
        }
        if !spec.injects.is_empty() {
            let names: Vec<&str> = spec.injects.iter().map(|i| i.name()).collect();
            command.env("COSCA_SEAM_INJECT", names.join(","));
        }
        let child_gate = spec.child_gate.then(|| self.fifo("child-gate"));
        if let Some(path) = &child_gate {
            command.env("COSCA_SEAM_CHILD_GATE", path);
        }
        let child_gate = child_gate.map(|path| hold_open(&path));
        if spec.child_fault {
            command.env("COSCA_SEAM_CHILD_FAULT", "1");
        }
        let loop_failure = spec.loop_failure.then(|| self.fifo("loop-failure"));
        if let Some(path) = &loop_failure {
            command.env("COSCA_SEAM_LOOP_FAILURE", path);
        }
        if spec.exhaust_fds {
            command.env("COSCA_SEAM_EXHAUST_FDS", "1");
        }
        if spec.shipped {
            command.env("COSCA_TEST_SHIM_SHIPPED", "1");
        }
        for (name, value) in &spec.raw_seams {
            command.env(name, value);
        }
        if let Some(cwd) = &spec.cwd {
            command.current_dir(cwd);
        }
        let ignore = spec.ignore.clone();
        let without_proc = spec.without_proc;
        // SAFETY: the closure calls only `setrlimit`, `signal`, `unshare`, `mount` and `umount2`, which are
        // async-signal-safe.
        unsafe {
            command.pre_exec(move || {
                // The tests make programs fault on purpose; leave no core files.
                let no_core = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                libc::setrlimit(libc::RLIMIT_CORE, &no_core);
                for signal in &ignore {
                    libc::signal(*signal, libc::SIG_IGN);
                }
                if without_proc
                    && (libc::unshare(libc::CLONE_NEWNS) != 0
                        || libc::mount(
                            std::ptr::null(),
                            c"/".as_ptr(),
                            std::ptr::null(),
                            libc::MS_REC | libc::MS_PRIVATE,
                            std::ptr::null(),
                        ) != 0
                        || libc::umount2(c"/proc".as_ptr(), libc::MNT_DETACH) != 0)
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = crate::test_spawn::spawn(&mut command).expect("the shim starts");
        let stdin = child.stdin.take();
        let pidfd = rustix::process::pidfd_open(
            rustix::process::Pid::from_raw(child.id() as i32).expect("a pid"),
            rustix::process::PidfdFlags::empty(),
        )
        .expect("a pidfd on the shim");
        Run {
            child: Some(child),
            stdin,
            pidfd,
            log: LogTail {
                fifo: log_fd,
                pending: vec![],
                lines: vec![],
                eof: false,
            },
            gates,
            child_gate,
            _work: self.work.clone(),
            loop_failure,
        }
    }
}

impl ShimRig {
    /// Runs the shim to its end. A shim that is refused before hello is not held by the acceptor, so
    /// nothing here depends on the link.
    pub(super) fn run_to_end(&self, spec: Spec) -> Finished {
        self.spawn(spec).finish()
    }
}

/// The lines the shim has logged so far, and whether the log has ended.
struct LogTail {
    fifo: OwnedFd,
    pending: Vec<u8>,
    lines: Vec<String>,
    eof: bool,
}

impl LogTail {
    /// Reads what is available now. A FIFO with no writer yet reads as end-of-file, so nothing is read
    /// before a poll reports data or a hang-up, and the kernel reports a hang-up only once a writer has
    /// come and gone.
    fn drain(&mut self) {
        let zero = rustix::event::Timespec { tv_sec: 0, tv_nsec: 0 };
        let mut buf = [0u8; 4096];
        loop {
            let mut fds = [PollFd::new(&self.fifo, PollFlags::IN)];
            match poll(&mut fds, Some(&zero)) {
                Ok(0) => return,
                Ok(_) => {}
                Err(rustix::io::Errno::INTR) => continue,
                Err(e) => panic!("poll: {e}"),
            }
            match rustix::io::read(&self.fifo, &mut buf) {
                Ok(0) => {
                    self.eof = true;
                    return;
                }
                Ok(n) => {
                    self.pending.extend_from_slice(&buf[..n]);
                    while let Some(at) = self.pending.iter().position(|&b| b == b'\n') {
                        let line: Vec<u8> = self.pending.drain(..=at).collect();
                        self.lines
                            .push(String::from_utf8_lossy(&line[..line.len() - 1]).into_owned());
                    }
                }
                Err(rustix::io::Errno::INTR | rustix::io::Errno::AGAIN) => {}
                Err(e) => panic!("read of the log: {e}"),
            }
        }
    }
}

/// One shim process.
pub(super) struct Run {
    child: Option<Child>,
    stdin: Option<std::process::ChildStdin>,
    pidfd: rustix::fd::OwnedFd,
    log: LogTail,
    /// The write ends of the gates' FIFOs, open from the start: a byte released a gate before the shim
    /// reaches it, and a shim that is gone leaves nothing to wait for.
    gates: HashMap<Gate, OwnedFd>,
    child_gate: Option<OwnedFd>,
    /// The directory of the FIFOs, kept for as long as the shim may open them.
    _work: std::sync::Arc<tempfile::TempDir>,
    loop_failure: Option<PathBuf>,
}

/// What ended a wait for a log line without finding it.
#[derive(Debug)]
pub(super) enum Gone {
    /// The log closed: every holder of its write end is gone.
    LogEnded,
    /// The shim exited, and what it logged is complete.
    ShimExited,
}

impl Run {
    pub(super) fn pid(&self) -> u32 {
        self.child.as_ref().expect("not yet waited").id()
    }

    /// Blocks until the log has `n` lines containing `needle`.
    pub(super) fn wait_count(&mut self, needle: &str, n: usize) {
        let count = |lines: &[String]| lines.iter().filter(|l| l.contains(needle)).count();
        loop {
            self.log.drain();
            if count(&self.log.lines) >= n {
                return;
            }
            let found = self.wait_line_after(self.log.lines.len(), |l| l.contains(needle));
            let ended = if found { String::new() } else { self.how_it_ended() };
            assert!(
                found,
                "the shim's log ended before {n} lines with {needle:?}: {:#?}\n{ended}",
                self.log.lines
            );
        }
    }

    /// Blocks until a line with index `from` or later satisfies `wanted`; `false` when the log or the
    /// shim ended first.
    fn wait_line_after(&mut self, from: usize, wanted: impl Fn(&str) -> bool) -> bool {
        loop {
            self.log.drain();
            if self.log.lines.iter().skip(from).any(|l| wanted(l)) {
                return true;
            }
            if self.log.eof {
                return false;
            }
            let known = self.log.lines.len();
            let mut fds = [
                PollFd::new(&self.log.fifo, PollFlags::IN),
                PollFd::new(&self.pidfd, PollFlags::IN),
            ];
            loop {
                match poll(&mut fds, None) {
                    Ok(_) => break,
                    Err(rustix::io::Errno::INTR) => {}
                    Err(e) => panic!("poll: {e}"),
                }
            }
            if !fds[1].revents().is_empty() && fds[0].revents().is_empty() {
                self.log.drain();
                if self.log.lines.len() == known {
                    return false;
                }
            }
        }
    }

    /// The pid of the program's process, as the shim logged it.
    pub(super) fn program_pid(&mut self) -> i32 {
        let line = self.wait_for("forked child pid=");
        let digits: String = line["forked child pid=".len()..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        digits.parse().expect("a pid")
    }

    /// A pidfd on the program's process. The program is unreaped for as long as the shim has not
    /// reaped it, so the pid names it exactly.
    pub(super) fn program_pidfd(&mut self) -> rustix::fd::OwnedFd {
        let pid = self.program_pid();
        rustix::process::pidfd_open(
            rustix::process::Pid::from_raw(pid).expect("a pid"),
            rustix::process::PidfdFlags::empty(),
        )
        .expect("the program is unreaped")
    }

    /// Whether the shim still holds the write end of the pipe the program's process waits on to be
    /// released: a pipe the process holds the read end of and the shim does not, and the shim holds the
    /// write end of.
    pub(super) fn holds_the_release_pipe(&mut self) -> bool {
        let (shim, child) = (self.pid(), self.program_pid() as u32);
        let ends = |pid: u32| -> Vec<(String, bool)> {
            let mut ends = vec![];
            for entry in std::fs::read_dir(format!("/proc/{pid}/fd")).expect("the fd table") {
                let path = entry.expect("an entry").path();
                let Ok(target) = std::fs::read_link(&path) else {
                    continue;
                };
                let target = target.to_string_lossy().into_owned();
                if !target.starts_with("pipe:[") {
                    continue;
                }
                let info = std::fs::read_to_string(format!(
                    "/proc/{pid}/fdinfo/{}",
                    path.file_name().expect("a name").to_string_lossy()
                ))
                .expect("fdinfo");
                let flags = info
                    .lines()
                    .find_map(|l| l.strip_prefix("flags:"))
                    .expect("flags")
                    .trim();
                let flags = u32::from_str_radix(flags, 8).expect("octal flags");
                ends.push((target, flags & libc::O_ACCMODE as u32 == libc::O_WRONLY as u32));
            }
            ends
        };
        let (shim_ends, child_ends) = (ends(shim), ends(child));
        child_ends
            .iter()
            .filter(|(pipe, writable)| !writable && !shim_ends.iter().any(|(p, w)| p == pipe && !w))
            .any(|(pipe, _)| shim_ends.iter().any(|(p, w)| p == pipe && *w))
    }

    /// The hex mask of `/proc/<shim>/status`'s `field` (`SigCgt`, `SigIgn`).
    pub(super) fn signal_mask(&self, field: &str) -> u64 {
        let status = std::fs::read_to_string(format!("/proc/{}/status", self.pid())).expect("the shim's status");
        let value = status
            .lines()
            .find_map(|l| l.strip_prefix(field).and_then(|r| r.strip_prefix(':')))
            .expect("the field");
        u64::from_str_radix(value.trim(), 16).expect("a hex mask")
    }

    /// How the shim ended, if it has, and what it wrote to stderr meanwhile: for a failure message.
    fn how_it_ended(&mut self) -> String {
        let mut fds = [PollFd::new(&self.pidfd, PollFlags::IN)];
        let zero = rustix::event::Timespec { tv_sec: 0, tv_nsec: 0 };
        if !matches!(poll(&mut fds, Some(&zero)), Ok(n) if n > 0) {
            return "the shim is still running".into();
        }
        let Some(child) = self.child.as_mut() else {
            return "the shim was collected".into();
        };
        let status = child
            .wait()
            .map_or_else(|e| format!("wait failed: {e}"), |s| format!("{s:?}"));
        let mut stderr = String::new();
        if let Some(pipe) = child.stderr.as_mut() {
            if let Ok(flags) = rustix::fs::fcntl_getfl(&*pipe) {
                _ = rustix::fs::fcntl_setfl(&*pipe, flags | OFlags::NONBLOCK);
            }
            _ = std::io::Read::read_to_string(pipe, &mut stderr);
        }
        format!("the shim ended: {status}; its stderr: {stderr:?}")
    }

    /// Takes the shim's stdout pipe.
    pub(super) fn take_stdout(&mut self) -> std::process::ChildStdout {
        self.child
            .as_mut()
            .expect("not yet waited")
            .stdout
            .take()
            .expect("not yet taken")
    }

    /// Takes the shim's stderr pipe.
    pub(super) fn take_stderr(&mut self) -> std::process::ChildStderr {
        self.child
            .as_mut()
            .expect("not yet waited")
            .stderr
            .take()
            .expect("not yet taken")
    }

    /// Everything the shim has logged.
    pub(super) fn lines(&mut self) -> &[String] {
        self.log.drain();
        &self.log.lines
    }

    /// Blocks until a log line satisfies `wanted`: one logged already, or the next to come.
    pub(super) fn wait_line(&mut self, wanted: impl Fn(&str) -> bool) -> Result<String, Gone> {
        loop {
            self.log.drain();
            if let Some(line) = self.log.lines.iter().find(|l| wanted(l)) {
                return Ok(line.clone());
            }
            if self.log.eof {
                return Err(Gone::LogEnded);
            }
            let known = self.log.lines.len();
            let mut fds = [
                PollFd::new(&self.log.fifo, PollFlags::IN),
                PollFd::new(&self.pidfd, PollFlags::IN),
            ];
            loop {
                match poll(&mut fds, None) {
                    Ok(_) => break,
                    Err(rustix::io::Errno::INTR) => {}
                    Err(e) => panic!("poll: {e}"),
                }
            }
            let (log_ready, shim_exited) = (!fds[0].revents().is_empty(), !fds[1].revents().is_empty());
            if shim_exited && !log_ready {
                // The shim is gone, and its log has nothing more for us.
                self.log.drain();
                if self.log.lines.len() == known {
                    return Err(Gone::ShimExited);
                }
            }
        }
    }

    /// Blocks until a line contains `needle`.
    pub(super) fn wait_for(&mut self, needle: &str) -> String {
        match self.wait_line(|l| l.contains(needle)) {
            Ok(line) => line,
            Err(gone) => {
                let ended = self.how_it_ended();
                panic!(
                    "the shim's log ended ({gone:?}) without {needle:?}; it has {:#?}\n{ended}",
                    self.log.lines
                )
            }
        }
    }

    /// Blocks until a line contains `needle`, ending only with the log itself: for a line that a
    /// process other than the shim (its child, outliving it) writes, where the shim's exit says
    /// nothing about whether the line is still to come. The log ends when every holder of its write
    /// end has gone, and the shim has opened it by the time a test calls this.
    pub(super) fn wait_for_in_log(&mut self, needle: &str) -> String {
        loop {
            self.log.drain();
            if let Some(line) = self.log.lines.iter().find(|l| l.contains(needle)) {
                return line.clone();
            }
            let ended = if self.log.eof {
                self.how_it_ended()
            } else {
                String::new()
            };
            assert!(
                !self.log.eof,
                "the log ended without {needle:?}: {:#?}\n{ended}",
                self.log.lines
            );
            let mut fds = [PollFd::new(&self.log.fifo, PollFlags::IN)];
            match poll(&mut fds, None) {
                Ok(_) | Err(rustix::io::Errno::INTR) => {}
                Err(e) => panic!("poll: {e}"),
            }
        }
    }

    /// Releases a gate once the shim is waiting at it.
    pub(super) fn release(&mut self, gate: Gate) {
        self.wait_for(&format!("gate: waiting at {}", gate.name()));
        let holder = self.gates.get(&gate).expect("the gate was requested");
        release_gate(holder);
    }

    /// Releases the child's gate, whether or not the child is at it yet; a child that is gone has
    /// nothing to release.
    pub(super) fn release_child_if_waiting(&mut self) {
        release_gate(self.child_gate.as_ref().expect("the child gate was requested"));
    }

    /// Releases the child's gate once the child is waiting at it.
    pub(super) fn release_child(&mut self) {
        self.wait_for_in_log("child: waiting at gate");
        release_gate(self.child_gate.as_ref().expect("the child gate was requested"));
    }

    /// Makes supervision fail.
    pub(super) fn fail_loop(&mut self) {
        let fifo = self.loop_failure.clone().expect("the loop failure was requested");
        open_for_release(&fifo);
    }

    /// Waits for the shim to exit, without collecting its output.
    pub(super) fn wait_exit(&mut self) -> std::process::ExitStatus {
        self.child
            .as_mut()
            .expect("not yet waited")
            .wait()
            .expect("the shim's exit")
    }

    /// Waits for the shim's exit and collects it. The shim's own stdout and stderr are returned.
    pub(super) fn finish(mut self) -> Finished {
        let child = self.child.take().expect("not yet waited");
        let output = child.wait_with_output().expect("the shim's exit");
        self.log.drain();
        Finished {
            code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            lines: std::mem::take(&mut self.log.lines),
        }
    }

    /// Lets go of the program's stdin.
    pub(super) fn close_stdin(&mut self) {
        self.stdin = None;
    }

    /// Sends `signal` to the shim through its pidfd.
    pub(super) fn signal(&self, signal: rustix::process::Signal) {
        rustix::process::pidfd_send_signal(&self.pidfd, signal).expect("the shim is alive");
    }
}

impl Drop for Run {
    /// A test that failed before it finished the shim must not leave it behind: its own child, killed
    /// through the handle `std` holds.
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            _ = child.kill();
            _ = child.wait();
        }
    }
}

pub(super) struct Finished {
    pub(super) code: Option<i32>,
    pub(super) stderr: String,
    pub(super) lines: Vec<String>,
}

impl Finished {
    pub(super) fn logged(&self, needle: &str) -> bool {
        self.lines.iter().any(|l| l.contains(needle))
    }
}

/// Opens a gate's FIFO for reading and writing, which does not wait for anyone. With this end open the
/// shim's own `open` of the FIFO returns at once, and its `read` waits for a byte.
fn hold_open(fifo: &Path) -> OwnedFd {
    open(fifo, OFlags::RDWR | OFlags::CLOEXEC, Mode::empty()).expect("the gate's FIFO")
}

/// One byte into a gate's FIFO: the shim's read of it returns, now or when the shim gets there.
fn release_gate(holder: &OwnedFd) {
    rustix::io::write(holder, b"g").expect("the gate's FIFO has room");
}

/// Opens a FIFO for writing and closes it: the reader's blocked `open` or `read` returns.
fn open_for_release(fifo: &Path) {
    // Blocks until the shim has the FIFO open for reading, which it does right after logging that it
    // waits.
    let w = open(fifo, OFlags::WRONLY | OFlags::CLOEXEC, Mode::empty()).expect("the gate's write end");
    drop(w);
}

/// The shim's owner as a process of its own, so that a test can end it: see `owner_helper`.
pub(super) struct Owner {
    child: Child,
    stdin: Option<std::process::ChildStdin>,
    out: std::io::BufReader<std::process::ChildStdout>,
    pub(super) dir: PathBuf,
    pub(super) pid: u32,
    /// Holds the link's directory; removed last.
    _work: tempfile::TempDir,
}

impl Owner {
    /// Starts the helper in `mode` and waits until it is ready.
    pub(super) fn start(mode: &str) -> Owner {
        Owner::start_with(mode, &[])
    }

    /// [`start`](Self::start) behind `wrapper`, a command that runs what follows it (`setpriv …`).
    pub(super) fn start_with(mode: &str, wrapper: &[&str]) -> Owner {
        use std::io::BufRead;
        let work = tempfile::tempdir().expect("a work directory");
        let exe = std::env::current_exe().expect("the test binary's path");
        let mut command = match wrapper.split_first() {
            Some((first, rest)) => {
                let mut c = Command::new(first);
                c.args(rest).arg(exe);
                c
            }
            None => Command::new(exe),
        };
        command
            .args(crate::elevation::shim::owner_helper::argv(mode, work.path()))
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = crate::test_spawn::spawn(&mut command).expect("the owner starts");
        let stdin = child.stdin.take();
        let mut out = std::io::BufReader::new(child.stdout.take().expect("piped"));
        let (mut dir, mut pid) = (None, None);
        loop {
            let mut line = String::new();
            let n = out.read_line(&mut line).expect("the owner's output");
            assert!(n > 0, "the owner ended before it was ready (dir {dir:?}, pid {pid:?})");
            let line = line.trim_end();
            if let Some(d) = line.strip_prefix("dir=") {
                dir = Some(PathBuf::from(d));
            } else if let Some(p) = line.strip_prefix("pid=") {
                pid = Some(p.parse().expect("a pid"));
            } else if line == "ready" {
                break;
            }
        }
        Owner {
            child,
            stdin,
            // The helper's later events go unread; it writes a few short lines at most, far under a
            // pipe buffer, and the pipe stays open so that it never sees a closed one.
            out,
            dir: dir.expect("the owner said its directory"),
            pid: pid.expect("the owner said its pid"),
            _work: work,
        }
    }

    /// Makes a fork copy of the owner as it is now, holding every descriptor it has open, and waits until
    /// it exists. The copy lives until the owner's stdin ends.
    pub(super) fn fork_copy(&mut self) {
        use std::io::{BufRead, Write};
        let stdin = self.stdin.as_mut().expect("the owner's stdin is open");
        writeln!(stdin, "fork").expect("the owner is alive");
        loop {
            let mut line = String::new();
            let n = self.out.read_line(&mut line).expect("the owner's output");
            assert!(n > 0, "the owner ended before it forked");
            if line.trim_end() == "forked" {
                return;
            }
        }
    }

    /// Waits until the owner has answered its shim `A`, and so holds the connection to it.
    pub(super) fn wait_answered(&mut self) {
        use std::io::BufRead;
        loop {
            let mut line = String::new();
            let n = self.out.read_line(&mut line).expect("the owner's output");
            assert!(n > 0, "the owner ended before it answered a shim");
            if line.trim_end() == "event Answered(Allow)" {
                return;
            }
        }
    }

    /// Makes a copy of the owner that keeps its connection to the shim and reads every byte the shim
    /// sends on it until the shim ends it, and waits until it exists. The copy outlives the owner, so
    /// that what the shim says to a cosca that is gone can still be seen: [`frames`](Self::frames).
    pub(super) fn fork_reader(&mut self) {
        use std::io::{BufRead, Write};
        let stdin = self.stdin.as_mut().expect("the owner's stdin is open");
        writeln!(stdin, "{}", crate::elevation::shim::owner_helper::READ_FRAMES).expect("the owner is alive");
        loop {
            let mut line = String::new();
            let n = self.out.read_line(&mut line).expect("the owner's output");
            assert!(n > 0, "the owner ended before it forked");
            if line.trim_end() == "forked" {
                return;
            }
        }
    }

    /// What the shim sent on the connection the [`fork_reader`](Self::fork_reader) copy holds, once the
    /// shim has closed it, as the frames' bytes.
    pub(super) fn frames(&mut self) -> Vec<u8> {
        use std::io::BufRead;
        loop {
            let mut line = String::new();
            let n = self.out.read_line(&mut line).expect("the owner's output");
            assert!(n > 0, "the reader ended without saying what it read");
            if let Some(hex) = line.trim_end().strip_prefix("frames ") {
                return (0..hex.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
                    .collect();
            }
        }
    }

    /// Has the owner send `bytes` as control bytes to its shim and exit at once, and reaps it.
    pub(super) fn send_and_exit(&mut self, bytes: &str) {
        use std::io::Write;
        let stdin = self.stdin.as_mut().expect("the owner's stdin is open");
        writeln!(stdin, "{}{bytes}", crate::elevation::shim::owner_helper::SEND_EXIT).expect("the owner is alive");
        let status = self.child.wait().expect("the owner's exit");
        assert!(status.success(), "the owner failed: {status:?}");
    }

    /// Ends the owner with SIGKILL, and reaps it.
    pub(super) fn kill(&mut self) {
        self.child.kill().expect("the owner is alive");
        self.child.wait().expect("the owner's exit");
    }

    /// Closes the owner's stdin: it exits, and so does any copy of it that waits on it.
    pub(super) fn close_stdin(&mut self) {
        self.stdin = None;
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        self.stdin = None;
        _ = self.child.kill();
        _ = self.child.wait();
    }
}
