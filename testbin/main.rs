//! Test-only helper spawned by the crate's integration tests. std-only, with
//! one exception: the `report-nested-kill-tree` mode uses the `cosca` crate
//! to exercise the real nested-member `kill_tree` path. Behavior is selected by argv[1].

#[cfg(target_os = "macos")]
use std::io::BufRead;
use std::io::{Read, Write};
use std::process::exit;

/// The `report-console-identity` mode, shared verbatim with the GUI-subsystem fixture.
#[cfg(windows)]
#[path = "console_identity.rs"]
mod console_identity;

/// The `report-breakaway` mode: job-object shapes and the three spawn vehicles.
#[cfg(windows)]
#[path = "breakaway.rs"]
mod breakaway;

/// Borrow a std stream's raw descriptor as an UNBUFFERED `File`. `ManuallyDrop` keeps the
/// real descriptor open (a plain `File` drop would close it — double-close on exit).
/// Callers must pass one of this process's std descriptors, which live for the whole run.
#[cfg(unix)]
fn borrow_std_file(fd: std::os::fd::RawFd) -> std::mem::ManuallyDrop<std::fs::File> {
    use std::os::fd::FromRawFd;
    // SAFETY: the fd is live per the contract above; ManuallyDrop prevents the close.
    std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(fd) })
}
#[cfg(windows)]
fn borrow_std_file(handle: std::os::windows::io::RawHandle) -> std::mem::ManuallyDrop<std::fs::File> {
    use std::os::windows::io::FromRawHandle;
    // SAFETY: the handle is live per the contract above; ManuallyDrop prevents the close.
    std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_handle(handle) })
}

/// Wrap CRT fd `fd` as a `File` for the `read-fd`/`write-fd` relay modes. Callers must
/// `std::mem::forget` the result after use so the drop does not close a descriptor this
/// process still owns (double-close on exit). On Windows the CRT fd is translated to its OS
/// handle via `get_osfhandle`; on unix the fd is used directly.
#[cfg(windows)]
fn file_from_fd(fd: i32) -> std::fs::File {
    use std::os::windows::io::{FromRawHandle, RawHandle};
    // SAFETY: get_osfhandle only reads the CRT fd table; it has no preconditions.
    let h = unsafe { libc::get_osfhandle(fd) };
    assert!(h != -1, "fd {fd} not wired into the CRT fd table");
    // SAFETY: `h` is a live OS handle for this open fd; the caller forgets the File so the
    // handle is not closed out from under the fd.
    unsafe { std::fs::File::from_raw_handle(h as RawHandle) }
}
#[cfg(unix)]
fn file_from_fd(fd: i32) -> std::fs::File {
    use std::os::fd::{FromRawFd, RawFd};
    // SAFETY: `fd` is an open descriptor passed in by the test; the caller forgets the File so
    // the descriptor is not closed out from under the fd.
    unsafe { std::fs::File::from_raw_fd(fd as RawFd) }
}

#[cfg(windows)]
fn install_ignore_break() {
    use windows::core::BOOL;
    use windows::Win32::System::Console::SetConsoleCtrlHandler;
    unsafe extern "system" fn ignore(_event: u32) -> BOOL {
        BOOL(1) // handled — do not die
    }
    // SAFETY: installing a console ctrl handler has no preconditions.
    unsafe { SetConsoleCtrlHandler(Some(ignore), true) }.expect("install ctrl handler");
}

/// Shared body of `control-echo-pid` and the grandchild arm of `spawn-orphan-escapee`'s
/// relay: publish `<tag><pid>\n`, then echo each byte received. `Ok(0)`/`Interrupted` are the
/// only expected outcomes besides a live echo; anything else is a genuine test-harness bug.
fn run_control_echo_pid(addr: &str, tag: &str) -> ! {
    let mut sock = std::net::TcpStream::connect(addr).unwrap();
    writeln!(sock, "{tag}{}", std::process::id()).unwrap();
    sock.flush().unwrap();
    let mut b = [0u8; 1];
    loop {
        match sock.read(&mut b) {
            Ok(0) => std::process::exit(0), // the test dropped the socket
            Ok(_) => sock.write_all(&b).unwrap(),
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => panic!("control socket read failed: {e}"),
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("");
    match mode {
        "argv0" => {
            // Print this process's argv[0] so callers can verify it.
            let argv0 = std::env::args().next().unwrap_or_default();
            println!("{argv0}");
        }
        "argv0-report" => {
            // Report argv[0] and the resolved image path on separate lines, so the raw backend
            // tests can prove argv[0] is independent of the executable that actually ran.
            let argv0 = std::env::args().next().unwrap_or_default();
            let image = std::env::current_exe().expect("current_exe");
            println!("argv0={argv0}");
            println!("image={}", image.display());
        }
        "read-fd" => {
            // Copy the given CRT fd to stdout (proves an inherited fd reached the child).
            let fd: i32 = args[2].parse().unwrap();
            let mut f = file_from_fd(fd);
            let mut out = std::io::stdout().lock();
            std::io::copy(&mut f, &mut out).unwrap();
            out.flush().unwrap();
            std::mem::forget(f); // keep the inherited fd open; do not close on exit
        }
        "write-fd" => {
            // Write the given text straight to the given CRT fd (proves the child can drive an
            // inherited fd back to the parent).
            let fd: i32 = args[2].parse().unwrap();
            let mut f = file_from_fd(fd);
            f.write_all(args[3].as_bytes()).unwrap();
            f.flush().unwrap();
            std::mem::forget(f); // keep the inherited fd open; do not close on exit
        }
        "isatty-fd" => {
            // Report whether the given CRT fd is a character device (console) vs a pipe/file, so
            // the raw backend tests can classify inherited stdio.
            let fd: i32 = args[2].parse().unwrap();
            // SAFETY: isatty only queries the fd; it has no preconditions.
            let tty = unsafe { libc::isatty(fd) };
            println!("isatty={tty}");
        }
        "echo-argv" => {
            let mut out = std::io::stdout().lock();
            for a in &args[2..] {
                writeln!(out, "{a}").unwrap();
            }
        }
        "env" => {
            let mut out = std::io::stdout().lock();
            for name in &args[2..] {
                let val = std::env::var(name).unwrap_or_default();
                writeln!(out, "{name}={val}").unwrap();
            }
        }
        "emit" => {
            let n_out: usize = args[2].parse().unwrap();
            let n_err: usize = args[3].parse().unwrap();
            // Flush explicitly: these bytes have no trailing newline, so the
            // line-buffered Stdout would otherwise hold them until process exit.
            let mut out = std::io::stdout().lock();
            out.write_all(&vec![b'o'; n_out]).unwrap();
            out.flush().unwrap();
            let mut err = std::io::stderr().lock();
            err.write_all(&vec![b'e'; n_err]).unwrap();
            err.flush().unwrap();
        }
        "tee-both" => {
            // Copy stdin to BOTH stdout and stderr in a loop, so a parent that
            // does not pump concurrently will deadlock once a pipe buffer fills.
            let mut stdin = std::io::stdin().lock();
            let mut stdout = std::io::stdout().lock();
            let mut stderr = std::io::stderr().lock();
            let mut buf = [0u8; 8192];
            loop {
                let n = stdin.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                stdout.write_all(&buf[..n]).unwrap();
                stderr.write_all(&buf[..n]).unwrap();
            }
            stdout.flush().unwrap();
            stderr.flush().unwrap();
        }
        "stdin-split-echo" => {
            // Prove the In-direction merge dup: fd 0 and fd 2 are dups of ONE pipe, so
            // reading EXACTLY n bytes from fd 0 and then fd 2 to EOF splits a single
            // ordered stream. "<head>|<tail>" on stdout is only produced if fd 2 is a
            // LIVE dup. fd 0 must be read UNBUFFERED — std::io::stdin()'s BufReader
            // would over-read into its buffer, stealing the bytes destined for fd 2.
            let n: usize = args[2].parse().unwrap();
            #[cfg(unix)]
            let (mut fd0, mut fd2) = (borrow_std_file(0), borrow_std_file(2));
            #[cfg(windows)]
            let (mut fd0, mut fd2) = {
                use std::os::windows::io::AsRawHandle;
                (
                    borrow_std_file(std::io::stdin().as_raw_handle()),
                    borrow_std_file(std::io::stderr().as_raw_handle()),
                )
            };
            let mut head = vec![0u8; n];
            fd0.read_exact(&mut head).unwrap();
            let mut tail = Vec::new();
            fd2.read_to_end(&mut tail).unwrap();
            let mut out = std::io::stdout().lock();
            out.write_all(&head).unwrap();
            out.write_all(b"|").unwrap();
            out.write_all(&tail).unwrap();
            out.flush().unwrap();
        }
        "emit-raw" => {
            // Write raw bytes (as hex pairs) to stdout; used to test invalid-UTF-8 handling.
            // Each arg after "emit-raw" is a 2-hex-digit byte value.
            let mut out = std::io::stdout().lock();
            for hex in &args[2..] {
                let byte = u8::from_str_radix(hex, 16).unwrap();
                out.write_all(&[byte]).unwrap();
            }
            out.flush().unwrap();
        }
        "exit" => {
            let code: i32 = args[2].parse().unwrap();
            exit(code);
        }
        "control-block" => {
            // Connect to the test's control listener, send a 1-byte tag, then
            // block holding the socket open. On our death the OS closes it,
            // EOF-ing the test's read — a real exit event, never a timer.
            let addr = &args[2];
            let tag = args.get(3).map(String::as_str).unwrap_or("?");
            let mut sock = std::net::TcpStream::connect(addr).unwrap();
            sock.write_all(tag.as_bytes()).unwrap();
            sock.flush().unwrap();
            let mut buf = [0u8; 1];
            let _ = sock.read(&mut buf); // blocks until the socket closes (our death) / test writes
        }
        #[cfg(target_os = "macos")]
        "control-block-mixed-cloexec-marker" => {
            // Like control-block, but first `F_DUPFD_CLOEXEC`s a second copy of the inherited
            // fd-marker descriptor, so this pid holds BOTH a CLOEXEC copy and the original
            // non-CLOEXEC one — exercising `holders()`'s AND-fold coverage gap (#59).
            //
            // The marker's fd number is NOT discovered here: an earlier version scanned this
            // process's own open fds for "the one nobody else explains", which passed locally
            // but was flaky on CI, where the runner hands the process extra inherited
            // descriptors indistinguishable from the marker by that scan alone. The test
            // process already knows the real number (`Child::test_fdmarker_fd`, its own
            // bookkeeping from installing the marker) and sends it over the control socket
            // after the tag handshake below — this mode is simply told, never guesses.
            let addr = &args[2];
            let tag = args.get(3).map(String::as_str).unwrap_or("?");
            let mut sock = std::net::TcpStream::connect(addr).unwrap();
            sock.write_all(tag.as_bytes()).unwrap();
            sock.flush().unwrap();

            let mut reader = std::io::BufReader::new(sock.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).expect("read marker fd from the test");
            let marker_fd: i32 = line.trim().parse().expect("marker fd must be a plain decimal number");
            // SAFETY: F_GETFD has no preconditions beyond a valid fd number; -1 means closed.
            assert!(
                unsafe { libc::fcntl(marker_fd, libc::F_GETFD) } != -1,
                "the test told us fd {marker_fd} carries the marker, but it is not open here"
            );

            // SAFETY: `marker_fd` was just confirmed open above; F_DUPFD_CLOEXEC duplicates it,
            // setting FD_CLOEXEC on the NEW copy only — the original descriptor is untouched
            // (still open, still non-CLOEXEC).
            let dup = unsafe { libc::fcntl(marker_fd, libc::F_DUPFD_CLOEXEC, 0) };
            assert!(
                dup >= 0,
                "F_DUPFD_CLOEXEC({marker_fd}) failed: {}",
                std::io::Error::last_os_error()
            );
            assert!(
                dup < marker_fd,
                "the CLOEXEC dup (fd {dup}) must land below the marker's own high fd \
                 ({marker_fd}) for this test to exercise the ordering its coverage depends on"
            );

            let mut buf = [0u8; 1];
            let _ = sock.read(&mut buf); // blocks until the socket closes (our death) / test writes
        }
        "control-echo-pid" => {
            // Like control-block, but publishes its own pid on the wire: `<tag><pid>\n`. Then
            // echoes each byte it receives, so a test can prove a member is ALIVE (a real
            // 1-byte round trip) as well as dead (EOF) — without a timer in either direction.
            let addr = args[2].clone();
            let tag = args.get(3).map(String::as_str).unwrap_or("?");
            run_control_echo_pid(&addr, tag);
        }
        "spawn-grandchild" => {
            // Spawn a grandchild that holds its own control connection (tag "G"),
            // then hold ours (tag "R"). Both die together iff containment works.
            let addr = args[2].clone();
            let exe = std::env::current_exe().unwrap();
            #[allow(clippy::zombie_processes)] // intentional: grandchild must outlive us; containment kills it
            let _gc = std::process::Command::new(exe)
                .args(["control-block", &addr, "G"])
                .spawn()
                .unwrap();
            // Become a control-block ourselves (no test-owned stdin → no EOF confound).
            let mut sock = std::net::TcpStream::connect(&addr).unwrap();
            sock.write_all(b"R").unwrap();
            sock.flush().unwrap();
            let mut buf = [0u8; 1];
            let _ = sock.read(&mut buf);
        }
        #[cfg(unix)]
        "spawn-grandchild-setuid" => {
            // Like spawn-grandchild, but the grandchild is a SEPARATE, pre-provisioned
            // setuid-root binary (argv[3]) rather than this same executable — proving issue
            // #61's fix against a mixed real process group: an ordinary member (us, the
            // group leader) plus one the caller genuinely cannot signal. The grandchild
            // inherits OUR process group (no setpgid call), so `killpg`/`kill_group` on our
            // pgid addresses both.
            let addr = args[2].clone();
            let setuid_helper = args[3].clone();
            #[allow(clippy::zombie_processes)] // intentional: grandchild must outlive us; containment kills/refuses us
            let _gc = std::process::Command::new(setuid_helper)
                .args(["setuid-control-block", &addr, "P"])
                .spawn()
                .unwrap();
            // Become a control-block ourselves (no test-owned stdin → no EOF confound).
            let mut sock = std::net::TcpStream::connect(&addr).unwrap();
            sock.write_all(b"R\n").unwrap();
            sock.flush().unwrap();
            let mut buf = [0u8; 1];
            let _ = sock.read(&mut buf);
        }
        #[cfg(unix)]
        "setuid-control-block" => {
            // Only ever exec'd from a SEPARATE, pre-provisioned copy of this binary that CI
            // chowns root:root and chmods u+s (see `COSCA_TEST_SETUID_HELPER` in
            // tests/group_teardown_setuid.rs). Reports readiness (or a provisioning
            // failure) as ONE line, then blocks like control-block. A single connect: every
            // outcome — success or failure — is reported over the SAME socket, so the
            // harness always gets a definite answer instead of an ambiguous connect-refused.
            let addr = &args[2];
            let tag = args.get(3).map(String::as_str).unwrap_or("?");
            let mut sock = std::net::TcpStream::connect(addr).unwrap();

            // The setuid-root file bit must already have made us effective-root at exec
            // time. If not, the copy is not actually setuid-root (wrong owner/mode) or the
            // filesystem it lives on is mounted `nosuid` — report loudly, never silently
            // proceed as an ordinary (killable) process, which would make the caller's
            // later "still alive" assertion pass for the wrong reason.
            // Safety: geteuid() has no preconditions.
            let euid_before = unsafe { libc::geteuid() };
            if euid_before != 0 {
                sock.write_all(
                    format!(
                        "F effective uid is {euid_before}, not 0 at exec — the setuid-root bit \
                         did not take effect (wrong owner/mode on COSCA_TEST_SETUID_HELPER's \
                         target, or a nosuid mount)\n"
                    )
                    .as_bytes(),
                )
                .unwrap();
                sock.flush().unwrap();
                exit(3);
            }
            // setuid(0): collapse the REAL uid to 0 too, not just the effective/saved uid the
            // exec-time setuid bit already granted. This is what makes us unsignalable by the
            // original unprivileged caller IN FACT: the kernel's own permission check
            // (`kill_ok_by_cred`) treats a matching REAL uid as sufficient permission on its
            // own, so without this call our real uid would still equal the caller's and this
            // whole scenario would not reproduce the bug at all — see group.rs's module docs.
            // Safety: setuid() has no preconditions; failure is reported below, not ignored.
            let rc = unsafe { libc::setuid(0) };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                sock.write_all(format!("F setuid(0) failed: {err}\n").as_bytes())
                    .unwrap();
                sock.flush().unwrap();
                exit(3);
            }
            // Safety: getuid()/geteuid() have no preconditions.
            let (ruid, euid) = unsafe { (libc::getuid(), libc::geteuid()) };
            if ruid != 0 || euid != 0 {
                sock.write_all(format!("F post-setuid(0) ids are ruid={ruid} euid={euid}, expected 0/0\n").as_bytes())
                    .unwrap();
                sock.flush().unwrap();
                exit(3);
            }
            // Success: report OUR pid so the harness can independently probe kill(pid, 0)
            // from the ORIGINAL caller's uid — an oracle outside this crate's own code path.
            sock.write_all(format!("{tag} {}\n", std::process::id()).as_bytes())
                .unwrap();
            sock.flush().unwrap();
            let mut buf = [0u8; 1];
            let _ = sock.read(&mut buf);
        }
        #[cfg(unix)]
        "spawn-grandchild-escapee" => {
            // Like spawn-grandchild, but FIRST escape any process group / session
            // the parent put us in by calling setsid(2). A killpg-based teardown
            // aimed at our original pgid would then miss us and the grandchild;
            // only the identity-aware TreeWalk catches us. We become a new session
            // leader, THEN spawn the grandchild (it inherits the new session), THEN
            // hold our own control connection.
            let addr = args[2].clone();
            // Safety: setsid() has no preconditions here (we are not already a
            // process-group leader in the common spawn path) and is always safe to
            // call; on EPERM we proceed anyway (best-effort escape for the test).
            unsafe {
                let _ = libc::setsid();
            }
            let exe = std::env::current_exe().unwrap();
            #[allow(clippy::zombie_processes)] // intentional: grandchild must outlive us; TreeWalk kills it
            let _gc = std::process::Command::new(exe)
                .args(["control-block", &addr, "G"])
                .spawn()
                .unwrap();
            let mut sock = std::net::TcpStream::connect(&addr).unwrap();
            sock.write_all(b"R").unwrap();
            sock.flush().unwrap();
            let mut buf = [0u8; 1];
            let _ = sock.read(&mut buf);
        }
        // The shape both current macOS mechanisms lose: a grandchild that leaves the session,
        // is reparented to launchd when its parent exits, and execs. The relay does the setsid
        // and exits at once; the grandchild it spawned reparents to pid 1 with its own pgid.
        #[cfg(unix)]
        "spawn-orphan-escapee" => {
            let addr = args[2].clone();
            let exe = std::env::current_exe().unwrap();
            let mut relay = std::process::Command::new(&exe);
            relay.args(["orphan-relay", &addr]);
            // SAFETY: pre_exec runs post-fork, pre-exec; libc::setsid is async-signal-safe.
            unsafe {
                use std::os::unix::process::CommandExt;
                relay.pre_exec(|| {
                    libc::setsid(); // best-effort: EPERM only if already a leader
                    Ok(())
                });
            }
            let mut relay = relay.spawn().unwrap();
            relay.wait().unwrap(); // its exit is the reparenting event
                                   // Same wire format as the grandchild, so the test parses one shape.
            run_control_echo_pid(&addr, "R");
        }
        #[cfg(unix)]
        "orphan-relay" => {
            let addr = args[2].clone();
            let exe = std::env::current_exe().unwrap();
            #[allow(clippy::zombie_processes)] // intentional: the grandchild must outlive us
            let _ = std::process::Command::new(&exe)
                .args(["control-echo-pid", &addr, "G"])
                .spawn()
                .unwrap();
            std::process::exit(0);
        }
        #[cfg(unix)]
        "spawn-grandchild-ignore-term" => {
            // spawn-grandchild where BOTH members ignore SIGTERM: the group's soft signal
            // provably kills neither, so only a tree escalation's hard sweep tears them down.
            // SAFETY: installing SIG_IGN for SIGTERM has no preconditions and is always safe.
            unsafe {
                let _ = libc::signal(libc::SIGTERM, libc::SIG_IGN);
            }
            let addr = args[2].clone();
            let exe = std::env::current_exe().unwrap();
            #[allow(clippy::zombie_processes)] // intentional: see spawn-grandchild
            let _gc = std::process::Command::new(exe)
                .args(["control-block-ignore-term", &addr, "G"])
                .spawn()
                .unwrap();
            let mut sock = std::net::TcpStream::connect(&addr).unwrap();
            sock.write_all(b"R").unwrap();
            sock.flush().unwrap();
            let mut buf = [0u8; 1];
            let _ = sock.read(&mut buf);
        }
        #[cfg(unix)]
        "control-block-ack-term" => {
            // Like control-block-ignore-term, but the SIGTERM handler ACKS by writing "T" to
            // the control socket and returns — the process stays alive, so SIGKILL remains
            // its only terminating signal AND signal delivery is observable as a real event.
            use std::os::fd::AsRawFd;
            static SOCK_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);
            extern "C" fn ack(_sig: libc::c_int) {
                let fd = SOCK_FD.load(std::sync::atomic::Ordering::Relaxed);
                if fd >= 0 {
                    // SAFETY: write(2) is async-signal-safe; the fd outlives the handler.
                    unsafe { libc::write(fd, b"T".as_ptr().cast(), 1) };
                }
            }
            let addr = &args[2];
            let tag = args.get(3).map(String::as_str).unwrap_or("?");
            let mut sock = std::net::TcpStream::connect(addr).unwrap();
            SOCK_FD.store(sock.as_raw_fd(), std::sync::atomic::Ordering::Relaxed);
            // SAFETY: the handler only calls async-signal-safe write(2).
            unsafe {
                let _ = libc::signal(libc::SIGTERM, ack as *const () as libc::sighandler_t);
            }
            sock.write_all(tag.as_bytes()).unwrap();
            sock.flush().unwrap();
            let mut buf = [0u8; 1];
            // Retry EINTR: the SIGTERM interrupts this read on platforms without SA_RESTART.
            loop {
                match sock.read(&mut buf) {
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    _ => break,
                }
            }
        }
        #[cfg(unix)]
        "spawn-grandchild-stubborn-child" => {
            // spawn-grandchild where only the GRANDCHILD ignores SIGTERM: the group's soft
            // signal kills the root (default disposition) but leaves the grandchild — a
            // survivor only the post-grace hard sweep can reach.
            let addr = args[2].clone();
            let exe = std::env::current_exe().unwrap();
            #[allow(clippy::zombie_processes)] // intentional: see spawn-grandchild
            let _gc = std::process::Command::new(exe)
                .args(["control-block-ignore-term", &addr, "G"])
                .spawn()
                .unwrap();
            let mut sock = std::net::TcpStream::connect(&addr).unwrap();
            sock.write_all(b"R").unwrap();
            sock.flush().unwrap();
            let mut buf = [0u8; 1];
            let _ = sock.read(&mut buf);
        }
        #[cfg(windows)]
        "control-block-ignore-break" => {
            // Ignore CTRL_BREAK, then behave exactly like control-block — only a hard kill ends us.
            install_ignore_break();
            let addr = &args[2];
            let tag = args.get(3).map(String::as_str).unwrap_or("?");
            let mut sock = std::net::TcpStream::connect(addr).unwrap();
            sock.write_all(tag.as_bytes()).unwrap();
            sock.flush().unwrap();
            let mut buf = [0u8; 1];
            let _ = sock.read(&mut buf);
        }
        #[cfg(windows)]
        "spawn-grandchild-ignore-break" => {
            // spawn-grandchild where BOTH members ignore CTRL_BREAK: whether or not the soft
            // group signal reaches this console group, only the hard sweep tears them down.
            install_ignore_break();
            let addr = args[2].clone();
            let exe = std::env::current_exe().unwrap();
            #[allow(clippy::zombie_processes)] // intentional: see spawn-grandchild
            let _gc = std::process::Command::new(exe)
                .args(["control-block-ignore-break", &addr, "G"])
                .spawn()
                .unwrap();
            let mut sock = std::net::TcpStream::connect(&addr).unwrap();
            sock.write_all(b"R").unwrap();
            sock.flush().unwrap();
            let mut buf = [0u8; 1];
            let _ = sock.read(&mut buf);
        }
        #[cfg(windows)]
        "control-block-ack-break" => {
            // Ack a CTRL_BREAK by writing "B" to the control socket and STAY ALIVE (the handler
            // returns "handled"). Receipt is then an observed event that cannot race a later
            // teardown, unlike a child that dies on the break.
            use std::sync::Mutex;
            use windows::core::BOOL;
            use windows::Win32::System::Console::SetConsoleCtrlHandler;

            // A console ctrl handler runs on an OS-spawned thread, not in signal context, so
            // ordinary allocating I/O is fine here. It writes through its OWN clone of the
            // socket, so it never contends with the main thread's blocking read. Only
            // CTRL_BREAK is acked: acking any event would let a stray CTRL_C or CTRL_CLOSE
            // satisfy a "the child received CTRL_BREAK" assertion.
            static ACK: std::sync::OnceLock<Mutex<std::net::TcpStream>> = std::sync::OnceLock::new();
            unsafe extern "system" fn ack(event: u32) -> BOOL {
                if event != windows::Win32::System::Console::CTRL_BREAK_EVENT {
                    return BOOL(0); // not handled — default disposition applies
                }
                // Every failure below traces and returns NOT-handled instead of fabricating a
                // success — including a poisoned lock, same disposition as the unset-ACK case.
                // Nothing panics: unwinding out of an `extern "system"` fn aborts.
                let Some(m) = ACK.get() else {
                    eprintln!("cosca_testbin: ctrl handler fired before ACK was set");
                    return BOOL(0);
                };
                let Ok(mut s) = m.lock() else {
                    eprintln!("cosca_testbin: ack socket mutex poisoned");
                    return BOOL(0);
                };
                if let Err(e) = s.write_all(b"B").and_then(|()| s.flush()) {
                    eprintln!("cosca_testbin: ack write failed: {e}");
                }
                BOOL(1) // handled — do not die
            }

            let addr = &args[2];
            let tag = args.get(3).map(String::as_str).unwrap_or("?");
            let mut sock = std::net::TcpStream::connect(addr).unwrap();
            ACK.set(Mutex::new(sock.try_clone().unwrap()))
                .expect("this arm runs exactly once per process");
            // SAFETY: installing a console ctrl handler has no preconditions.
            unsafe { SetConsoleCtrlHandler(Some(ack), true) }.expect("install ctrl handler");
            sock.write_all(tag.as_bytes()).unwrap();
            sock.flush().unwrap();
            let mut buf = [0u8; 1];
            let _ = sock.read(&mut buf); // blocks until the socket closes (our death)
        }
        #[cfg(windows)]
        "spawn-grandchild-ack-break" => {
            // A 2-level tree for the lone graceful op's radius: the ROOT ignores CTRL_BREAK (so
            // only the escalation can end it), while its grandchild ACKS the break and stays
            // alive. The grandchild is an ordinary std spawn with creation flags 0, so it joins
            // the root's console group AND console — exactly the descendant the cooperative half
            // reaches and the forced half does not.
            install_ignore_break();
            let addr = args[2].clone();
            let exe = std::env::current_exe().unwrap();
            #[allow(clippy::zombie_processes)] // intentional: see spawn-grandchild
            let _gc = std::process::Command::new(exe)
                .args(["control-block-ack-break", &addr, "G"])
                .spawn()
                .unwrap();
            let mut sock = std::net::TcpStream::connect(&addr).unwrap();
            sock.write_all(b"R").unwrap();
            sock.flush().unwrap();
            let mut buf = [0u8; 1];
            let _ = sock.read(&mut buf);
        }
        #[cfg(windows)]
        "report-nested-terminate" => {
            use std::fmt::Write as _;

            // This process is itself spawned CONTAINED (so NESTED_ENV is set), which makes the
            // crate spawn below a nested member: Containment::Delegated, owning no tree teardown
            // of its own, yet leading its own console process group. Connect FIRST so a panic
            // anywhere below reaches the test as socket EOF instead of hanging it.
            let mut report_sock = std::net::TcpStream::connect(&args[2]).unwrap();

            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let ack_addr = listener.local_addr().unwrap().to_string();
            let exe = std::env::current_exe().unwrap();
            let mut cmd = cosca::Command::new();
            cmd.executable(&exe)
                .args(["cosca_testbin", "control-block-ack-break", &ack_addr, "G"])
                .contain();
            let child = cmd.spawn().expect("spawn nested delegated child");
            // The tag proves the child is alive AND has completed console registration — it is
            // written after its ctrl handler is installed — before anything is signalled.
            let (mut ack, _) = listener.accept().expect("accept ack socket");
            let mut t = [0u8; 1];
            ack.read_exact(&mut t).expect("read ack tag");
            assert_eq!(&t, b"G", "wrong ack tag");

            let in_our_console = |pid: u32| {
                let mut buf = vec![0u32; 16];
                loop {
                    // SAFETY: standard Win32; `buf` is a valid writable slice.
                    let n = unsafe { windows::Win32::System::Console::GetConsoleProcessList(&mut buf) } as usize;
                    if n == 0 {
                        return None; // no console at all
                    }
                    if n <= buf.len() {
                        return Some(buf[..n].contains(&pid));
                    }
                    buf.resize(n, 0);
                }
            };
            let saw_break = |sock: &mut std::net::TcpStream| -> &'static str {
                let mut b = [0u8; 1];
                match sock.read(&mut b) {
                    Ok(1) if &b == b"B" => "1",
                    Ok(1) => "?",
                    Ok(_) => "0",
                    Err(_) => "E",
                }
            };
            let describe = |e: &cosca::error::Error| match e {
                cosca::error::Error::NoConsole { .. } => "NoConsole".to_string(),
                cosca::error::Error::Unsupported { .. } => "Unsupported".to_string(),
                cosca::error::Error::Containment { .. } => "Containment".to_string(),
                other => format!("Other({})", other.to_string().replace(char::is_whitespace, "_")),
            };

            let containment = if child.containment() == cosca::Containment::Delegated {
                "delegated"
            } else {
                "other" // anything else fails the assertion, which is the point
            };
            let mechanism = match child.graceful_mechanism() {
                cosca::GracefulMechanism::ConsoleGroup => "console-group",
                cosca::GracefulMechanism::OtherConsoleGroup => "other-console-group",
                cosca::GracefulMechanism::Process => "process",
                _ => "none",
            };
            let membership = in_our_console(child.id().pid());
            let in_console = match membership {
                Some(true) => "1",
                Some(false) => "0",
                None => "?",
            };
            // The invariant that did NOT change, pinned in the same report as the one that did:
            // a nested member owns no tree teardown.
            let tree = match child.terminate_tree() {
                Err(cosca::error::Error::Unsupported { .. }) => "Unsupported",
                _ => "other",
            };
            let terminate = match child.terminate() {
                Ok(()) => "Ok".to_string(),
                Err(e) => describe(&e),
            };
            // The blocking read happens ONLY where delivery is guaranteed; otherwise kill first
            // and then read, so the read collects EOF or a reset and this mode always reports.
            // `kill()`, never `kill_tree()`: this child's kill_tree is unconditionally
            // Unsupported (the `tree` field above), so a kill_tree fallback would error every
            // time, never perform the read, and leave a live unreaped grandchild behind.
            let delivered = membership == Some(true) && mechanism == "console-group" && terminate == "Ok";
            let seen = if delivered {
                saw_break(&mut ack)
            } else {
                match child.kill() {
                    Ok(()) => saw_break(&mut ack),
                    Err(_) => "K", // the teardown failed, so delivery was never observable
                }
            };

            // Unconditional, so the happy path (where the child is still alive by design) reaps
            // too rather than relying on the fallback branch having run.
            let cleanup = match child.kill() {
                Ok(()) => {
                    child.wait().expect("reap the nested child");
                    "Ok".to_string()
                }
                // Skip the reap: an unbounded wait on a provably-live child would block forever.
                // Nothing leaks — this process is itself contained by the test, so the kernel
                // removes any survivor when that job handle closes.
                Err(e) => describe(&e),
            };

            let mut line = String::new();
            write!(
                line,
                "containment={containment} mechanism={mechanism} in_console={in_console} \
                 terminate={terminate} break={seen} tree={tree} cleanup={cleanup}"
            )
            .unwrap();
            report_sock.write_all(line.as_bytes()).unwrap();
            report_sock.flush().unwrap();
        }
        #[cfg(windows)]
        "report-console-lone" => {
            use std::fmt::Write as _;
            use std::time::Duration;

            // Connect FIRST — the test blocks on accept(), so a panic below must reach it as
            // socket EOF instead of hanging the suite. Sibling of `report-console-terminate`;
            // see there for why each token is whitespace-free.
            let mut report_sock = std::net::TcpStream::connect(&args[2]).unwrap();

            let mut list = [0u32; 1];
            // SAFETY: both calls are standard Win32; `list` is a valid writable slice.
            let n = unsafe {
                windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(0));
                windows::Win32::System::Console::GetConsoleProcessList(&mut list)
            };
            let console = if n != 0 {
                "1"
            } else if std::io::Error::last_os_error().raw_os_error()
                == Some(windows::Win32::Foundation::ERROR_INVALID_HANDLE.0 as i32)
            {
                "0" // genuinely no console
            } else {
                "?" // the probe itself failed
            };

            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let ack_addr = listener.local_addr().unwrap().to_string();
            let exe = std::env::current_exe().unwrap();

            let mut cmd = cosca::Command::new();
            cmd.executable(&exe)
                .args(["cosca_testbin", "control-block-ack-break", &ack_addr, "R"])
                .contain();
            let child = cmd.spawn().expect("spawn contained root");
            let (mut ack, _) = listener.accept().expect("accept ack socket");
            let mut t = [0u8; 1];
            ack.read_exact(&mut t).expect("read ack tag");
            assert_eq!(&t, b"R", "wrong ack tag");

            let in_our_console = |pid: u32| {
                // Grow to whatever count the API reports rather than capping.
                let mut buf = vec![0u32; 16];
                loop {
                    // SAFETY: standard Win32; `buf` is a valid writable slice.
                    let n = unsafe { windows::Win32::System::Console::GetConsoleProcessList(&mut buf) } as usize;
                    if n == 0 {
                        return None; // no console at all
                    }
                    if n <= buf.len() {
                        return Some(buf[..n].contains(&pid));
                    }
                    buf.resize(n, 0);
                }
            };
            let three_way = |b: Option<bool>| match b {
                Some(true) => "1",
                Some(false) => "0",
                None => "?",
            };
            let saw_break = |sock: &mut std::net::TcpStream| -> &'static str {
                let mut b = [0u8; 1];
                match sock.read(&mut b) {
                    Ok(1) if &b == b"B" => "1",
                    Ok(1) => "?",
                    Ok(_) => "0",
                    Err(_) => "E",
                }
            };
            let describe = |e: &cosca::error::Error| match e {
                cosca::error::Error::NoConsole { .. } => "NoConsole".to_string(),
                cosca::error::Error::Unsupported { .. } => "Unsupported".to_string(),
                cosca::error::Error::Containment { .. } => "Containment".to_string(),
                other => format!("Other({})", other.to_string().replace(char::is_whitespace, "_")),
            };
            let liveness = |l: cosca::identity::Liveness| match l {
                cosca::identity::Liveness::Alive => "alive",
                cosca::identity::Liveness::Dead => "dead",
                cosca::identity::Liveness::Unknown => "unknown",
            };
            // Two of GracefulMechanism's Display strings contain spaces, and the report is parsed
            // by splitting on whitespace — so this mode emits its own tokens.
            let mechanism = match child.graceful_mechanism() {
                cosca::GracefulMechanism::ConsoleGroup => "console-group",
                cosca::GracefulMechanism::OtherConsoleGroup => "other-console-group",
                cosca::GracefulMechanism::Process => "process",
                _ => "none",
            };

            let c_in_console = in_our_console(child.id().pid());
            let terminate = match child.terminate() {
                Ok(()) => "Ok".to_string(),
                Err(e) => describe(&e),
            };
            let alive_after_terminate = liveness(child.is_alive());
            // The blocking read happens ONLY where delivery is guaranteed: the child was MEASURED
            // to be in our console, its mechanism says the flags do not exclude delivery, and the
            // call reported success. Every other combination defers the read until after the
            // cleanup kill below, so it collects EOF or a reset and this mode always reports.
            let delivered = c_in_console == Some(true) && mechanism == "console-group" && terminate == "Ok";
            let early_break = delivered.then(|| saw_break(&mut ack));

            // ZERO grace: the acker survives its break by design, so the escalation is
            // deterministic and its exit code is what proves the forced half ran.
            let (graceful, graceful_code) = match child.graceful_shutdown(Duration::ZERO) {
                Ok(status) => (
                    "Ok".to_string(),
                    status.code().map(|c| c.to_string()).unwrap_or_else(|| "none".into()),
                ),
                Err(e) => (describe(&e), "none".to_string()),
            };
            let alive_after_graceful = liveness(child.is_alive());

            let cleanup = match child.kill() {
                Ok(()) => "Ok".to_string(),
                Err(e) => describe(&e),
            };
            if cleanup == "Ok" {
                child.wait().expect("reap the acker");
            }
            // `K`: the teardown that should have ended the child failed, so delivery was never
            // observable — distinct from an observed non-delivery.
            let seen = match early_break {
                Some(seen) => seen,
                None if cleanup == "Ok" => saw_break(&mut ack),
                None => "K",
            };

            let mut line = String::new();
            write!(
                line,
                "console={console} c_in_console={} mechanism={mechanism} terminate={terminate} \
                 alive_after_terminate={alive_after_terminate} break={seen} graceful={graceful} \
                 graceful_code={graceful_code} alive_after_graceful={alive_after_graceful} \
                 cleanup={cleanup}",
                three_way(c_in_console),
            )
            .unwrap();
            report_sock.write_all(line.as_bytes()).unwrap();
            report_sock.flush().unwrap();
        }
        #[cfg(windows)]
        "report-breakaway" => {
            breakaway::run(&args[2], &args[3], &args[4]);
        }
        #[cfg(windows)]
        "report-console-identity" => {
            let caller_pid: u32 = args[3].parse().expect("argv[3]: the spawning process's pid");
            console_identity::run(&args[2], caller_pid);
        }
        #[cfg(windows)]
        "report-console-terminate" => {
            use std::fmt::Write as _;
            use std::time::Duration;

            // Connect FIRST. The test blocks on accept(), so a panic anywhere below must still
            // reach it as socket EOF instead of hanging the suite.
            let mut report_sock = std::net::TcpStream::connect(&args[2]).unwrap();

            // Three-way: a zero return is also how this API reports failure, so "?" must never
            // be able to satisfy the test's `console=0` vacuity guard. The last error is
            // cleared first so the code read below is provably the one this call set.
            let mut list = [0u32; 1];
            // SAFETY: both calls are standard Win32; `list` is a valid writable slice.
            let n = unsafe {
                windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(0));
                windows::Win32::System::Console::GetConsoleProcessList(&mut list)
            };
            let console = if n != 0 {
                "1"
            } else if std::io::Error::last_os_error().raw_os_error()
                == Some(windows::Win32::Foundation::ERROR_INVALID_HANDLE.0 as i32)
            {
                "0" // genuinely no console
            } else {
                "?" // the probe itself failed
            };

            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let ack_addr = listener.local_addr().unwrap().to_string();
            let exe = std::env::current_exe().unwrap();

            // A contained root that acks CTRL_BREAK over its own socket and keeps running.
            let spawn_acker = |tag: &str| {
                let mut cmd = cosca::Command::new();
                cmd.executable(&exe)
                    .args(["cosca_testbin", "control-block-ack-break", &ack_addr, tag])
                    .contain();
                let child = cmd.spawn().expect("spawn contained root");
                let (mut sock, _) = listener.accept().expect("accept ack socket");
                let mut t = [0u8; 1];
                sock.read_exact(&mut t).expect("read ack tag");
                assert_eq!(&t, tag.as_bytes(), "wrong ack tag");
                (child, sock)
            };
            // Is a given pid attached to OUR console? Measured, not assumed: `console=1` alone
            // only says WE have a console, not that the root is in it, and a blocking read
            // gated on that weaker fact could hang forever. The acker has already handshaked
            // its tag by the time this runs, so it has completed console registration.
            let in_our_console = |pid: u32| {
                // Grow to whatever count the API reports rather than capping: a too-small
                // buffer makes it return the REQUIRED count without filling, which a fixed cap
                // would silently read as "absent".
                let mut buf = vec![0u32; 16];
                loop {
                    // SAFETY: standard Win32; `buf` is a valid writable slice.
                    let n = unsafe { windows::Win32::System::Console::GetConsoleProcessList(&mut buf) } as usize;
                    if n == 0 {
                        return false; // no console at all
                    }
                    if n <= buf.len() {
                        return buf[..n].contains(&pid);
                    }
                    buf.resize(n, 0);
                }
            };
            // "1" delivered, "0" EOF (died without acking), "?" unexpected byte, "E" socket
            // failure, "K" not read because the teardown that should have ended the child
            // failed. A transport error must not masquerade as "no delivery".
            let saw_break = |sock: &mut std::net::TcpStream| -> &'static str {
                let mut b = [0u8; 1];
                match sock.read(&mut b) {
                    Ok(1) if &b == b"B" => "1",
                    Ok(1) => "?",
                    Ok(_) => "0",
                    Err(_) => "E",
                }
            };
            // Every field must stay ONE whitespace-free token: the report is parsed by
            // splitting on whitespace, and an Error's Display is full of spaces.
            let describe = |e: &cosca::error::Error| match e {
                cosca::error::Error::NoConsole { .. } => "NoConsole".to_string(),
                other => format!("Other({})", other.to_string().replace(char::is_whitespace, "_")),
            };
            let classify = |r: Result<(), cosca::error::Error>| match r {
                Ok(()) => "Ok".to_string(),
                Err(e) => describe(&e),
            };

            // (1) terminate_tree — signal-only, so delivery is observable without escalation.
            let (c1, mut ack1) = spawn_acker("R");
            // One whitespace-free token per field, so the report parses unambiguously; the
            // Display form ("job object") would split across two fields.
            let containment_tag = match c1.containment() {
                cosca::Containment::JobObject => "job",
                _ => "other", // anything else fails the assertion, which is the point
            };
            // One unambiguous token per liveness state. Never fold `Unknown` in with
            // `Dead`: "couldn't tell" is not evidence that the tree went away, and each
            // assertion below is proving something concrete about survival.
            let liveness = |l: cosca::identity::Liveness| match l {
                cosca::identity::Liveness::Alive => "alive",
                cosca::identity::Liveness::Dead => "dead",
                cosca::identity::Liveness::Unknown => "unknown",
            };
            let c1_in_console = in_our_console(c1.id().pid());
            let terminate = classify(c1.terminate_tree());
            let alive_after_terminate = liveness(c1.is_alive());
            // The blocking wait for delivery happens ONLY where delivery is guaranteed: the
            // root was MEASURED to be in our console AND terminate reported success. Every
            // other combination kills first and collects EOF, so it always reaches the report
            // and fails as an assertion rather than as a suite hang. The post-kill read/reap
            // only runs when the kill itself succeeded — on a failed kill the child is still
            // alive and blocked, so both would block forever and discard the kill error.
            let (terminate_break, kill_tree) = if c1_in_console && terminate == "Ok" {
                let seen = saw_break(&mut ack1);
                (seen, classify(c1.kill_tree()))
            } else {
                let killed = classify(c1.kill_tree());
                let seen = if killed == "Ok" { saw_break(&mut ack1) } else { "K" };
                (seen, killed)
            };
            if kill_tree == "Ok" {
                c1.wait().expect("reap probe root 1");
            }

            // (2) graceful_shutdown_tree — the escalation trio, ZERO grace. Delivery is proved
            // by (1); this leg proves the trio's own classification and that a failure leaves
            // the tree untouched.
            let (c2, _ack2) = spawn_acker("S");
            let graceful = match c2.graceful_shutdown_tree(Duration::ZERO) {
                Ok(_) => "Ok".to_string(),
                Err(e) => describe(&e),
            };
            let alive_after_graceful = liveness(c2.is_alive());
            // "Skipped" — NOT "Ok": nothing was called on this path, so reporting a success
            // would be a tautology. Whether the tree really went away is carried by the
            // measured `alive_after_graceful`.
            let graceful_cleanup = if graceful == "Ok" {
                "Skipped".to_string()
            } else {
                let killed = classify(c2.kill_tree());
                if killed == "Ok" {
                    c2.wait().expect("reap probe root 2"); // a failed sweep leaves it alive
                }
                killed
            };

            let mut line = String::new();
            write!(
                line,
                "console={console} c1_in_console={} containment={containment_tag} \
                 terminate_tree={terminate} alive_after_terminate={alive_after_terminate} \
                 terminate_break={terminate_break} kill_tree={kill_tree} graceful={graceful} \
                 alive_after_graceful={alive_after_graceful} graceful_cleanup={graceful_cleanup}",
                u8::from(c1_in_console),
            )
            .unwrap();
            report_sock.write_all(line.as_bytes()).unwrap();
            report_sock.flush().unwrap();
        }
        #[cfg(unix)]
        "sid-report" => {
            // Print our session id (getsid(0)) to stdout so the test can verify
            // setsid() actually ran and the child is its own session leader.
            // Safety: getsid(0) has no preconditions and always succeeds for pid 0.
            let sid = unsafe { libc::getsid(0) };
            println!("{sid}");
        }
        #[cfg(unix)]
        "fd3-echo" => {
            // Read all bytes from fd 3 and echo them to stdout. Used by the
            // arbitrary-fd tests to prove the child received its fd 3 mapping.
            // Safety: fd 3 is passed in by the test (via command-fds); this is
            // the only caller and it always provides a valid, open fd 3.
            use std::os::fd::FromRawFd;
            let mut f = unsafe { std::fs::File::from_raw_fd(3) };
            std::io::copy(&mut f, &mut std::io::stdout().lock()).unwrap();
        }
        #[cfg(unix)]
        "fd3-write" => {
            // Write the token bytes to fd 3 and flush. Used by the cgroup-clobber
            // test: if command-fds' dup2 ran before the cgroup self-placement, a
            // stray "0" would corrupt this fd's stream; an exact match proves no
            // clobber. Safety: fd 3 is passed in by the test (via command-fds);
            // this is the only caller and it always provides a valid, open fd 3.
            use std::os::fd::FromRawFd;
            let token = &args[2];
            let mut f = unsafe { std::fs::File::from_raw_fd(3) };
            f.write_all(token.as_bytes()).unwrap();
            f.flush().unwrap();
        }
        "report-nested-kill-tree" => {
            // This process is itself spawned CONTAINED (so NESTED_ENV is set). A crate
            // spawn here is a nested member (Attached::Delegated), whose kill_tree() must
            // be Unsupported. Report 'D' (Delegated + Unsupported) or 'O' (other).
            let addr = &args[2];
            let exe = std::env::current_exe().unwrap();
            let mut gc = cosca::Command::new();
            gc.executable(&exe).args(["cosca_testbin", "exit", "0"]).contain();
            let child = gc.spawn().unwrap();
            // A nested member must report Containment::Delegated AND reject kill_tree as
            // Unsupported. Transmitting both discriminates the Delegated path from an
            // uncontained None (which also yields Unsupported) — so a marker-propagation
            // regression (nested -> None) is caught, not silently passed.
            let is_delegated = child.containment() == cosca::Containment::Delegated;
            let unsupported = matches!(child.kill_tree(), Err(cosca::error::Error::Unsupported { .. }));
            let _ = child.wait();
            let mut sock = std::net::TcpStream::connect(addr).unwrap();
            sock.write_all(if is_delegated && unsupported { b"D" } else { b"O" })
                .unwrap();
            sock.flush().unwrap();
        }
        #[cfg(unix)]
        "control-block-ignore-term" => {
            // Ignore SIGTERM, then behave exactly like control-block.
            // SAFETY: installing SIG_IGN for SIGTERM has no preconditions and is always safe.
            unsafe {
                let _ = libc::signal(libc::SIGTERM, libc::SIG_IGN);
            }
            let addr = &args[2];
            let tag = args.get(3).map(String::as_str).unwrap_or("?");
            let mut sock = std::net::TcpStream::connect(addr).unwrap();
            sock.write_all(tag.as_bytes()).unwrap();
            sock.flush().unwrap();
            let mut buf = [0u8; 1];
            let _ = sock.read(&mut buf);
        }
        "is-elevated-report" => {
            println!("{}", if cosca::elevation::is_elevated() { "1" } else { "0" });
        }
        #[cfg(unix)]
        "controlling-terminal" => {
            let present = cosca::elevation::controlling_terminal_present();
            println!("{}", if present { "1" } else { "0" });
        }
        // Linux PTY harness: become a session leader with no ctty (setsid), acquire the
        // inherited pty slave (fd 3) as controlling terminal (TIOCSCTTY), then probe. stdin
        // is /dev/null, so a `1` here proves the probe reads /dev/tty, not isatty(STDIN).
        #[cfg(target_os = "linux")]
        "acquire-ctty-and-probe" => {
            // SAFETY: setsid has no preconditions here; TIOCSCTTY on the inherited slave fd 3
            // makes it this new session's controlling terminal. Both are one-shot syscalls.
            unsafe {
                assert!(libc::setsid() != -1, "setsid failed");
                assert!(libc::ioctl(3, libc::TIOCSCTTY as _, 0) != -1, "TIOCSCTTY failed");
            }
            let present = cosca::elevation::controlling_terminal_present();
            println!("{}", if present { "1" } else { "0" });
        }
        "write-marker" => {
            let path = &args[2];
            std::fs::write(path, b"1").expect("write marker");
        }
        // Publish our own pid, then block long enough for the run0 propagation test to kill us.
        "write-pid-then-sleep" => {
            std::fs::write(&args[2], std::process::id().to_string()).expect("write pid");
            std::thread::sleep(std::time::Duration::from_secs(600));
        }
        // A long-lived elevated child for the Windows Unkillable/drop test.
        "sleep-marker" => {
            std::thread::sleep(std::time::Duration::from_secs(600));
        }
        other => {
            eprintln!("cosca_testbin: unknown mode {other:?}");
            exit(2);
        }
    }
}
