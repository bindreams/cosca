//! Test-only helper spawned by the crate's integration tests. std-only, with
//! one exception: the `report-nested-kill-tree` mode uses the `cosca` crate
//! to exercise the real nested-member `kill_tree` path. Behavior is selected by argv[1].

use std::io::{Read, Write};
use std::process::exit;

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
