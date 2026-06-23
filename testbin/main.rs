//! Test-only helper spawned by the crate's integration tests. std-only; does
//! not depend on the `subprocess` crate. Behavior is selected by argv[1].

use std::io::{Read, Write};
use std::process::exit;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("");
    match mode {
        "argv0" => {
            // Print this process's argv[0] so callers can verify it.
            let argv0 = std::env::args().next().unwrap_or_default();
            println!("{argv0}");
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
        other => {
            eprintln!("subprocess_testbin: unknown mode {other:?}");
            exit(2);
        }
    }
}
