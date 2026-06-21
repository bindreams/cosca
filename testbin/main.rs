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
        other => {
            eprintln!("subprocess_testbin: unknown mode {other:?}");
            exit(2);
        }
    }
}
