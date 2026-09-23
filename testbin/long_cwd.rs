//! The `long-cwd-probe` mode: whether a process whose own cwd is longer than `MAX_PATH` can still
//! spawn a child, through cosca's raw backend (which passes that cwd as `lpCurrentDirectory`) and
//! with a NULL `lpCurrentDirectory` (what `std` passes with no `current_dir`).
//!
//! This is the one process that moves its own cwd: it is a separate process, spawned for it.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// One report line per fact, `key=value`, in a fixed order.
pub fn run(base: &str) {
    let long = long_dir(Path::new(base));
    println!("len={}", long.as_os_str().len());
    let plain = set_cwd(long.as_os_str());
    println!("set_plain={}", outcome(&plain));
    let set = if plain.is_ok() {
        true
    } else {
        let mut verbatim = OsString::from(r"\\?\");
        verbatim.push(&long);
        let r = set_cwd(&verbatim);
        println!("set_verbatim={}", outcome(&r));
        r.is_ok()
    };
    if !set {
        return;
    }
    let exe = std::env::current_exe().expect("current_exe");
    let mut raw = cosca::Command::new();
    raw.executable(&exe).args(["cosca_testbin", "exit", "0"]);
    println!(
        "cosca_raw={}",
        spawned(raw.status().map(|s| s.success()).map_err(|e| e.to_string()))
    );
    let null = std::process::Command::new(&exe).args(["exit", "0"]).status();
    println!(
        "null_cwd={}",
        spawned(null.map(|s| s.success()).map_err(|e| e.to_string()))
    );
    let explicit = std::process::Command::new(&exe)
        .args(["exit", "0"])
        .current_dir(std::env::current_dir().expect("current_dir"))
        .status();
    println!(
        "explicit_cwd={}",
        spawned(explicit.map(|s| s.success()).map_err(|e| e.to_string()))
    );
}

/// A directory under `base` whose path is over 300 characters, created through a verbatim path so
/// creating it does not itself depend on long-path support.
fn long_dir(base: &Path) -> PathBuf {
    let mut dir = base.to_path_buf();
    while dir.as_os_str().len() <= 300 {
        dir.push("cosca-long-cwd-component-0123456789");
    }
    let mut verbatim = OsString::from(r"\\?\");
    verbatim.push(&dir);
    std::fs::create_dir_all(&verbatim).expect("create the long directory");
    dir
}

fn set_cwd(path: &std::ffi::OsStr) -> Result<(), u32> {
    let r = std::env::set_current_dir(path);
    r.map_err(|e| e.raw_os_error().map_or(u32::MAX, |c| c as u32))
}

fn outcome(r: &Result<(), u32>) -> String {
    match r {
        Ok(()) => "ok".into(),
        Err(code) => format!("err={code}"),
    }
}

fn spawned(r: Result<bool, String>) -> String {
    match r {
        Ok(true) => "ok".into(),
        Ok(false) => "exit-nonzero".into(),
        Err(e) => format!("err({e})"),
    }
}
