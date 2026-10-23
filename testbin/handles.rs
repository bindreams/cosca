//! M2 and M3: the `handles-probe` and `report-handles` modes.
//!
//! `handles-probe <case> <dir>` spawns `report-handles` through each route and prints one line per
//! route with the child's report: `std` (`std::process::Command`), `cosca` (argv-only, std's route
//! on `main`), `raw_fd3` (argv-only with fd 3 mapped) and `raw_exe` (`executable()`), the last two
//! the raw backend. Each child inherits this process's std handles.
//! - `null`: this process sets its own three std handles to null first (M2).
//! - `stray`: this process opens `<dir>\stray.txt`, marks the handle inheritable, gives it to no
//!   `Command`, and asks each child whether that handle value names the file (M3).

use std::ffi::OsString;
use std::path::Path;

use windows::Win32::Foundation::{HANDLE, HANDLE_FLAGS, HANDLE_FLAG_INHERIT};
use windows::Win32::Storage::FileSystem::{
    GetFileType, GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED, FILE_TYPE_CHAR, FILE_TYPE_DISK, FILE_TYPE_PIPE,
};
use windows::Win32::System::Console::{
    SetStdHandle, STD_ERROR_HANDLE, STD_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows::Win32::System::Threading::{GetStartupInfoW, STARTF_USESTDHANDLES, STARTUPINFOW};

#[link(name = "kernel32", kind = "raw-dylib")]
extern "system" {
    /// `GetStdHandle` unwrapped: the `windows` crate turns a null handle into an error carrying a
    /// stale last-error code, and a null std handle is what M2 measures.
    #[link_name = "GetStdHandle"]
    fn raw_std_handle(id: STD_HANDLE) -> HANDLE;
}

/// This process's std handle `id`, null included.
fn std_handle(id: STD_HANDLE) -> HANDLE {
    // SAFETY: no preconditions.
    unsafe { raw_std_handle(id) }
}

const STD: [(&str, STD_HANDLE); 3] = [
    ("stdin", STD_INPUT_HANDLE),
    ("stdout", STD_OUTPUT_HANDLE),
    ("stderr", STD_ERROR_HANDLE),
];

/// `report-handles <report> [<handle>]`: writes to `<report>` whether `STARTF_USESTDHANDLES` was
/// set, what each std handle is (`null`, `char`, `pipe`, `disk`, `unknown`, `invalid`), and the
/// file the hex `<handle>` names in this process (`probed=<path>`, `probed=err=<code>`, or
/// `probed=none` without one).
pub fn report(path: &str, probed: Option<&str>) {
    let mut si = STARTUPINFOW::default();
    // SAFETY: `si` is a live out-parameter.
    unsafe { GetStartupInfoW(&mut si) };
    let mut lines = vec![format!("usestdhandles={}", si.dwFlags.0 & STARTF_USESTDHANDLES.0 != 0)];
    for (name, id) in STD {
        let h = std_handle(id);
        let kind = if h.0.is_null() {
            "null".to_owned()
        } else if h.0 as isize == -1 {
            "invalid".to_owned()
        } else {
            file_type(h)
        };
        lines.push(format!("{name}={kind}"));
    }
    let probed = match probed {
        None => "none".to_owned(),
        Some(hex) => {
            let value = usize::from_str_radix(hex, 16).expect("a hex handle value");
            final_path(HANDLE(value as *mut _))
        }
    };
    lines.push(format!("probed={probed}"));
    std::fs::write(path, lines.join("\n") + "\n").expect("write the report");
}

fn file_type(h: HANDLE) -> String {
    // SAFETY: `h` is this process's own std handle.
    match unsafe { GetFileType(h) } {
        FILE_TYPE_CHAR => "char".to_owned(),
        FILE_TYPE_PIPE => "pipe".to_owned(),
        FILE_TYPE_DISK => "disk".to_owned(),
        _ => format!(
            "unknown(err={})",
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        ),
    }
}

/// The file `h` names, or the error asking gives.
fn final_path(h: HANDLE) -> String {
    let mut buf = vec![0u16; 1024];
    // SAFETY: `buf` is a live buffer of its length; an invalid `h` is an error, not UB.
    let n = unsafe { GetFinalPathNameByHandleW(h, &mut buf, FILE_NAME_NORMALIZED) } as usize;
    if n == 0 || n > buf.len() {
        return format!("err={}", std::io::Error::last_os_error().raw_os_error().unwrap_or(-1));
    }
    String::from_utf16_lossy(&buf[..n])
}

/// `handles-probe <case> <dir>`.
pub fn probe(case: &str, dir: &str) {
    let dir = Path::new(dir);
    match case {
        "null" => {
            let saved: Vec<HANDLE> = STD.iter().map(|&(_, id)| std_handle(id)).collect();
            for (_, id) in STD {
                // SAFETY: sets this process's own std handle; this mode starts no other thread.
                unsafe { SetStdHandle(id, HANDLE::default()) }.expect("SetStdHandle(NULL)");
            }
            let null = STD.iter().all(|&(_, id)| std_handle(id).0.is_null());
            let lines = routes(dir, None, |_| String::new());
            for ((_, id), h) in STD.iter().zip(saved) {
                // SAFETY: restores the handle saved above.
                unsafe { SetStdHandle(*id, h) }.expect("restore the std handle");
            }
            println!("parent_std_handles={}", if null { "null" } else { "not-null" });
            for line in lines {
                println!("{line}");
            }
        }
        "stray" => {
            use std::os::windows::io::AsRawHandle;
            let stray_path = dir.join("stray.txt");
            let stray = std::fs::File::create(&stray_path).expect("create stray.txt");
            let h = HANDLE(stray.as_raw_handle());
            // SAFETY: `h` is owned by `stray`, alive for the call.
            unsafe { windows::Win32::Foundation::SetHandleInformation(h, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT) }
                .expect("mark the stray handle inheritable");
            let mut flags = 0u32;
            // SAFETY: `h` is alive; `flags` is a live out-parameter.
            unsafe { windows::Win32::Foundation::GetHandleInformation(h, &mut flags) }.expect("GetHandleInformation");
            println!(
                "stray_inheritable={}",
                HANDLE_FLAGS(flags).contains(HANDLE_FLAG_INHERIT)
            );
            let hex = format!("{:x}", h.0 as usize);
            let name = stray_path.file_name().unwrap().to_string_lossy().into_owned();
            let lines = routes(dir, Some(&hex), |report| {
                let probed = report.lines().find_map(|l| l.strip_prefix("probed=")).unwrap_or("");
                format!(
                    ",inherited={}",
                    probed.to_ascii_lowercase().ends_with(&name.to_ascii_lowercase())
                )
            });
            for line in lines {
                println!("{line}");
            }
            drop(stray);
        }
        other => panic!("unknown case {other:?}"),
    }
}

/// One `<route>=<report>` line per route; `extra` adds to a report that was written.
fn routes(dir: &Path, probed: Option<&str>, extra: impl Fn(&str) -> String) -> Vec<String> {
    let exe = std::env::current_exe().expect("current_exe");
    let mut lines = Vec::new();
    for route in ["std", "cosca", "raw_fd3", "raw_exe"] {
        let report = dir.join(format!("{route}.txt"));
        let mut args: Vec<OsString> = vec!["report-handles".into(), report.clone().into()];
        args.extend(probed.map(OsString::from));
        let status = match route {
            "std" => {
                #[allow(
                    clippy::disallowed_methods,
                    reason = "no other thread of this process forks: this mode starts none, and the crate's helper threads only wait"
                )]
                let status = std::process::Command::new(&exe).args(&args).status();
                status.map(|s| s.success()).map_err(|e| crate::measure::io_error(&e))
            }
            _ => {
                let mut cmd = cosca::Command::new();
                if route == "raw_exe" {
                    let mut line = OsString::from("cosca_testbin");
                    for arg in &args {
                        line.push(" \"");
                        line.push(arg);
                        line.push("\"");
                    }
                    cmd.executable(&exe).commandline(line);
                } else {
                    cmd.arg(&exe).args(&args);
                }
                if route == "raw_fd3" {
                    cmd.fd(3, cosca::Stdio::null()).expect("map fd 3");
                }
                cmd.status()
                    .map(|s| s.success())
                    .map_err(|e| crate::measure::cosca_error(&e))
            }
        };
        let line = match status {
            Ok(true) => {
                let text = std::fs::read_to_string(&report).expect("the child's report");
                let fields: Vec<&str> = text
                    .lines()
                    .filter(|l| probed.is_some() || !l.starts_with("probed="))
                    .collect();
                format!("{route}={}{}", fields.join(","), extra(&text))
            }
            Ok(false) => format!("{route}=exit-nonzero"),
            Err(why) => format!("{route}={why}"),
        };
        lines.push(line);
    }
    lines
}
