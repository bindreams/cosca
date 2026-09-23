//! `cosca_testbin_cwd`: moves its OWN process's cwd, then measures spawning from there. It is a
//! separate process spawned for the purpose, so no test's cwd changes. `build.rs` embeds a
//! `longPathAware` manifest in this binary alone.
//!
//! Each mode prints `key=value` lines, rendering the directories it made as `<d>` (`<vd>` when
//! verbatim) and the long directory as `<long>`:
//!
//! - `long <base> <unaware-child>`: whether long paths are enabled for this process
//!   (`RtlAreLongPathsEnabled`, the manifest and the `LongPathsEnabled` policy together), then
//!   whether it can enter a directory over 300 characters. If it can, one spawn per route and
//!   child: cosca's raw backend (the cwd as `lpCurrentDirectory`), `std` with no `current_dir` (a
//!   NULL `lpCurrentDirectory`, main's route) and `std` with the long `current_dir`. The children
//!   are this binary (long-path aware) and `<unaware-child>` (`cosca_testbin_image`, which is not).
//! - `verbatim <base> <image-child>`: enters `\\?\<d>`, then reports what Win32 and cosca make of
//!   `tool.exe.`, `sub.` and `sub.\tool.exe` against that cwd, and of a rooted name and a `..` run
//!   past its root.
//! - `drive-dir` and `verbatim-unc`: see [`completion`].
//! - `report-cwd`: prints `cwd=` and this process's cwd; the long-path-aware child.
//!
//! A `[[bin]]` cannot be `cfg`-ed out, so off Windows it exits 1.

#[cfg(windows)]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("long") => probe::long(&args[2], &args[3]),
        Some("verbatim") => probe::verbatim(&args[2], &args[3]),
        Some("drive-dir") => completion::drive_dir(&args[2], &args[3]),
        Some("verbatim-unc") => completion::verbatim_unc(&args[2], &args[3]),
        Some("report-cwd") => println!("cwd={}", std::env::current_dir().unwrap().display()),
        other => panic!("unknown mode {other:?}"),
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("cosca_testbin_cwd is a Windows probe");
    std::process::exit(1);
}

#[cfg(windows)]
#[path = "cwd/completion.rs"]
mod completion;

#[cfg(windows)]
mod probe {
    use std::ffi::{OsStr, OsString};
    use std::path::{Path, PathBuf};

    #[link(name = "ntdll", kind = "raw-dylib")]
    extern "system" {
        /// Whether this process may use paths past `MAX_PATH`: its manifest opts in AND the
        /// `LongPathsEnabled` policy is set.
        fn RtlAreLongPathsEnabled() -> u8;
    }

    /// Replaces each `(from, to)` in `s`, in order.
    pub(crate) struct Render(pub(crate) Vec<(String, &'static str)>);

    impl Render {
        pub(crate) fn apply(&self, s: &str) -> String {
            self.0
                .iter()
                .fold(s.to_owned(), |s, (from, to)| s.replace(from.as_str(), to))
        }
    }

    pub(crate) fn verbatim_of(dir: &Path) -> OsString {
        let mut v = OsString::from(r"\\?\");
        v.push(dir);
        v
    }

    /// `base`, canonical and without its `\\?\`, so every path the probe prints spells it alike.
    pub(crate) fn canonical(base: &str) -> PathBuf {
        let full = std::fs::canonicalize(base).expect("canonicalize the base");
        let full = full.to_str().expect("a UTF-8 base");
        PathBuf::from(full.strip_prefix(r"\\?\").expect("a verbatim canonical path"))
    }

    pub(crate) fn set_cwd(path: &OsStr) -> Result<(), u32> {
        let r = std::env::set_current_dir(path);
        r.map_err(|e| e.raw_os_error().map_or(u32::MAX, |c| c as u32))
    }

    pub(crate) fn outcome(r: &Result<(), u32>) -> String {
        match r {
            Ok(()) => "ok".into(),
            Err(code) => format!("err={code}"),
        }
    }

    /// A spawn's outcome: `ok,` and the child's `key=` line on success.
    pub(crate) fn spawned(r: std::io::Result<(bool, Vec<u8>)>, key: &str, render: &Render) -> String {
        match r {
            Ok((true, stdout)) => {
                let stdout = String::from_utf8_lossy(&stdout);
                match stdout.lines().find(|l| l.starts_with(key)) {
                    Some(line) => format!("ok,{}", render.apply(line)),
                    None => format!("ok,no {key} line"),
                }
            }
            Ok((false, _)) => "exit-nonzero".into(),
            Err(e) => match e.raw_os_error() {
                Some(code) => format!("err={code}"),
                None => format!("err({:?})", e.kind()),
            },
        }
    }

    pub(crate) fn cosca_output(cmd: &mut cosca::Command) -> std::io::Result<(bool, Vec<u8>)> {
        match cmd.output() {
            Ok(out) => Ok((out.status.success(), out.stdout)),
            Err(cosca::error::Error::Io(e)) => Err(e),
            Err(other) => Err(std::io::Error::other(other.to_string())),
        }
    }

    pub(crate) fn std_output(cmd: &mut std::process::Command) -> std::io::Result<(bool, Vec<u8>)> {
        cmd.output().map(|out| (out.status.success(), out.stdout))
    }

    pub fn long(base: &str, unaware: &str) {
        // SAFETY: no arguments; reads this process's own state.
        let enabled = unsafe { RtlAreLongPathsEnabled() } != 0;
        println!("long_paths_enabled={enabled}");
        let d = canonical(base);
        let mut long = d.clone();
        while long.as_os_str().len() <= 300 {
            long.push("cosca-long-cwd-component-0123456789");
        }
        std::fs::create_dir_all(verbatim_of(&long)).expect("create the long directory");
        let plain = set_cwd(long.as_os_str());
        println!("set_plain={}", outcome(&plain));
        if plain.is_err() {
            println!("set_verbatim={}", outcome(&set_cwd(&verbatim_of(&long))));
            return;
        }
        let render = Render(vec![
            (long.to_str().unwrap().to_owned(), "<long>"),
            (d.to_str().unwrap().to_owned(), "<d>"),
        ]);
        let aware = std::env::current_exe().unwrap();
        for (label, child, args) in [
            ("aware", aware.as_path(), &["report-cwd"][..]),
            ("unaware", Path::new(unaware), &[][..]),
        ] {
            let mut line = OsString::from("child");
            for arg in args {
                line.push(" ");
                line.push(arg);
            }
            let mut raw = cosca::Command::new();
            raw.executable(child).commandline(line);
            println!("cosca_raw_{label}={}", spawned(cosca_output(&mut raw), "cwd=", &render));
            let null = std_output(std::process::Command::new(child).args(args));
            println!("null_cwd_{label}={}", spawned(null, "cwd=", &render));
            let explicit = std_output(std::process::Command::new(child).args(args).current_dir(&long));
            println!("explicit_cwd_{label}={}", spawned(explicit, "cwd=", &render));
        }
    }

    pub fn verbatim(base: &str, image: &str) {
        let d = canonical(base).join("d");
        std::fs::create_dir_all(d.join("sub")).expect("create <d>\\sub");
        std::fs::copy(image, d.join("tool.exe")).expect("copy the image child");
        std::fs::copy(image, d.join("sub").join("tool.exe")).expect("copy the image child into sub");
        let vd = verbatim_of(&d);
        let set = set_cwd(&vd);
        println!("set={}", outcome(&set));
        if set.is_err() {
            return;
        }
        let render = Render(vec![
            (vd.to_str().unwrap().to_owned(), "<vd>"),
            (d.to_str().unwrap().to_owned(), "<d>"),
        ]);
        for (key, name) in [("gfpn_tool", "tool.exe."), ("gfpn_sub", "sub.")] {
            // `std::path::absolute` is `GetFullPathNameW` for a relative name.
            let full = std::path::absolute(name).expect("GetFullPathNameW");
            println!("{key}={}", render.apply(full.to_str().unwrap()));
        }
        println!("win32_tool={}", win32_tool(&d, &render));
        let mut raw_tool = cosca::Command::new();
        raw_tool.raw_executable("tool.exe.").commandline("tool");
        println!("raw_tool={}", spawned(cosca_output(&mut raw_tool), "image=", &render));
        for (key, raw) in [("raw_nested", true), ("exe_nested", false)] {
            let mut nested = cosca::Command::new();
            if raw {
                nested.raw_executable(r"sub.\tool.exe");
            } else {
                nested.executable(r"sub.\tool.exe");
            }
            nested.commandline("tool");
            println!("{key}={}", spawned(cosca_output(&mut nested), "image=", &render));
        }
        let mut raw_sub = cosca::Command::new();
        raw_sub.executable(image).commandline("x").current_dir("sub.");
        println!("raw_sub={}", spawned(cosca_output(&mut raw_sub), "cwd=", &render));
        let std_sub = std_output(std::process::Command::new(image).current_dir("sub."));
        println!("std_sub={}", spawned(std_sub, "cwd=", &render));
        let depth = d.components().count() - 2;
        crate::completion::past_the_root(depth, &render);
        crate::completion::rooted_cwd(image, &render);
    }

    /// `CreateProcessW` given `tool.exe.` as a relative `lpApplicationName`, as main's raw backend
    /// passed a relative `raw_executable()`: the file Win32 itself loads.
    fn win32_tool(d: &Path, render: &Render) -> String {
        use std::os::windows::ffi::OsStrExt;
        use windows::core::{PCWSTR, PWSTR};
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{
            CreateProcessW, WaitForSingleObject, INFINITE, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION,
            STARTF_USESTDHANDLES, STARTUPINFOW,
        };
        let report = d.join("win32-report.txt");
        let wide = |s: &OsStr| s.encode_wide().chain([0]).collect::<Vec<u16>>();
        let app = wide(OsStr::new("tool.exe."));
        let mut line = wide(&{
            let mut l = OsString::from("tool --report-to \"");
            l.push(&report);
            l.push("\"");
            l
        });
        // Null std handles: the child writes its report to `report`, and would otherwise print it
        // into this probe's own stdout too.
        let si = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            dwFlags: STARTF_USESTDHANDLES,
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();
        // SAFETY: `app` and `line` are NUL-terminated and outlive the call; `line` is mutable, as
        // `CreateProcessW` requires; `si` and `pi` are valid for the call.
        let created = unsafe {
            CreateProcessW(
                PCWSTR(app.as_ptr()),
                Some(PWSTR(line.as_mut_ptr())),
                None,
                None,
                false,
                PROCESS_CREATION_FLAGS(0),
                None,
                PCWSTR::null(),
                &si,
                &mut pi,
            )
        };
        if let Err(e) = created {
            return format!("err={}", e.code().0 as u32 & 0xFFFF);
        }
        // SAFETY: `pi`'s handles are live and owned here, closed once each after the wait.
        unsafe {
            WaitForSingleObject(pi.hProcess, INFINITE);
            let _ = CloseHandle(pi.hThread);
            let _ = CloseHandle(pi.hProcess);
        }
        let text = std::fs::read_to_string(&report).expect("the child's report");
        match text.lines().find(|l| l.starts_with("image=")) {
            Some(line) => format!("ok,{}", render.apply(line)),
            None => "ok,no image= line".into(),
        }
    }
}
