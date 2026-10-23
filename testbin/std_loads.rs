//! M5, std's column: the `std-loads <t> <image>` and `std-loads-dup <t> <image>` modes.
//!
//! Each row spawns an argv-only command three ways and prints `<row>: std=… cosca=… raw_fd3=…`:
//! `std::process::Command`; an argv-only `cosca::Command`, which `main` sends through std's
//! route; and the same with fd 3 mapped, which `main` sends to the raw backend. A `.contain()` row
//! gives std `main`'s `prepare` stand-in (`env_clear()`, then this process's variables), and fails
//! the probe if std and cosca load different files: the stand-in would then not be `main`'s route.
//!
//! The planted programs are copies of `cosca_testbin_image`, which prints `image=` and `cwd=`.
//! `<t>` is the probe's cwd, and `<t>\p` is first on its `PATH` (set by the test). Directories
//! render as `<t>`, `<unc-t>` (`<t>` through the administrative share), `<sys>` and `<win>`.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use crate::measure::{cosca_run, std_run, Render};

/// One env op, applied in order after any stand-in.
#[derive(Clone)]
enum Op {
    Clear,
    Set(OsString, OsString),
    Remove(OsString),
}

/// An argv-only command, built the same way for each route.
#[derive(Clone)]
struct Row {
    argv: Vec<OsString>,
    ops: Vec<Op>,
    cwd: Option<OsString>,
    contain: bool,
}

impl Row {
    fn new(argv: &[&str]) -> Self {
        Self {
            argv: argv.iter().map(OsString::from).collect(),
            ops: Vec::new(),
            cwd: None,
            contain: false,
        }
    }
    fn set(mut self, k: impl Into<OsString>, v: impl Into<OsString>) -> Self {
        self.ops.push(Op::Set(k.into(), v.into()));
        self
    }
    fn remove(mut self, k: &str) -> Self {
        self.ops.push(Op::Remove(k.into()));
        self
    }
    fn clear(mut self) -> Self {
        self.ops.push(Op::Clear);
        self
    }
    fn cwd(mut self, dir: impl Into<OsString>) -> Self {
        self.cwd = Some(dir.into());
        self
    }
    fn contained(mut self) -> Self {
        self.contain = true;
        self
    }

    fn std_command(&self) -> std::process::Command {
        let mut cmd = std::process::Command::new(&self.argv[0]);
        cmd.args(&self.argv[1..]);
        if self.contain {
            cmd.env_clear().envs(std::env::vars_os());
        }
        for op in &self.ops {
            match op {
                Op::Clear => cmd.env_clear(),
                Op::Set(k, v) => cmd.env(k, v),
                Op::Remove(k) => cmd.env_remove(k),
            };
        }
        if let Some(dir) = &self.cwd {
            cmd.current_dir(dir);
        }
        cmd
    }

    fn cosca_command(&self) -> cosca::Command {
        let mut cmd = cosca::Command::new();
        cmd.args(&self.argv);
        for op in &self.ops {
            match op {
                Op::Clear => cmd.env_clear(),
                Op::Set(k, v) => cmd.env(k, v),
                Op::Remove(k) => cmd.env_remove(k),
            };
        }
        if let Some(dir) = &self.cwd {
            cmd.current_dir(dir);
        }
        if self.contain {
            cmd.contain();
        }
        cmd
    }
}

const KEYS: &[&str] = &["image", "cwd"];

/// Runs `row` on each route and prints its line.
fn measure(name: &str, row: &Row, render: &Render) {
    let std_col = std_run(&mut row.std_command(), KEYS, render);
    let cosca_col = cosca_run(&mut row.cosca_command(), KEYS, render);
    let mut raw = row.cosca_command();
    raw.fd(3, cosca::Stdio::null()).expect("map fd 3");
    let raw_col = cosca_run(&mut raw, KEYS, render);
    println!("{name}: std={std_col} cosca={cosca_col} raw_fd3={raw_col}");
    if row.contain {
        assert_eq!(
            std_col, cosca_col,
            "{name}: std under prepare's stand-in loaded another file than cosca's contained route"
        );
    }
}

/// A row with no std counterpart (cosca's own checks): cosca's two routes only.
fn measure_cosca(name: &str, build: impl Fn() -> cosca::Command, render: &Render) {
    let cosca_col = cosca_run(&mut build(), KEYS, render);
    let mut raw = build();
    let raw_col = match raw.fd(3, cosca::Stdio::null()) {
        Ok(_) => cosca_run(&mut raw, KEYS, render),
        Err(e) => crate::measure::cosca_error(&e),
    };
    println!("{name}: std=n/a cosca={cosca_col} raw_fd3={raw_col}");
}

fn plant(image: &str, to: &Path) {
    std::fs::create_dir_all(to.parent().expect("a parent")).expect("create the directory");
    std::fs::copy(image, to).unwrap_or_else(|e| panic!("plant {to:?}: {e}"));
}

fn renderer(t: &Path) -> Render {
    let unc = unc_of(t);
    let dir = |f: unsafe fn(Option<&mut [u16]>) -> u32| {
        let mut buf = vec![0u16; 1024];
        // SAFETY: `buf` is a live buffer of its length.
        let n = unsafe { f(Some(&mut buf)) } as usize;
        String::from_utf16_lossy(&buf[..n])
    };
    let sys = dir(windows::Win32::System::SystemInformation::GetSystemDirectoryW);
    let win = dir(windows::Win32::System::SystemInformation::GetWindowsDirectoryW);
    Render(vec![
        (unc, "<unc-t>".to_owned()),
        (t.display().to_string(), "<t>".to_owned()),
        (sys, "<sys>".to_owned()),
        (win, "<win>".to_owned()),
    ])
}

/// `t` through its drive's administrative share, `\\localhost\X$\…`.
fn unc_of(t: &Path) -> String {
    let s = t.display().to_string();
    format!(r"\\localhost\{}${}", &s[..1], &s[2..])
}

/// `std-loads <t> <image>`: every row but class 8's.
pub fn run(t: &str, image: &str) {
    let t = PathBuf::from(t);
    let ts = t.display().to_string();
    let render = renderer(&t);
    for (to, from) in [
        (r"p\probe.exe", image),
        (r"p\find.exe", image),
        (r"d5\pro.be", image),
        (r"d5b\pb.x.exe", image),
        (r"bin\tool.exe", image),
        (r"bin\py3.11.exe", image),
        (r"bin\tc.com", image),
        (r"bin\tc.com.exe", image),
        (r"rel\r6.exe", image),
        (r"sub3\t3.exe", image),
        (r"t7\..exe", image),
        ("probe1.exe", image),
        ("lit1", image),
        (r"d9b\p9.exe", image),
        (r"sys\whoami.exe", image),
        (r"app\pa.exe", image),
        (r"u10\u10tool.exe", image),
        (r"short\l11.exe", image),
    ] {
        plant(from, &t.join(to));
    }
    std::fs::write(t.join(r"bin\tool"), b"not a PE image").expect("plant the non-PE tool");
    for dir in ["s", "other", "sub12", r"d9a\p9.exe", "x", "y", "a"] {
        std::fs::create_dir_all(t.join(dir)).expect("create a directory");
    }
    // `1:tool`: std searches `<dir>\1:tool.exe`, the stream `tool.exe` of a file `1`.
    std::fs::create_dir_all(t.join("d1n")).expect("create d1n");
    std::fs::write(t.join(r"d1n\1"), b"").expect("create d1n\\1");
    let stream = std::fs::copy(image, t.join(r"d1n\1:tool.exe"));
    println!(
        "plant_stream={}",
        stream.map_or_else(|e| crate::measure::io_error(&e), |_| "ok".into())
    );

    // Class 11: a candidate of exactly 300 units, before a short one.
    let long = crate::measure::dir_of_len(&t.join("L"), 300 - 1 - "l11.exe".len());
    plant(image, &long.join("l11.exe"));
    let candidate = long.join("l11.exe");
    assert_eq!(
        candidate.as_os_str().encode_wide_len(),
        300,
        "precondition: the long candidate is 300 units"
    );
    // Class 10 reaches `<t>` through the administrative share.
    let unc = unc_of(&t);
    assert!(
        Path::new(&format!(r"{unc}\u10\u10tool.exe")).is_file(),
        "precondition: {unc} is served and this token may open it"
    );
    let drive = &ts[..2];
    let s = t.join("s");
    let doubled = format!(r"\\localhost\\{}", &unc[r"\\localhost\".len()..]);

    let rows: Vec<(&str, Row)> = vec![
        // §3: the bare-name search, and D5 class 4.
        ("c4_env_clear", Row::new(&["probe"]).clear()),
        ("c4_path_empty_dir", Row::new(&["probe"]).set("PATH", &s)),
        ("c4_path_removed", Row::new(&["probe"]).remove("PATH")),
        (
            "c4_whoami_on_child_path",
            Row::new(&["whoami"]).set("PATH", t.join("sys")),
        ),
        ("c4_find_no_ops", Row::new(&["find"])),
        ("c4_find_contained", Row::new(&["find"]).contained()),
        ("app_dir", Row::new(&["pa"]).set("PATH", &s)),
        // Class 5.
        ("c5_literal_only", Row::new(&["pro.be"]).set("PATH", t.join("d5"))),
        ("c5_exe_only", Row::new(&["pb.x"]).set("PATH", t.join("d5b"))),
        // Class 2.
        ("c2_non_pe_beside_exe", Row::new(&[&format!(r"{ts}\bin\tool")])),
        ("c2_dotted_exe_only", Row::new(&[&format!(r"{ts}\bin\py3.11")])),
        ("c2_com_beside_com_exe", Row::new(&[&format!(r"{ts}\bin\tc.com")])),
        ("c2_relative_non_pe", Row::new(&[r"bin\tool"])),
        // Class 3.
        (
            "c3_relative_with_current_dir",
            Row::new(&[r"sub3\t3.exe"]).cwd(t.join("other")),
        ),
        // Class 6.
        ("c6_relative_entry", Row::new(&["r6"]).set("PATH", "rel")),
        (
            "c6_rooted_entry",
            Row::new(&["r6"]).set("PATH", format!(r"{}\rel", &ts[2..])),
        ),
        (
            "c6_drive_relative_entry",
            Row::new(&["r6"]).set("PATH", format!("{drive}rel")),
        ),
        // Class 7.
        ("c7_names_no_file", Row::new(&[&format!(r"{ts}\t7\.")])),
        // Class 1.
        (
            "c1_drive_relative_exe",
            Row::new(&[&format!("{drive}probe1")]).set("PATH", &s),
        ),
        (
            "c1_drive_relative_literal_only",
            Row::new(&[&format!("{drive}lit1")]).set("PATH", &s),
        ),
        (
            "c1_drive_relative_other_cwd",
            Row::new(&[&format!("{drive}probe1")])
                .set("PATH", &s)
                .cwd(t.join("other")),
        ),
        ("c1_non_letter_drive", Row::new(&["1:tool"]).set("PATH", t.join("d1n"))),
        // Class 9.
        (
            "c9_directory_before_file",
            Row::new(&["p9"]).set("PATH", format!(r"{ts}\d9a;{ts}\d9b")),
        ),
        // Class 10.
        (
            "c10_doubled_unc_name",
            Row::new(&[&format!(r"{doubled}\u10\u10tool.exe")]),
        ),
        (
            "c10_doubled_unc_entry",
            Row::new(&["u10tool"]).set("PATH", format!(r"{doubled}\u10")),
        ),
        // Class 11.
        (
            "c11_long_candidate_first",
            Row::new(&["l11"]).set("PATH", format!("{};{ts}\\short", long.display())),
        ),
        // Classes 12 and 13, and the other `current_dir` rows of §3.
        ("c12_verbatim_cwd", Row::new(&["probe"]).cwd(format!(r"\\?\{ts}\sub12"))),
        (
            "c13_verbatim_cwd_dotdot",
            Row::new(&["probe"]).cwd(format!(r"\\?\{ts}\x\..\y")),
        ),
        (
            "c13_verbatim_cwd_trailing_dot",
            Row::new(&["probe"]).cwd(format!(r"\\?\{ts}\a.")),
        ),
        (
            "c13_verbatim_cwd_trailing_space",
            Row::new(&["probe"]).cwd(format!(r"\\?\{ts}\a ")),
        ),
        ("cwd_trailing_dot", Row::new(&["probe"]).cwd(format!(r"{ts}\sub12."))),
        ("cwd_trailing_space", Row::new(&["probe"]).cwd(format!(r"{ts}\sub12 "))),
        ("cwd_server_only", Row::new(&["probe"]).cwd(r"\\localhost")),
        ("e1_empty_cwd", Row::new(&["probe"]).cwd("")),
        // §3: a verbatim image.
        ("verbatim_image", Row::new(&[&format!(r"\\?\{ts}\bin\tool.exe")])),
        // §3: an app execution alias, found on the parent's `PATH`.
        ("app_alias_winget", Row::new(&["winget", "--version"])),
        // N7: a NUL in an env value, and no such program.
        ("n7_nul_in_env", Row::new(&["nosuch-q"]).set("K", "a\0b")),
    ];
    for (name, row) in &rows {
        measure(name, row, &render);
    }

    // §3's error precedence, which only cosca's routes have.
    measure_cosca(
        "order_nul_cwd_no_program",
        || {
            let mut c = cosca::Command::new();
            c.current_dir("a\0b");
            c
        },
        &render,
    );
    measure_cosca(
        "order_merge_unmapped_fd",
        || {
            let mut c = cosca::Command::new();
            c.arg("nosuch-q");
            c.stdout(cosca::Stdio::merge(cosca::Fd::from(9))).expect("stdout");
            c
        },
        &render,
    );
    measure_cosca(
        "order_reserved_creation_flag",
        || {
            let mut c = cosca::Command::new();
            c.arg("nosuch-q").creation_flags(0x400);
            c
        },
        &render,
    );
    measure_cosca(
        "order_breakaway_contained",
        || {
            let mut c = cosca::Command::new();
            c.arg("nosuch-q").contain().breakaway_from_job();
            c
        },
        &render,
    );
}

/// `std-loads-dup <t> <image>`: class 8, run in a block holding `Path=<t>\c8a` then
/// `PATH=<t>\c8b`. Also the `Path` entries each route hands the child.
pub fn run_dup(t: &str, image: &str) {
    let t = PathBuf::from(t);
    let render = renderer(&t);
    plant(image, &t.join(r"c8a\tool8.exe"));
    plant(image, &t.join(r"c8b\tool8.exe"));
    plant(image, &t.join(r"c8b\only8.exe"));
    let paths: Vec<OsString> = std::env::vars_os()
        .filter(|(k, _)| k.eq_ignore_ascii_case("path"))
        .map(|(k, v)| [k, v].join(OsStr::new("=")))
        .collect();
    println!("c8_parent_view={paths:?}");
    for (name, row) in [
        ("c8_both_op", Row::new(&["tool8"]).set("K", "1")),
        ("c8_both_contained", Row::new(&["tool8"]).contained()),
        ("c8_second_only_op", Row::new(&["only8"]).set("K", "1")),
        ("c8_second_only_contained", Row::new(&["only8"]).contained()),
    ] {
        measure(name, &row, &render);
    }
    let me = std::env::current_exe().expect("current_exe");
    let me = me.to_str().expect("a UTF-8 path");
    for (name, row) in [
        ("c8_child_env_op", Row::new(&[me, "dump-env-block"]).set("K", "1")),
        ("c8_child_env_contained", Row::new(&[me, "dump-env-block"]).contained()),
    ] {
        let std_col = path_entries(crate::measure::std_stdout(&mut row.std_command()));
        let cosca_col = path_entries(crate::measure::cosca_stdout(&mut row.cosca_command()));
        let mut raw = row.cosca_command();
        raw.fd(3, cosca::Stdio::null()).expect("map fd 3");
        let raw_col = path_entries(crate::measure::cosca_stdout(&mut raw));
        println!(
            "{name}: std={} cosca={} raw_fd3={}",
            render.apply(&std_col),
            render.apply(&cosca_col),
            render.apply(&raw_col)
        );
    }
}

/// The `Path`-named entries of a `dump-env-block` dump, or the error that stopped it.
fn path_entries(dump: Result<Vec<u8>, String>) -> String {
    use std::os::windows::ffi::OsStringExt;
    let dump = match dump {
        Ok(dump) => dump,
        Err(why) => return why,
    };
    let entries: Vec<String> = String::from_utf8_lossy(&dump)
        .lines()
        .map(|hex| {
            let units: Vec<u16> = (0..hex.len())
                .step_by(4)
                .map(|i| u16::from_str_radix(&hex[i..i + 4], 16).expect("hex"))
                .collect();
            OsString::from_wide(&units).to_string_lossy().into_owned()
        })
        .filter(|e| e.get(..5).is_some_and(|name| name.eq_ignore_ascii_case("path=")))
        .collect();
    format!("{entries:?}")
}

/// UTF-16 length of an `OsStr`.
trait EncodeWideLen {
    fn encode_wide_len(&self) -> usize;
}

impl EncodeWideLen for OsStr {
    fn encode_wide_len(&self) -> usize {
        use std::os::windows::ffi::OsStrExt;
        self.encode_wide().count()
    }
}
