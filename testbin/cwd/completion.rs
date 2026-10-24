//! The probe modes that measure how Win32 completes a name against state other than a plain cwd:
//! a drive's own directory (`=X:`) and a verbatim UNC cwd.

use std::ffi::OsStr;
use std::path::Path;

use crate::probe::{canonical, cosca_output, outcome, set_cwd, spawned, std_output, verbatim_of, Render};

/// `GetFullPathNameW` on `path`, reading this process's cwd and environment.
fn gfpn(path: &OsStr) -> String {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::GetFullPathNameW;
    let wide: Vec<u16> = path.encode_wide().chain([0]).collect();
    // SAFETY: `wide` is NUL-terminated; `buf` is a live buffer the call writes at most its length of.
    crate::measure::wide_string(|buf| unsafe { GetFullPathNameW(PCWSTR(wide.as_ptr()), Some(buf), None) })
        .unwrap_or_else(|code| format!("err={code}"))
}

/// A drive letter mapped to a directory with `DefineDosDeviceW` for as long as it lives. A second
/// one for the same letter shadows the first until it is dropped.
pub(crate) struct Subst {
    drive: String,
    target: Vec<u16>,
    removed: bool,
}

/// Why a letter could not be mapped.
pub(crate) enum MapError {
    /// The letter already had other definitions, which the new one shadowed. It is removed again.
    Shadowed(Vec<String>),
    Failed(String),
}

impl std::fmt::Display for MapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Shadowed(all) => write!(f, "the letter had other definitions: {all:?}"),
            Self::Failed(why) => f.write_str(why),
        }
    }
}

const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_INSUFFICIENT_BUFFER: i32 = 122;

/// Every definition of `drive` (`X:`), newest first, or the OS error code: `ERROR_FILE_NOT_FOUND`
/// when it has none.
fn definitions(drive: &str) -> Result<Vec<String>, i32> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
    let name: Vec<u16> = OsStr::new(drive).encode_wide().chain([0]).collect();
    let mut buf = vec![0u16; 1024];
    loop {
        // SAFETY: `name` is NUL-terminated; `buf` is a live buffer the call writes at most its length of.
        let n = unsafe { QueryDosDeviceW(PCWSTR(name.as_ptr()), Some(&mut buf)) } as usize;
        if n != 0 {
            return Ok(buf[..n]
                .split(|&u| u == 0)
                .filter(|s| !s.is_empty())
                .map(String::from_utf16_lossy)
                .collect());
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(ERROR_INSUFFICIENT_BUFFER) => buf.resize(buf.len() * 2, 0),
            other => return Err(other.unwrap_or(-1)),
        }
    }
}

/// Panics unless `drive` has no definition at all.
pub(crate) fn assert_undefined(drive: &str) {
    match definitions(drive) {
        Err(ERROR_FILE_NOT_FOUND) => {}
        other => panic!("{drive} should have no definition left: {other:?}"),
    }
}

impl Subst {
    /// Maps the highest letter from `Z:` down to `M:` that nothing else defines to `target`: it
    /// defines first, then looks, and gives up a letter whose definitions are not just ours.
    pub(crate) fn map_free(target: &Path) -> Result<Self, String> {
        for letter in (b'M'..=b'Z').rev() {
            match Self::new(&format!("{}:", letter as char), target, 0) {
                Ok(subst) => return Ok(subst),
                Err(MapError::Shadowed(_)) => continue,
                Err(MapError::Failed(why)) => return Err(why),
            }
        }
        Err("every letter from M: to Z: is already defined".to_owned())
    }

    /// Maps `drive` to `target` over the `below` definitions it must already have. Any other
    /// count shows someone else's mapping, so the new one is removed again by exact match.
    pub(crate) fn new(drive: &str, target: &Path, below: usize) -> Result<Self, MapError> {
        use std::os::windows::ffi::OsStrExt;
        use windows::core::PCWSTR;
        use windows::Win32::Storage::FileSystem::{DefineDosDeviceW, DEFINE_DOS_DEVICE_FLAGS};
        let name: Vec<u16> = OsStr::new(drive).encode_wide().chain([0]).collect();
        let target: Vec<u16> = target.as_os_str().encode_wide().chain([0]).collect();
        // SAFETY: both strings are NUL-terminated and outlive the call.
        unsafe {
            DefineDosDeviceW(
                DEFINE_DOS_DEVICE_FLAGS(0),
                PCWSTR(name.as_ptr()),
                PCWSTR(target.as_ptr()),
            )
        }
        .map_err(|e| MapError::Failed(format!("{e}")))?;
        let subst = Self {
            drive: drive.to_owned(),
            target,
            removed: false,
        };
        // On an error `subst` drops here and removes the mapping.
        let all = definitions(drive).map_err(|code| MapError::Failed(format!("QueryDosDeviceW err={code}")))?;
        if all.len() == below + 1 {
            return Ok(subst);
        }
        subst
            .remove()
            .map_err(|e| MapError::Failed(format!("could not remove the shadowing mapping of {drive}: {e}")))?;
        Err(MapError::Shadowed(all))
    }

    pub(crate) fn drive(&self) -> &str {
        &self.drive
    }

    /// Removes the mapping and reports a failure. The drop guard covers an early exit; a test that
    /// must know the mapping is gone calls this instead.
    pub(crate) fn remove(mut self) -> Result<(), String> {
        self.removed = true;
        self.undefine()
    }

    fn undefine(&self) -> Result<(), String> {
        use std::os::windows::ffi::OsStrExt;
        use windows::core::PCWSTR;
        use windows::Win32::Storage::FileSystem::{DefineDosDeviceW, DDD_EXACT_MATCH_ON_REMOVE, DDD_REMOVE_DEFINITION};
        let name: Vec<u16> = OsStr::new(&self.drive).encode_wide().chain([0]).collect();
        // SAFETY: both strings are NUL-terminated and outlive the call.
        unsafe {
            DefineDosDeviceW(
                DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE,
                PCWSTR(name.as_ptr()),
                PCWSTR(self.target.as_ptr()),
            )
        }
        .map_err(|e| format!("{e}"))
    }
}

impl Drop for Subst {
    fn drop(&mut self) {
        if self.removed {
            return;
        }
        // Never a panic: this runs while unwinding too, and a second panic would abort before the
        // report reaches the test.
        if let Err(e) = self.undefine() {
            eprintln!("could not remove the {} mapping: {e}", self.drive);
        }
    }
}

/// Sets `=<drive>` in this process's environment, or removes it for `None`.
fn set_drive_dir(drive: &str, value: Option<&str>) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::System::Environment::SetEnvironmentVariableW;
    let name: Vec<u16> = OsStr::new(&format!("={drive}")).encode_wide().chain([0]).collect();
    let value: Option<Vec<u16>> = value.map(|v| OsStr::new(v).encode_wide().chain([0]).collect());
    let value = value.as_ref().map_or(PCWSTR::null(), |v| PCWSTR(v.as_ptr()));
    // SAFETY: `name` and `value` are NUL-terminated and outlive the call.
    unsafe { SetEnvironmentVariableW(PCWSTR(name.as_ptr()), value) }.map_err(|e| format!("{e}"))
}

/// `=<drive>`'s value in this process's environment, or `unset`.
fn drive_dir_value(drive: &str) -> String {
    std::env::vars_os()
        .find(|(k, _)| k.to_string_lossy().eq_ignore_ascii_case(&format!("={drive}")))
        .map_or_else(|| "unset".to_owned(), |(_, v)| v.to_string_lossy().into_owned())
}

/// `drive-dir <base> <image-child>`: maps a free drive letter `X:` to `<d>` for the logon session
/// (system-affecting, so its test runs on CI only), holding `sub`,
/// `exists\sub` and the file `afile`, and runs from `<d>` on another drive. For each value of
/// `=X:`, set afresh before each route, it reports where cosca's raw backend runs a child given
/// `current_dir("X:sub")`, what `GetFullPathNameW` makes of `X:sub` and the value it leaves in
/// `=X:`, and where std runs the child.
pub fn drive_dir(base: &str, image: &str) {
    let d = canonical(base);
    for sub in ["sub", r"exists\sub"] {
        std::fs::create_dir_all(d.join(sub)).expect("create the drive's directories");
    }
    std::fs::write(d.join("afile"), b"x").expect("create <d>\\afile");
    let _subst = match Subst::map_free(&d) {
        Ok(s) => s,
        Err(e) => return println!("subst=err {e}"),
    };
    let drive = _subst.drive().to_owned();
    println!("cwd_set={}", outcome(&set_cwd(d.as_os_str())));
    let render = Render(vec![(drive.clone(), "X:"), (d.to_str().unwrap().to_owned(), "<d>")]);
    let other = format!(r"{}\exists", d.display());
    for (label, value) in [
        ("unset", None),
        ("exists", Some(format!(r"{drive}\exists"))),
        ("gone", Some(format!(r"{drive}\gone"))),
        ("file", Some(format!(r"{drive}\afile"))),
        ("drive_rel", Some(format!("{drive}exists"))),
        ("relative", Some("exists".to_owned())),
        ("rooted", Some(r"\exists".to_owned())),
        ("other_drive", Some(other.clone())),
    ] {
        let set = || set_drive_dir(&drive, value.as_deref()).expect("set =X:");
        let name = format!("{drive}sub");
        set();
        let mut raw = cosca::Command::new();
        raw.executable(image).commandline("x").current_dir(&name);
        println!("cosca_{label}={}", spawned(cosca_output(&mut raw), "cwd=", &render));
        set();
        println!("gfpn_{label}={}", render.apply(&gfpn(OsStr::new(&name))));
        println!("after_{label}={}", render.apply(&drive_dir_value(&drive)));
        set();
        let std_run = std_output(std::process::Command::new(image).current_dir(&name));
        println!("std_{label}={}", spawned(std_run, "cwd=", &render));
    }
}

/// Where cosca and std run a child given the rooted `current_dir(r"\x")` from this process's cwd.
pub fn rooted_cwd(image: &str, render: &Render) {
    let mut raw = cosca::Command::new();
    raw.executable(image).commandline("x").current_dir(r"\x");
    println!("cosca_rooted_cwd={}", spawned(cosca_output(&mut raw), "cwd=", render));
    let std_run = std_output(std::process::Command::new(image).current_dir(r"\x"));
    println!("std_rooted_cwd={}", spawned(std_run, "cwd=", render));
}

/// `GetFullPathNameW` of a rooted name and of a `..` run one past the root, on this process's cwd,
/// `depth` components below its root.
pub fn past_the_root(depth: usize, render: &Render) {
    println!("gfpn_rooted={}", render.apply(&gfpn(OsStr::new(r"\t.exe"))));
    let up = format!(r"{}t.exe", r"..\".repeat(depth + 1));
    println!("gfpn_up_past_root={}", render.apply(&gfpn(OsStr::new(&up))));
}

/// `verbatim-unc <base> <image-child>`: reaches `<d>` through the `\\localhost\<drive>$` share,
/// so it needs that administrative share served and an administrator's elevated token to open it.
/// First, from a plain cwd, where cosca and std run a child given that directory as
/// `current_dir`, plainly and verbatim. Then it enters the verbatim spelling itself and reports what
/// `GetFullPathNameW` makes of a rooted name, of `..` runs reaching and passing the share, and of a
/// written verbatim `..`.
pub fn verbatim_unc(base: &str, image: &str) {
    let d = canonical(base).join("u");
    std::fs::create_dir_all(&d).expect("create <d>");
    let text = d.to_str().unwrap();
    let (drive, rest) = text.split_at(2);
    let letter = &drive[..1];
    let share = format!(r"\\localhost\{letter}$");
    let vshare = format!(r"\\?\UNC\localhost\{letter}$");
    let unc = format!("{share}{rest}");
    let vd = verbatim_of(Path::new(&format!(r"UNC\localhost\{letter}${rest}")));
    let vd = vd.to_str().unwrap().to_owned();
    let vparent = vd[..vd.rfind('\\').unwrap()].to_owned();
    let render = Render(vec![
        (vd.clone(), "<vd>"),
        (vparent, "<vparent>"),
        (unc.clone(), "<unc>"),
        (vshare.clone(), "<vshare>"),
        (share.clone(), "<share>"),
        (text.to_owned(), "<d>"),
    ]);
    for (key, dir) in [("unc", &unc), ("vunc", &vd)] {
        let mut raw = cosca::Command::new();
        raw.executable(image).commandline("x").current_dir(dir);
        println!("cosca_{key}_cwd={}", spawned(cosca_output(&mut raw), "cwd=", &render));
        let std_run = std_output(std::process::Command::new(image).current_dir(dir));
        println!("std_{key}_cwd={}", spawned(std_run, "cwd=", &render));
    }
    let set = set_cwd(OsStr::new(&vd));
    println!("set={}", outcome(&set));
    if set.is_err() {
        return;
    }
    let depth = rest.split('\\').filter(|c| !c.is_empty()).count();
    let up = |n: usize| format!(r"{}t.exe", r"..\".repeat(n));
    rooted_cwd(image, &render);
    for (key, name) in [
        ("rooted", r"\t.exe".to_owned()),
        ("up_depth", up(depth)),
        ("up_depth_1", up(depth + 1)),
        ("up_depth_2", up(depth + 2)),
        ("written_up", format!(r"{vd}\..\t.exe")),
        ("written_past_share", format!(r"{vd}\{}", up(depth + 1))),
    ] {
        println!("gfpn_{key}={}", render.apply(&gfpn(OsStr::new(&name))));
    }
}
