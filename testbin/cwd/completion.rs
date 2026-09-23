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
    let mut buf = vec![0u16; 32 * 1024];
    // SAFETY: `wide` is NUL-terminated; `buf` is a live buffer the call writes at most its length of.
    let n = unsafe { GetFullPathNameW(PCWSTR(wide.as_ptr()), Some(&mut buf), None) };
    if n == 0 || n as usize > buf.len() {
        return format!("err={}", std::io::Error::last_os_error().raw_os_error().unwrap_or(-1));
    }
    String::from_utf16_lossy(&buf[..n as usize])
}

/// A drive letter mapped to a directory with `DefineDosDeviceW` for as long as it lives.
struct Subst {
    drive: String,
    target: Vec<u16>,
}

impl Subst {
    fn new(drive: &str, target: &Path) -> Result<Self, String> {
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
        .map_err(|e| format!("{e}"))?;
        Ok(Self {
            drive: drive.to_owned(),
            target,
        })
    }
}

impl Drop for Subst {
    fn drop(&mut self) {
        use std::os::windows::ffi::OsStrExt;
        use windows::core::PCWSTR;
        use windows::Win32::Storage::FileSystem::{DefineDosDeviceW, DDD_EXACT_MATCH_ON_REMOVE, DDD_REMOVE_DEFINITION};
        let name: Vec<u16> = OsStr::new(&self.drive).encode_wide().chain([0]).collect();
        // SAFETY: both strings are NUL-terminated and outlive the call.
        let removed = unsafe {
            DefineDosDeviceW(
                DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE,
                PCWSTR(name.as_ptr()),
                PCWSTR(self.target.as_ptr()),
            )
        };
        removed.expect("remove the drive mapping");
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

/// `drive-dir <base> <image-child>`: maps a free drive letter `X:` to `<d>`, holding `sub` and
/// `exists\sub`, and runs from `<d>` on another drive. For each value of `=X:` it reports what
/// `GetFullPathNameW` makes of `X:sub`, and where cosca's raw backend and std run a child given
/// `current_dir("X:sub")`.
pub fn drive_dir(base: &str, image: &str) {
    use windows::Win32::Storage::FileSystem::GetLogicalDrives;
    let d = canonical(base);
    for sub in ["sub", r"exists\sub"] {
        std::fs::create_dir_all(d.join(sub)).expect("create the drive's directories");
    }
    // SAFETY: no arguments; reads the mounted drives.
    let mask = unsafe { GetLogicalDrives() };
    let letter = (b'M'..=b'Z')
        .rev()
        .find(|l| mask & (1 << (l - b'A')) == 0)
        .expect("a free drive letter");
    let drive = format!("{}:", letter as char);
    let _subst = match Subst::new(&drive, &d) {
        Ok(s) => s,
        Err(e) => return println!("subst=err {e}"),
    };
    println!("cwd_set={}", outcome(&set_cwd(d.as_os_str())));
    let render = Render(vec![(drive.clone(), "X:"), (d.to_str().unwrap().to_owned(), "<d>")]);
    let other = format!(r"{}\exists", d.display());
    for (label, value) in [
        ("unset", None),
        ("exists", Some(format!(r"{drive}\exists"))),
        ("gone", Some(format!(r"{drive}\gone"))),
        ("drive_rel", Some(format!("{drive}exists"))),
        ("relative", Some("exists".to_owned())),
        ("rooted", Some(r"\exists".to_owned())),
        ("other_drive", Some(other.clone())),
    ] {
        if let Err(e) = set_drive_dir(&drive, value.as_deref()) {
            println!("{label}=setenv err {e}");
            continue;
        }
        let name = format!("{drive}sub");
        println!("gfpn_{label}={}", render.apply(&gfpn(OsStr::new(&name))));
        let mut raw = cosca::Command::new();
        raw.executable(image).commandline("x").current_dir(&name);
        println!("cosca_{label}={}", spawned(cosca_output(&mut raw), "cwd=", &render));
        let std_run = std_output(std::process::Command::new(image).current_dir(&name));
        println!("std_{label}={}", spawned(std_run, "cwd=", &render));
    }
}

/// `verbatim-unc <base> <image-child>`: reaches `<d>` through the `\\localhost\<drive>$` share.
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
    let render = Render(vec![
        (vd.clone(), "<vd>"),
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
