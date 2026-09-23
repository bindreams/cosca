//! Canaries: UNC, device and verbatim-marker roots.

use crate::harness::{canary, check_resolutions, literal_rows};
use crate::pure::rooted_prefix;

/// Canary: `..` never pops a UNC path's `\\server\share`, but pops everything after `\\.\`.
///
/// So under a UNC root the share name is the floor: `\\srv\x.bat\y\..\..` is `\\srv\x.bat`, a
/// batch-shaped name. Under `\\.\` the device name is an ordinary component: `\\.\C:\..\..\x.bat`
/// is `\\.\x.bat`. `/` and `\` are interchangeable in the leading pair, so `//srv/…` and `\/srv\…`
/// are UNC paths too. Server and share are positional: a `..`, dots-only, empty or one-space
/// segment in either slot is part of the root, not an operation on it, and neither slot is
/// trimmed. `\\...\x.bat\y\..` is `\\...\x.bat`.
///
/// String-level only: `GetFullPathNameW` contacts no server and opens no device.
#[test]
#[ignore = "platform canary: needs a Windows runner"]
fn dotdot_stops_at_the_unc_share_but_not_at_a_device_name() {
    canary("Windows", |facts, failures| {
        let rows = literal_rows(&[
            (
                r"\\srv\x.bat\..",
                r"\\srv\x.bat",
                "`..` right after the share pops nothing",
            ),
            (r"\\srv\x.bat\y\..\..", r"\\srv\x.bat", "the second `..` pops nothing"),
            (
                r"\\srv\x.bat\y.bat\..",
                r"\\srv\x.bat",
                "`..` pops the component after the share",
            ),
            (
                r"\\srv\x.bat\..\y",
                r"\\srv\x.bat\y",
                "the walk continues from the share",
            ),
            (r"\\srv\x.bat\..\..\y", r"\\srv\x.bat\y", "however many `..`"),
            (
                r"\\srv\x.bat\...",
                r"\\srv\x.bat\",
                "a dots-only final component drops out",
            ),
            (r"\\srv\x.bat.", r"\\srv\x.bat", "the share name loses its trailing dot"),
            (
                r"\\srv\..\x.bat",
                r"\\srv\..\x.bat",
                "`..` in the share slot is the share name",
            ),
            (r"//srv/x.bat/..", r"\\srv\x.bat", "`//` is a UNC root"),
            (r"\/srv\x.cmd\..", r"\\srv\x.cmd", r"`\/` is a UNC root"),
            (r"/\srv\x.bat\..", r"\\srv\x.bat", r"`/\` is a UNC root"),
            (
                r"//srv/x.bat/y/../..",
                r"\\srv\x.bat",
                "slash-spelled, the share is still the floor",
            ),
            (
                r"//srv/x.bat/../y",
                r"\\srv\x.bat\y",
                "slash-spelled, the walk continues from the share",
            ),
            (
                r"\\.\C:\x.bat\..",
                r"\\.\C:",
                "a device path's `..` pops an ordinary component",
            ),
            (r"\\.\C:\..", r"\\.\", "the device name `C:` is popped too"),
            (
                r"\\.\C:\..\..\x.bat",
                r"\\.\x.bat",
                "popped past the device, a batch name is left",
            ),
            (r"\\.\x.bat\..", r"\\.\", "the device name is popped"),
            (r"\\.\x.bat\y\..\..", r"\\.\", r"`\\.\` is the floor"),
            (r"\\.\pipe\x.bat\..", r"\\.\pipe", "`pipe` is an ordinary component"),
            (r"//./C:/x.bat/..", r"\\.\C:", r"`//./` is `\\.\`"),
            (
                r"\\.\C:\dir\x.bat.",
                r"\\.\C:\dir\x.bat",
                "a device path loses a trailing dot",
            ),
            (
                r"\\...\x.bat\y\..",
                r"\\...\x.bat",
                "a dots-only server is part of the root",
            ),
            (
                r"\\...\x.bat\..",
                r"\\...\x.bat",
                "a dots-only server is part of the root",
            ),
            (
                r"\\...\x.bat\..\..\y",
                r"\\...\x.bat\y",
                "a dots-only server is part of the root",
            ),
            (
                r"\\..\x.bat\y\..",
                r"\\..\x.bat",
                "a `..` server is part of the root, not a pop",
            ),
            (
                r"\\..\x.bat\..",
                r"\\..\x.bat",
                "a `..` server is part of the root, not a pop",
            ),
            (r"\\\x.bat\y\..", r"\\\x.bat", "an empty server is part of the root"),
            (r"\\\x.bat\..", r"\\\x.bat", "an empty server is part of the root"),
            (r"\\ \x.bat\y\..", r"\\ \x.bat", "a one-space server is kept as given"),
            (
                r"\\. \x.bat\y\..",
                r"\\. \x.bat",
                "`. ` is a server, not the device marker",
            ),
            (r"\\.. \x.bat\y\..", r"\\.. \x.bat", "a server keeps its trailing space"),
            (r"\\srv.\x.bat\y\..", r"\\srv.\x.bat", "a server keeps its trailing dot"),
            (r"//../x.bat/y/..", r"\\..\x.bat", "slash-spelled, a `..` server"),
            (r"//.../x.bat/y/..", r"\\...\x.bat", "slash-spelled, a dots-only server"),
        ]);
        check_resolutions(&rows, facts, failures);
    });
}

/// Canary: in `GetFullPathNameW`, `\\?\` and every slash spelling of it (`//?/`, `\\?/`, `/\?\`,
/// `\/?\`) resolve alike — separators become `\`, trailing dots drop, `..` pops — while `\??\` is
/// a rooted path on the current drive.
///
/// So `GetFullPathNameW`'s answer never says whether a string is verbatim: that is decided by the
/// literal prefix, and only std's `is_verbatim` (`\\?\` or `\??\`, exactly) and the file APIs read
/// it. `dots_and_spaces::a_trailing_dot_or_space_reaches_the_batch_file_only_when_plain` shows
/// which file each spelling opens.
#[test]
#[ignore = "platform canary: needs a Windows runner"]
fn verbatim_marker_spellings_resolve_alike() {
    canary("Windows", |facts, failures| {
        let mut rows = literal_rows(&[
            (r"\\?\C:\dir\x.bat.", r"\\?\C:\dir\x.bat", "the verbatim marker"),
            (r"//?/C:/dir/x.bat.", r"\\?\C:\dir\x.bat", "slash-spelled"),
            (
                r"//?/C:/dir/...",
                r"\\?\C:\dir\",
                "slash-spelled, a dots-only name drops out",
            ),
            (
                r"//?/C:/dir/x.bat/y/..",
                r"\\?\C:\dir\x.bat",
                "slash-spelled, `..` pops",
            ),
            (r"\\?/C:\dir\x.bat.", r"\\?\C:\dir\x.bat", "slash after `?`"),
            (r"/\?\C:\dir\x.bat.", r"\\?\C:\dir\x.bat", "slash first"),
            (r"\/?\C:\dir\x.bat.", r"\\?\C:\dir\x.bat", "slash second"),
            (r"\\?\C:/dir/x.bat.", r"\\?\C:\dir\x.bat", "slashes after the marker"),
        ]);
        match std::env::current_dir() {
            Ok(cwd) => {
                let cwd = cwd.to_str().expect("cwd is not UTF-8").to_string();
                println!("current directory: {cwd:?}");
                match rooted_prefix(&cwd) {
                    Some(root) => rows.push((
                        r"\??\C:\dir\x.bat.".to_string(),
                        format!(r"{root}\??\C:\dir\x.bat"),
                        r"`\??\` is rooted on the current drive or share",
                    )),
                    None => failures.push(format!("the current directory {cwd:?} has no root")),
                }
            }
            Err(e) => failures.push(format!("could not read the current directory: {e}")),
        }
        check_resolutions(&rows, facts, failures);
    });
}
