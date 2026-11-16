//! M7: the `=X:` rows that need no mapped drive. `tests/common/drive_rule.rs` has the runner and
//! D1's arms; `windows_process_cwd.rs` has the rows that need a mapped drive: an `=X:` value naming
//! a directory on drive X itself, and a partially qualified value whose target must exist.

use crate::common::drive_rule::{canonical, free_drive, run, Arm, Cwd, Render, Row, Var};
use crate::provenance::survey_platform;
use crate::test_groups::{path_probes, Group};

/// M7's rows that need no mapped drive: an unmapped drive letter (printed `<X>:`) whose `=X:` value,
/// where it names a directory, names one on the temp directory's drive T (printed `<T>:`). Then the
/// rows where E is on T, verbatim or UNC. The rows whose value must exist relative to the child's cwd
/// are in `windows_process_cwd`'s mapped test. The letter is searched in `G..=L`, disjoint from the
/// mapped tests' `M..=Z`.
///
/// Asserted: the child runs in the row's cwd and sees the row's `=X:` value (for a `Recorded` row,
/// one the block holds), and its answer is the row's. The UNC rows, last, need `\\localhost\<T>$`
/// served and openable, as CI runners serve it.
#[skuld::test]
fn m7_a_drive_relative_name_against_a_childs_block_without_a_mapped_drive(#[fixture(path_probes)] _group: &Group) {
    survey_platform();
    let tmp = tempfile::tempdir().expect("tempdir");
    let d = canonical(tmp.path());
    for sub in ["e", "exists", "exists2"] {
        std::fs::create_dir(format!(r"{d}\{sub}")).expect("create the row directories");
    }
    for sub in [r"e\sub", r"exists\sub"] {
        std::fs::create_dir(format!(r"{d}\{sub}")).expect("create the row directories");
    }
    let e = format!(r"{d}\e");
    let exists = format!(r"{d}\exists");
    let exists2 = format!(r"{d}\exists2");
    let t = &d[..2];
    let letter = free_drive(b'G'..=b'L');
    let q = format!("{letter}:");
    let lq = q.to_ascii_lowercase();
    let lt = t.to_ascii_lowercase();
    let sr = format!("SystemRoot={}", std::env::var("SystemRoot").expect("SystemRoot"));
    let unc = format!(r"\\localhost\{}${}", &t[..1], &d[2..]);
    // The system drive's `PROGRA~1`, which Win32 serves under its short name (8.3 names enabled).
    let short = format!(r"{}\PROGRA~1", std::env::var("SystemDrive").expect("SystemDrive"));
    assert!(
        std::path::Path::new(&short).is_dir(),
        "precondition: {short} is a directory"
    );
    let render = Render(vec![(unc.clone(), "<unc>".into()), (d.clone(), "<d>".into())]);
    let drives = [(letter, 'X'), (t.chars().next().expect("a drive"), 'T')];

    let given = || Cwd::Given(e.clone());
    let block = |entries: &[String]| [vec![sr.clone()], entries.to_vec()].concat();
    let set = |v: &str| Var::Is(Some(v.to_owned()));
    let rows = vec![
        // Replays the drive rule's value cases through a child's block. The partially qualified
        // values whose target is on a mapped drive are in `windows_process_cwd`.
        Row {
            key: "unset",
            cwd: given(),
            block: block(&[]),
            name: format!("{q}tool"),
            arm: Arm::Root,
            var: Var::Is(None),
        },
        Row {
            key: "other_drive",
            cwd: given(),
            block: block(&[format!("={q}={exists}")]),
            name: format!("{q}tool"),
            arm: Arm::Value(exists.clone()),
            var: set(&exists),
        },
        Row {
            key: "empty",
            cwd: given(),
            block: block(&[format!("={q}=")]),
            name: format!("{q}tool"),
            arm: Arm::Root,
            var: set(""),
        },
        // Spelled as Win32 leaves it alone, so used: another case, a short name.
        Row {
            key: "lowercase_value",
            cwd: given(),
            block: block(&[format!("={q}={}", exists.to_ascii_lowercase())]),
            name: format!("{q}tool"),
            arm: Arm::Value(exists.to_ascii_lowercase()),
            var: set(&exists.to_ascii_lowercase()),
        },
        Row {
            key: "short_name",
            cwd: given(),
            block: block(&[format!("={q}={short}")]),
            name: format!("{q}tool"),
            arm: Arm::Value(short.clone()),
            var: set(&short),
        },
        // GetFullPathNameW keeps the value's separator and the name's own, but opening the name
        // fails; cosca completes onto `exists` and starts the file there: a stated limit.
        Row {
            key: "trailing_separator",
            cwd: given(),
            block: block(&[format!(r"={q}={exists}\")]),
            name: format!("{q}tool"),
            arm: Arm::Answer(format!(r"{exists}\\tool")),
            var: set(&format!(r"{exists}\")),
        },
        // A drive's root, which Windows' own tools write: used, with no doubled separator.
        Row {
            key: "drive_root",
            cwd: given(),
            block: block(&[format!(r"={q}={t}\")]),
            name: format!("{q}tool"),
            arm: Arm::Value(format!(r"{t}\")),
            var: set(&format!(r"{t}\")),
        },
        // A bare drive: Win32 uses it as written (`T:tool`, which opens no file). cosca completes
        // such a name onto the drive's root: a stated limit.
        Row {
            key: "bare_drive",
            cwd: given(),
            block: block(&[format!("={q}={t}")]),
            name: format!("{q}tool"),
            arm: Arm::Answer(format!("{t}tool")),
            var: set(t),
        },
        // Case and drive units.
        Row {
            key: "lowercase_program",
            cwd: given(),
            block: block(&[format!("={q}={exists}")]),
            name: format!("{lq}tool"),
            arm: Arm::Value(exists.clone()),
            var: set(&exists),
        },
        Row {
            key: "lowercase_key",
            cwd: given(),
            block: block(&[format!("={lq}={exists}")]),
            name: format!("{q}tool"),
            arm: Arm::Value(exists.clone()),
            var: Var::Recorded,
        },
        Row {
            key: "digit_drive",
            cwd: given(),
            block: block(&[format!("=1:={exists}")]),
            name: "1:tool".into(),
            arm: Arm::Value(exists.clone()),
            var: set(&exists),
        },
        Row {
            key: "e_acute_drive",
            cwd: given(),
            block: block(&[format!("=é:={exists}")]),
            name: "é:tool".into(),
            arm: Arm::Value(exists.clone()),
            var: set(&exists),
        },
        Row {
            key: "e_acute_drive_upper_key",
            cwd: given(),
            block: block(&[format!("=É:={exists}")]),
            name: "é:tool".into(),
            arm: Arm::Value(exists.clone()),
            var: Var::Recorded,
        },
        // Duplicates in an inherited block: D1 reads the first match.
        Row {
            key: "duplicate_lower_first",
            cwd: given(),
            block: block(&[format!("={lq}={exists}"), format!("={q}={exists2}")]),
            name: format!("{q}tool"),
            arm: Arm::Value(exists.clone()),
            var: Var::Recorded,
        },
        Row {
            key: "duplicate_upper_first",
            cwd: given(),
            block: block(&[format!("={q}={exists}"), format!("={lq}={exists2}")]),
            name: format!("{q}tool"),
            arm: Arm::Value(exists.clone()),
            var: Var::Recorded,
        },
        // `env_clear()`: the block is empty, so there is no `=X:` either.
        Row {
            key: "env_clear",
            cwd: given(),
            block: vec![],
            name: format!("{q}tool"),
            arm: Arm::Root,
            var: Var::Is(None),
        },
        // E on T, the name's own drive: `Base`, whatever `=T:` holds.
        Row {
            key: "e_on_the_drive_given",
            cwd: given(),
            block: block(&[format!("={t}={exists}")]),
            name: format!("{t}tool"),
            arm: Arm::Base,
            var: set(&exists),
        },
        Row {
            key: "e_on_the_drive_inherited",
            cwd: Cwd::Inherited(e.clone()),
            block: block(&[format!("={t}={exists}")]),
            name: format!("{t}tool"),
            arm: Arm::Base,
            var: set(&exists),
        },
        Row {
            key: "e_on_the_drive_lowercase_program",
            cwd: given(),
            block: block(&[format!("={t}={exists}")]),
            name: format!("{lt}tool"),
            arm: Arm::Base,
            var: set(&exists),
        },
        // A verbatim E has no drive, so D1 takes `=T:`.
        Row {
            key: "verbatim_e",
            cwd: Cwd::Given(format!(r"\\?\{e}")),
            block: block(&[format!("={t}={exists}")]),
            name: format!("{t}tool"),
            arm: Arm::Value(exists.clone()),
            var: set(&exists),
        },
    ];
    for row in &rows {
        run(row, &render, &drives);
    }

    // Each of these names an existing directory (`sub` and `T:sub` name `e\sub`, the cwd's), and
    // Win32 ignores it: the name falls to the drive's root.
    let slashes = exists.replace('\\', "/");
    let ignored = [
        ("forward_slashes", slashes.clone()),
        ("slash_verbatim", format!("//?/{slashes}")),
        ("verbatim", format!(r"\\?\{exists}")),
        ("device", format!(r"\\.\{exists}")),
        ("mixed_separators", format!("{exists}/sub")),
        ("doubled_separator", format!(r"{exists}\\sub")),
        ("dot_dot", format!(r"{exists}\..\exists")),
        ("dot", format!(r"{exists}\.")),
        ("trailing_dot", format!("{exists}.")),
        ("trailing_space", format!("{exists} ")),
        ("relative", "sub".to_owned()),
        ("rooted", exists[2..].to_owned()),
        ("drive_relative", format!("{t}sub")),
    ];
    for (key, value) in ignored {
        let row = Row {
            key,
            cwd: given(),
            block: block(&[format!("={q}={value}")]),
            name: format!("{q}tool"),
            arm: Arm::Root,
            var: set(&value),
        };
        run(&row, &render, &drives);
    }

    assert!(
        std::path::Path::new(&format!(r"{unc}\exists")).is_dir(),
        "precondition: {unc} is reachable through the administrative share"
    );
    let unc_exists = format!(r"{unc}\exists");
    let unc_rows = vec![
        // A UNC value is ignored, whatever it names.
        Row {
            key: "unc_value",
            cwd: given(),
            block: block(&[format!("={q}={unc_exists}")]),
            name: format!("{q}tool"),
            arm: Arm::Root,
            var: set(&unc_exists),
        },
        Row {
            key: "unc_share_root",
            cwd: given(),
            block: block(&[format!(r"={q}=\\localhost\{}$", &t[..1])]),
            name: format!("{q}tool"),
            arm: Arm::Root,
            var: set(&format!(r"\\localhost\{}$", &t[..1])),
        },
        // A UNC E has no drive either.
        Row {
            key: "unc_e",
            cwd: Cwd::Given(format!(r"{unc}\e")),
            block: block(&[format!("={t}={exists}")]),
            name: format!("{t}tool"),
            arm: Arm::Value(exists.clone()),
            var: set(&exists),
        },
    ];
    for row in &unc_rows {
        run(row, &render, &drives);
    }
}

/// `executable("T:tool")` loads the file the child's own `GetFullPathNameW("T:tool")` names, on a
/// plain cwd on T (`Base`), on a verbatim one (`\\?\<e>`, which has no drive, so the child takes
/// `=T:`), and with a verbatim `=T:` itself (`\\?\<exists>\sub`, name `T:..\tool`). The child reports
/// its answer for the block `=T:=<value>`; cosca is given the same `=T:` and two copies of the image,
/// one in each directory, and the one it loads is compared with the child's answer.
///
/// Win32 ignores a verbatim `=T:` value: the name falls to the drive's root (`T:\tool`), as when the
/// variable is missing. So the verbatim `=T:` row loads nothing and cosca refuses it as `NotFound`,
/// not the `<exists>\tool.exe` a use of the value would find.
///
/// Preconditions, asserted: the child reports a path in the directory the row names (the drive's
/// root for the verbatim `=T:` row, which holds no `tool.exe`).
#[skuld::test]
fn m7c_cosca_completes_a_drive_relative_executable_as_a_childs_get_full_path_name_does(
    #[fixture(path_probes)] _group: &Group,
) {
    survey_platform();
    let tmp = tempfile::tempdir().expect("tempdir");
    let d = canonical(tmp.path());
    let (e, exists) = (format!(r"{d}\e"), format!(r"{d}\exists"));
    for dir in [&e, &exists] {
        std::fs::create_dir(dir).expect("create the row directories");
        std::fs::copy(crate::common::testbin(), format!(r"{dir}\tool.exe")).expect("copy the image");
    }
    std::fs::create_dir(format!(r"{exists}\sub")).expect("create the verbatim row's directory");
    let verbatim_value = format!(r"\\?\{exists}\sub");
    let t = &d[..2];
    let sr = format!("SystemRoot={}", std::env::var("SystemRoot").expect("SystemRoot"));
    let render = Render(vec![(d.clone(), "<d>".into())]);
    let drives = [(t.chars().next().expect("a drive"), 'T')];
    assert!(
        !std::path::Path::new(&format!(r"{t}\tool.exe")).exists(),
        "precondition: the root of {t} holds no tool.exe"
    );
    // (key, the child's cwd, the `=T:` value, the name, the directory the child must answer in, whether
    // the name finds an image)
    let rows = [
        (
            "plain_e",
            e.clone(),
            exists.clone(),
            format!("{t}tool"),
            e.clone(),
            true,
        ),
        (
            "verbatim_e",
            format!(r"\\?\{e}"),
            exists.clone(),
            format!("{t}tool"),
            exists.clone(),
            true,
        ),
        (
            "verbatim_value",
            format!(r"\\?\{e}"),
            verbatim_value.clone(),
            format!(r"{t}..\tool"),
            t.to_owned(),
            false,
        ),
    ];
    // A verbatim path is the same path without the prefix, for comparing where two answers are.
    let dir_of = |path: &str| {
        let dir = path.rsplit_once('\\').expect("a path").0.to_ascii_lowercase();
        dir.strip_prefix(r"\\?\").map_or(dir.clone(), str::to_owned)
    };
    for (key, cwd, value, name, under, loads) in rows {
        let row = Row {
            key,
            cwd: Cwd::Given(cwd.clone()),
            block: vec![sr.clone(), format!("={t}={value}")],
            name: name.clone(),
            arm: match key {
                "plain_e" => Arm::Base,
                // A verbatim value is ignored.
                "verbatim_value" => Arm::Root,
                _ => Arm::Value(value.clone()),
            },
            var: Var::Is(Some(value.clone())),
        };
        let full = run(&row, &render, &drives);
        assert_eq!(
            dir_of(&full),
            under.to_ascii_lowercase(),
            "{key}: precondition: the child's answer"
        );

        let mut cmd = crate::common::command(crate::common::Console::Hidden);
        cmd.executable(&name)
            .commandline("x argv0-report")
            .current_dir(&cwd)
            .env(format!("={t}"), &value)
            .stdout(cosca::Stdio::pipe())
            .expect("pipe stdout");
        let spawned = cmd.spawn();
        if !loads {
            match spawned {
                Err(cosca::error::Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => panic!("{key}: cosca refused the name as something other than NotFound: {e}"),
                Ok(_) => panic!("{key}: cosca loaded an image, where the child's answer is {full}"),
            }
        }
        let mut child = spawned.unwrap_or_else(|e| panic!("{key}: cosca refused the name: {e}"));
        let mut out = String::new();
        std::io::Read::read_to_string(&mut child.stdout().expect("stdout"), &mut out).expect("read the report");
        child.wait().expect("wait");
        let image = out
            .lines()
            .find_map(|l| l.strip_prefix("image="))
            .unwrap_or_else(|| panic!("{key}: no image= line in {out:?}"));
        assert_eq!(
            dir_of(image),
            dir_of(&full),
            "{key}: cosca loaded {image}, the child's GetFullPathNameW says {full}"
        );
    }
}
