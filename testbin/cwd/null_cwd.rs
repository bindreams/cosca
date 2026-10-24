//! M12 and M13: a child spawned with no `current_dir` from a process cwd whose string no longer
//! names it, against one given that string explicitly. std then passes `NULL`; the raw backend
//! never does, and passes the cwd string whether or not `current_dir` was set. Each spawn reports
//! `ok,cwd=<string>,markers=<names>`: the child's cwd string and the `marker-*` files it finds
//! there, which tell two directories behind one string apart.

use std::ffi::OsStr;
use std::path::Path;

use crate::completion::{assert_undefined, Subst};
use crate::measure::{cosca_run, std_run, Render};
use crate::probe::{canonical, outcome, set_cwd, verbatim_of};

/// `report-cwd-final`: this process's cwd string and the `marker-*` names in its cwd.
pub fn report_cwd_final() {
    println!(
        "cwd={}",
        std::env::current_dir().map_or_else(|e| format!("err({e})"), |p| p.display().to_string())
    );
    let markers = match std::fs::read_dir(".") {
        Ok(entries) => {
            let mut names: Vec<String> = entries
                .filter_map(|entry| match entry {
                    Ok(e) => Some(e.file_name().to_string_lossy().into_owned()).filter(|n| n.starts_with("marker")),
                    Err(e) => Some(format!("err({e})")),
                })
                .collect();
            names.sort();
            names.join(",")
        }
        Err(e) => format!("err({e})"),
    };
    println!("markers={markers}");
}

const KEYS: &[&str] = &["cwd", "markers"];

/// Spawns `child report-cwd-final` from this process's cwd, printing `<prefix>_<route>=`. `null_std`
/// sends `NULL`; `unset_raw` sets no `current_dir`, and the raw backend sends the cwd string.
fn spawn_rows(prefix: &str, child: &str, render: &Render) {
    let gcd = std::env::current_dir();
    println!(
        "{prefix}_gcd={}",
        gcd.as_ref()
            .map_or_else(|e| format!("err({e})"), |p| render.apply(&p.display().to_string()))
    );
    let null_std = std_run(std::process::Command::new(child).arg("report-cwd-final"), KEYS, render);
    println!("{prefix}_null_std={null_std}");
    let mut unset_raw = cosca::Command::new();
    unset_raw.executable(child).commandline("x report-cwd-final");
    println!("{prefix}_unset_raw={}", cosca_run(&mut unset_raw, KEYS, render));
    let Ok(gcd) = gcd else { return };
    let string_std = std_run(
        std::process::Command::new(child)
            .arg("report-cwd-final")
            .current_dir(&gcd),
        KEYS,
        render,
    );
    println!("{prefix}_string_std={string_std}");
    let mut string_raw = cosca::Command::new();
    string_raw
        .executable(child)
        .commandline("x report-cwd-final")
        .current_dir(&gcd);
    println!("{prefix}_string_raw={}", cosca_run(&mut string_raw, KEYS, render));
}

/// `subst-cwd <base> <child>`: maps a free letter `X:` to `<d1>` and enters `X:\sub`, then
/// (`removed_`) removes the mapping, or (`repointed_`) maps `X:` to `<d2>` over it, and spawns
/// from there. System-affecting: the mapping is visible to the whole logon session.
pub fn subst_cwd(base: &str, child: &str) {
    let d = canonical(base);
    let (d1, d2) = (d.join("d1"), d.join("d2"));
    for (dir, marker) in [(&d1, "marker-d1"), (&d2, "marker-d2")] {
        std::fs::create_dir_all(dir.join("sub")).expect("create the drive's directories");
        std::fs::write(dir.join("sub").join(marker), b"").expect("plant the marker");
    }
    let first = Subst::map_free(&d1).expect("map a free letter to <d1>");
    let drive = first.drive().to_owned();
    let render = Render(vec![
        (d1.display().to_string(), "<d1>".to_owned()),
        (d2.display().to_string(), "<d2>".to_owned()),
        (d.display().to_string(), "<d>".to_owned()),
        (drive.clone(), "X:".to_owned()),
    ]);
    let sub = format!(r"{drive}\sub");

    let set = set_cwd(OsStr::new(&sub));
    println!("removed_set={}", outcome(&set));
    first.remove().expect("remove the mapping of X:");
    assert_undefined(&drive);
    if set.is_ok() {
        spawn_rows("removed", child, &render);
    }
    set_cwd(d.as_os_str()).expect("leave the removed drive");

    let first = Subst::new(&drive, &d1, 0).unwrap_or_else(|e| panic!("map {drive} to <d1> again: {e}"));
    let set = set_cwd(OsStr::new(&sub));
    println!("repointed_set={}", outcome(&set));
    let second = Subst::new(&drive, &d2, 1).unwrap_or_else(|e| panic!("map {drive} to <d2> over <d1>: {e}"));
    assert!(
        Path::new(&format!(r"{drive}\sub\marker-d2")).exists(),
        "{drive} was re-pointed at <d2>"
    );
    if set.is_ok() {
        spawn_rows("repointed", child, &render);
    }
    set_cwd(d.as_os_str()).expect("leave the re-pointed drive");
    // Both removals run before either check, so one failure leaves no mapping behind that the
    // other would have removed.
    let second = second.remove();
    let first = first.remove();
    second.expect("remove the second mapping of X:");
    first.expect("remove the first mapping of X:");
    assert_undefined(&drive);
}

/// `verbatim-null <base> <image>`: enters `\\?\<d>` and spawns `<image>` from there.
pub fn verbatim_null(base: &str, image: &str) {
    let d = canonical(base).join("v13");
    std::fs::create_dir_all(&d).expect("create <d>");
    std::fs::write(d.join("marker-v13"), b"").expect("plant the marker");
    let vd = verbatim_of(&d);
    let set = set_cwd(&vd);
    println!("set={}", outcome(&set));
    if set.is_err() {
        return;
    }
    let render = Render(vec![
        (vd.to_string_lossy().into_owned(), "<vd>".to_owned()),
        (d.display().to_string(), "<d>".to_owned()),
    ]);
    let image = Path::new(image);
    let gcd = std::env::current_dir().expect("the verbatim cwd");
    println!("gcd={}", render.apply(&gcd.display().to_string()));
    let keys = &["cwd"];
    println!(
        "null_std={}",
        std_run(&mut std::process::Command::new(image), keys, &render)
    );
    let mut null_cosca = cosca::Command::new();
    null_cosca.arg(image);
    println!("null_cosca={}", cosca_run(&mut null_cosca, keys, &render));
    let mut unset_raw = cosca::Command::new();
    unset_raw.executable(image).commandline("x");
    println!("unset_raw={}", cosca_run(&mut unset_raw, keys, &render));
    let string_std = std_run(std::process::Command::new(image).current_dir(&gcd), keys, &render);
    println!("string_std={string_std}");
    let mut string_raw = cosca::Command::new();
    string_raw.executable(image).commandline("x").current_dir(&gcd);
    println!("string_raw={}", cosca_run(&mut string_raw, keys, &render));
}
