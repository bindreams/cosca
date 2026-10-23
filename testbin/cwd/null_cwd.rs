//! M12 and M13: a child spawned with no `current_dir` (`NULL`, std's route) from a process cwd
//! whose string no longer names it, against one given that string explicitly. Each spawn reports
//! `ok,cwd=<string>,markers=<names>`: the child's cwd string and the `marker-*` files it finds
//! there, which tell two directories behind one string apart.

use std::ffi::OsStr;
use std::path::Path;

use crate::completion::{free_drive, Subst};
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
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with("marker"))
                .collect();
            names.sort();
            names.join(",")
        }
        Err(e) => format!("err({e})"),
    };
    println!("markers={markers}");
}

const KEYS: &[&str] = &["cwd", "markers"];

/// Spawns `child report-cwd-final` four ways from this process's cwd, printing `<prefix>_<route>=`.
fn spawn_rows(prefix: &str, child: &str, render: &Render) {
    let gcd = std::env::current_dir();
    println!(
        "{prefix}_gcd={}",
        gcd.as_ref()
            .map_or_else(|e| format!("err({e})"), |p| render.apply(&p.display().to_string()))
    );
    let null_std = std_run(std::process::Command::new(child).arg("report-cwd-final"), KEYS, render);
    println!("{prefix}_null_std={null_std}");
    let mut null_raw = cosca::Command::new();
    null_raw.executable(child).commandline("x report-cwd-final");
    println!("{prefix}_null_raw={}", cosca_run(&mut null_raw, KEYS, render));
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
    let drive = free_drive();
    let render = Render(vec![
        (d1.display().to_string(), "<d1>".to_owned()),
        (d2.display().to_string(), "<d2>".to_owned()),
        (d.display().to_string(), "<d>".to_owned()),
        (drive.clone(), "X:".to_owned()),
    ]);
    let sub = format!(r"{drive}\sub");

    let first = Subst::new(&drive, &d1).expect("map X: to <d1>");
    let set = set_cwd(OsStr::new(&sub));
    println!("removed_set={}", outcome(&set));
    drop(first);
    if set.is_ok() {
        spawn_rows("removed", child, &render);
    }
    set_cwd(d.as_os_str()).expect("leave the removed drive");

    let first = Subst::new(&drive, &d1).expect("map X: to <d1>");
    let set = set_cwd(OsStr::new(&sub));
    println!("repointed_set={}", outcome(&set));
    let second = Subst::new(&drive, &d2).expect("map X: to <d2> over <d1>");
    if set.is_ok() {
        spawn_rows("repointed", child, &render);
    }
    set_cwd(d.as_os_str()).expect("leave the re-pointed drive");
    drop(second);
    drop(first);
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
    let mut null_raw = cosca::Command::new();
    null_raw.executable(image).commandline("x");
    println!("null_raw={}", cosca_run(&mut null_raw, keys, &render));
    let string_std = std_run(std::process::Command::new(image).current_dir(&gcd), keys, &render);
    println!("string_std={string_std}");
    let mut string_raw = cosca::Command::new();
    string_raw.executable(image).commandline("x").current_dir(&gcd);
    println!("string_raw={}", cosca_run(&mut string_raw, keys, &render));
}
