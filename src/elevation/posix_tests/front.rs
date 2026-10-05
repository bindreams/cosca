//! The front the rewrite names on its derived command: the one source a spawn's kill gates read.

use super::super::rewrite_with_host;
use super::rewrite_tests::{elevated_sudo_host, sudo_host};
use crate::command::Command;
use crate::elevation::pkexec::PkexecVersion;
use crate::elevation::plan::{BackendSet, Host, Os};
use crate::elevation::{Auth, Backend};
use std::path::PathBuf;

/// A Linux host offering every CLI backend, its `pkexec` pinned on `/dev/null`.
fn every_backend_host() -> Host {
    Host {
        available: BackendSet {
            run0: Some(PathBuf::from("/usr/bin/run0")),
            sudo: Some(PathBuf::from("/usr/bin/sudo")),
            doas: Some(PathBuf::from("/usr/bin/doas")),
            pkexec: Some(PathBuf::from("/usr/bin/pkexec")),
            osascript: None,
        },
        pkexec_version: PkexecVersion::Parsed {
            version: "121".into(),
            release: Some(121),
        },
        pkexec_pin: Some(std::sync::Arc::new(
            std::fs::File::open("/dev/null").expect("open /dev/null"),
        )),
        os: Os::Linux,
        ..sudo_host()
    }
}

/// The name of the front the rewrite of an `id` under `backend` on `host` names, if any.
fn front_named(backend: Backend, host: &Host) -> Option<&'static str> {
    let mut c = Command::new();
    let auth = if backend == Backend::Pkexec {
        Auth::Gui
    } else {
        Auth::NonInteractive
    };
    c.args(["id"]).elevation_backend(backend).elevation_auth(auth);
    let rewrite = rewrite_with_host(&mut c, host).expect("rewrite");
    rewrite
        .derived
        .expect("a derived command")
        .elevation_front()
        .map(|front| front.name)
}

/// sudo and doas leave this process tracking a front; pkexec and run0 do not.
#[skuld::test]
fn sudo_and_doas_name_a_front_and_pkexec_and_run0_do_not() {
    let host = every_backend_host();
    assert_eq!(front_named(Backend::Sudo, &host), Some("sudo"));
    assert_eq!(front_named(Backend::Doas, &host), Some("doas"));
    assert_eq!(front_named(Backend::Pkexec, &host), None);
    assert_eq!(front_named(Backend::Run0, &host), None);
}

/// An already-elevated caller runs the program itself: no front.
#[skuld::test]
fn an_already_elevated_spawn_names_no_front() {
    assert_eq!(front_named(Backend::Sudo, &elevated_sudo_host()), None);
}
