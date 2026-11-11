use super::{parse, PkexecVersion, KEEP_CWD_SINCE};
use crate::error::{Error, IoFailure};

const OS_CODE: i32 = 2;

/// `pkexec --version`'s stdout, verbatim (exit 0, empty stderr), measured per image.
const UBUNTU_22_04: &[u8] = b"pkexec version 0.105\n";
const ROCKY_9: &[u8] = b"pkexec version 0.117\n";
const FEDORA_37: &[u8] = b"pkexec version 121\n";
const DEBIAN_12: &[u8] = b"pkexec version 122\n";
const FEDORA_44: &[u8] = b"pkexec version 127\n";

fn parsed(version: &str, release: Option<u32>) -> PkexecVersion {
    PkexecVersion::Parsed {
        version: version.into(),
        release,
    }
}

#[skuld::test]
fn the_measured_outputs_parse() {
    assert_eq!(parse(UBUNTU_22_04), parsed("0.105", None));
    assert_eq!(parse(ROCKY_9), parsed("0.117", None));
    assert_eq!(parse(FEDORA_37), parsed("121", Some(121)));
    assert_eq!(parse(DEBIAN_12), parsed("122", Some(122)));
    assert_eq!(parse(FEDORA_44), parsed("127", Some(127)));
}

/// Pins [`KEEP_CWD_SINCE`] against an accidental edit.
#[skuld::test]
fn keep_cwd_arrived_in_121() {
    assert_eq!(KEEP_CWD_SINCE, 121);
}

#[skuld::test]
fn only_121_and_later_is_runnable() {
    for (out, ok) in [
        (UBUNTU_22_04, false),
        (ROCKY_9, false),
        (b"pkexec version 0.120\n".as_slice(), false),
        (b"pkexec version 120\n", false),
        (FEDORA_37, true),
        (DEBIAN_12, true),
        (FEDORA_44, true),
    ] {
        let v = parse(out);
        assert_eq!(v.refusal().is_none(), ok, "{v:?}");
    }
}

/// Anything but exactly `pkexec version <V>\n` is not a version.
#[skuld::test]
fn the_pattern_is_strict() {
    for out in [
        "",
        "pkexec version 122",
        "pkexec version 122\n\n",
        "pkexec version  122\n",
        "pkexec version 122 \n",
        " pkexec version 122\n",
        "pkexec version 122\r\n",
        "Pkexec version 122\n",
        "pkexec version v122\n",
        "pkexec version 0122\n",
        "pkexec version 122.1\n",
        "pkexec version 0.\n",
        "pkexec version 0.1x\n",
        "pkexec version 1.0\n",
        "pkexec version +122\n",
        "pkexec version 99999999999\n",
        "polkit 122\n",
    ] {
        assert_eq!(parse(out.as_bytes()), PkexecVersion::Unparsed(out.into()), "{out:?}");
    }
}

#[skuld::test]
fn non_utf8_output_is_its_own_case() {
    assert_eq!(
        parse(b"pkexec version \xff\n"),
        PkexecVersion::NonUtf8("pkexec version \u{fffd}\n".into())
    );
}

fn refusal_detail(v: PkexecVersion) -> String {
    match v.refusal() {
        Some(Error::Unsupported { op, detail, .. }) => {
            assert!(op.contains("pkexec"), "{op}");
            detail
        }
        other => panic!("{v:?}: expected Unsupported, got {other:?}"),
    }
}

/// Each refusal says which case it is, carries the raw text where there is one, and names the way
/// out.
#[skuld::test]
fn each_refusal_names_its_case_and_the_raw_text() {
    let cases = [
        (parse(UBUNTU_22_04), "reports version 0.105"),
        (parse(b"pkexec version 120\n"), "reports version 120"),
        (parse(b"polkit 122\n"), "\"polkit 122\\n\""),
        (parse(b"pkexec version \xff\n"), "non-UTF-8"),
        (
            PkexecVersion::SpawnFailed(IoFailure::of(&std::io::Error::from_raw_os_error(OS_CODE))),
            "`pkexec --version` could not be run;",
        ),
        (
            PkexecVersion::Failed {
                status: "exit status: 3".into(),
                stdout: "oops".into(),
                stderr: "boom".into(),
            },
            "exited with exit status: 3",
        ),
        (PkexecVersion::NotProbed, "was not checked"),
        (
            PkexecVersion::Unresolved {
                path: "/opt/bin/pkexec".into(),
                error: IoFailure::of(&std::io::Error::from_raw_os_error(OS_CODE)),
            },
            "/opt/bin/pkexec could not be resolved to its real file;",
        ),
        (
            PkexecVersion::Unpinned {
                path: "/opt/bin/pkexec".into(),
                error: IoFailure::of(&std::io::Error::from_raw_os_error(OS_CODE)),
            },
            "pkexec at /opt/bin/pkexec could not be opened as its real file;",
        ),
    ];
    for (v, needle) in cases {
        let detail = refusal_detail(v.clone());
        assert!(detail.contains(needle), "{v:?}: {detail}");
        assert!(detail.contains("121"), "{v:?}: {detail}");
        assert!(detail.contains("sudo"), "{v:?}: {detail}");
    }
    let failed = refusal_detail(PkexecVersion::Failed {
        status: "exit status: 3".into(),
        stdout: "oops".into(),
        stderr: "boom".into(),
    });
    assert!(failed.contains("\"oops\"") && failed.contains("\"boom\""), "{failed}");
}

#[skuld::test]
fn a_refusal_that_follows_a_failed_read_has_it_as_its_cause() {
    let os = || std::io::Error::from_raw_os_error(OS_CODE);
    for v in [
        PkexecVersion::SpawnFailed(IoFailure::of(&os())),
        PkexecVersion::Unresolved {
            path: "/opt/bin/pkexec".into(),
            error: IoFailure::of(&os()),
        },
        PkexecVersion::Unpinned {
            path: "/opt/bin/pkexec".into(),
            error: IoFailure::of(&os()),
        },
    ] {
        let refusal = v.refusal().expect("a failed read refuses");
        assert_eq!(refusal.raw_os_error(), Some(OS_CODE), "{v:?}: {refusal:?}");
        let Error::Unsupported { detail, .. } = &refusal else {
            panic!("{v:?}: expected Unsupported, got {refusal:?}");
        };
        assert!(!detail.contains(&os().to_string()), "{v:?}: {detail}");
    }
}

#[skuld::test]
fn a_kept_failure_comes_back_as_an_equal_io_error() {
    let os = std::io::Error::from_raw_os_error(OS_CODE);
    let back = IoFailure::of(&os).to_io();
    assert_eq!((back.raw_os_error(), back.kind()), (Some(OS_CODE), os.kind()));
    let plain = std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a regular file");
    let back = IoFailure::of(&plain).to_io();
    assert_eq!((back.raw_os_error(), back.kind()), (None, plain.kind()));
    assert_eq!(back.to_string(), "not a regular file");
}
