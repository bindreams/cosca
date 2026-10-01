use std::path::Path;

use crate::modtree::{walk, GitSource, Source};
use crate::test_util::{paths, MemSource};

#[test]
fn walks_path_modules() {
    let src = MemSource::new(&[
        (
            "/t/tests/r.rs",
            "#[path = \"common/mod.rs\"]\nmod common;\nmod plain;\nmod dir_mod;\nmod a { #[path = \"p.rs\"] mod b; mod c; }\n#[path = \"../shared/x_tests.rs\"]\nmod x;\n#[path = \"../src/test_harness.rs\"]\nmod test_harness;\nfn f() { mod in_fn; }\n",
        ),
        ("/t/tests/common/mod.rs", "mod sub;\n"),
        ("/t/tests/common/sub.rs", ""),
        ("/t/tests/plain.rs", "mod inner;\n"),
        ("/t/tests/plain/inner.rs", ""),
        ("/t/tests/dir_mod/mod.rs", "mod deep;\n"),
        ("/t/tests/dir_mod/deep.rs", ""),
        ("/t/tests/a/p.rs", ""),
        ("/t/tests/a/c.rs", ""),
        // A `#[path]` file is mod-rs-like: its children sit beside it.
        ("/t/shared/x_tests.rs", "mod y;\n"),
        ("/t/shared/y.rs", ""),
    ]);
    let files = walk(&src, Path::new("/t/tests/r.rs")).unwrap();
    assert_eq!(
        paths(&files),
        [
            "/t/shared/x_tests.rs",
            "/t/shared/y.rs",
            "/t/tests/a/c.rs",
            "/t/tests/a/p.rs",
            "/t/tests/common/mod.rs",
            "/t/tests/common/sub.rs",
            "/t/tests/dir_mod/deep.rs",
            "/t/tests/dir_mod/mod.rs",
            "/t/tests/plain.rs",
            "/t/tests/plain/inner.rs",
            "/t/tests/r.rs",
        ]
    );
    assert!(files.iter().filter(|f| f.is_root).count() == 1 && files[0].is_root);
}

#[test]
fn a_file_reachable_twice_is_listed_once() {
    let src = MemSource::new(&[
        ("/t/r.rs", "#[path = \"s.rs\"] mod one;\n#[path = \"s.rs\"] mod two;\n"),
        ("/t/s.rs", ""),
    ]);
    assert_eq!(
        paths(&walk(&src, Path::new("/t/r.rs")).unwrap()),
        ["/t/r.rs", "/t/s.rs"]
    );
}

#[test]
fn an_ambiguous_or_missing_module_file_is_an_error_naming_it() {
    let both = MemSource::new(&[("/t/r.rs", "mod m;\n"), ("/t/m.rs", ""), ("/t/m/mod.rs", "")]);
    let err = walk(&both, Path::new("/t/r.rs")).err().unwrap().to_string();
    assert!(err.contains("ambiguous") && err.contains("/t/m.rs"), "{err}");
    let none = MemSource::new(&[("/t/r.rs", "mod m;\n")]);
    let err = walk(&none, Path::new("/t/r.rs")).err().unwrap().to_string();
    assert!(err.contains("no file") && err.contains("/t/m.rs"), "{err}");
}

#[test]
fn git_source_reads_a_revision_and_reports_absence() {
    let dir = tempfile::tempdir().unwrap();
    let top = std::fs::canonicalize(dir.path()).unwrap();
    let git = |args: &[&str]| {
        let st = std::process::Command::new("git")
            .arg("-C")
            .arg(&top)
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@example.invalid",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(st.success(), "git {args:?}");
    };
    git(&["init", "-q"]);
    std::fs::write(top.join("a.rs"), "old\n").unwrap();
    git(&["add", "a.rs"]);
    git(&["commit", "-q", "-m", "one"]);
    std::fs::write(top.join("a.rs"), "new\n").unwrap();
    let src = GitSource::new(&top, "HEAD").unwrap();
    assert_eq!(src.read(&top.join("a.rs")).unwrap().as_deref(), Some("old\n"));
    assert_eq!(src.read(&top.join("b.rs")).unwrap(), None);
    assert!(GitSource::new(&top, "no-such-rev").is_err());
}

#[test]
fn follows_every_cfg_attr_path_alternative() {
    let src = MemSource::new(&[
        (
            "/t/r.rs",
            "#[cfg_attr(windows, path = \"b/win.rs\")]\n#[cfg_attr(unix, path = \"b/unix.rs\")]\nmod backend;\n#[cfg_attr(unix, path = \"o.rs\")]\nmod other;\n",
        ),
        ("/t/b/win.rs", ""),
        ("/t/b/unix.rs", ""),
        // The default file serves the platforms no `cfg_attr` names.
        ("/t/other.rs", ""),
        ("/t/o.rs", ""),
    ]);
    assert_eq!(
        paths(&walk(&src, Path::new("/t/r.rs")).unwrap()),
        ["/t/b/unix.rs", "/t/b/win.rs", "/t/o.rs", "/t/other.rs", "/t/r.rs"]
    );
}

#[test]
fn follows_nested_cfg_attr_path_alternatives() {
    let src = MemSource::new(&[
        (
            "/t/r.rs",
            "#[cfg_attr(unix, cfg_attr(all(), path = \"n.rs\"))]\nmod m;\n",
        ),
        ("/t/m.rs", ""),
        ("/t/n.rs", ""),
    ]);
    assert_eq!(
        paths(&walk(&src, Path::new("/t/r.rs")).unwrap()),
        ["/t/m.rs", "/t/n.rs", "/t/r.rs"]
    );
}

#[test]
fn only_the_exact_harness_include_at_a_root_is_skipped() {
    let src = MemSource::new(&[
        (
            "/t/tests/r.rs",
            "#[path = \"../src/test_harness.rs\"]\nmod test_harness;\n#[cfg(test)]\nmod inline_harness { }\nmod sub;\n",
        ),
        (
            "/t/tests/sub.rs",
            "#[path = \"../b.rs\"] mod test_harness;\nmod test_harness2 { #[path = \"c.rs\"] mod c; }\n",
        ),
        ("/t/b.rs", ""),
        ("/t/tests/sub/test_harness2/c.rs", ""),
    ]);
    let got = paths(&walk(&src, Path::new("/t/tests/r.rs")).unwrap());
    assert_eq!(
        got,
        [
            "/t/b.rs",
            "/t/tests/r.rs",
            "/t/tests/sub.rs",
            "/t/tests/sub/test_harness2/c.rs"
        ]
    );
}

#[test]
fn an_inline_or_repointed_test_harness_module_is_walked() {
    let src = MemSource::new(&[("/t/r.rs", "#[path = \"b.rs\"]\nmod test_harness;\n"), ("/t/b.rs", "")]);
    assert_eq!(
        paths(&walk(&src, Path::new("/t/r.rs")).unwrap()),
        ["/t/b.rs", "/t/r.rs"]
    );
}
