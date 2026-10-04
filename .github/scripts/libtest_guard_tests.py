#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Self-test for libtest_guard.py.

Runs the guard on .github/fixtures/libtest-guard, a toy crate with one feature per case, and
asserts the exit code and the (file, line) set the guard writes to --findings-json. The OS- and
arch-gated cases assert the host's own OS and architecture; each OS is covered by running this
script on it.
"""

import json
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
GUARD = HERE / "libtest_guard.py"
FIXTURE = HERE.parent / "fixtures" / "libtest-guard"
MANIFEST = FIXTURE / "Cargo.toml"

host_os = {"Linux": "linux", "Darwin": "macos"}.get(platform.system(), "windows")
host_triple = subprocess.run(["rustc", "--print", "host-tuple"], check=True, capture_output=True, text=True).stdout.strip()
host_arch = host_triple.partition("-")[0]
# The other architecture's triple comes from the matrix (`matrix.other`); it must be installed.
other_triple = os.environ.get("LIBTEST_GUARD_OTHER_TARGET") or sys.exit(
    "::error::LIBTEST_GUARD_OTHER_TARGET is not set: the target triple of the other architecture")
other_arch = other_triple.partition("-")[0]

failures = 0
checks = 0


def line_of(file: str, pattern: str) -> int:
    for n, line in enumerate((FIXTURE / file).read_text().splitlines(), 1):
        if pattern in line:
            return n
    sys.exit(f"::error::fixture {file} has no line containing {pattern!r}")


def both(pattern: str) -> set[str]:
    """The findings of the case holding PATTERN, in the lib and in the `it` target."""
    return {f"src/lib.rs:{line_of('src/lib.rs', pattern)}", f"tests/it.rs:{line_of('tests/it.rs', pattern)}"}


def fail(msg: str) -> None:
    global failures
    failures += 1
    print(f"FAIL - {msg}")


with tempfile.TemporaryDirectory() as tmp:
    work = Path(tmp)
    (work / "cwd-with-wrapper" / ".cargo").mkdir(parents=True)
    (work / "cwd-with-wrapper" / ".cargo" / "config.toml").write_text('[build]\nrustc-wrapper = "false"\n')

    def check(name, want_rc, want_found, *args, manifest=MANIFEST, env=None, cwd=None, stderr_has=(), stderr_lacks=()):
        """Run the guard on the fixture; assert exit code, findings and stderr."""
        global checks
        checks += 1
        out = work / "findings.json"
        out.unlink(missing_ok=True)
        done = subprocess.run(
            [sys.executable, str(GUARD), "--manifest-path", str(manifest),
             "--findings-json", str(out), *args],
            env={**os.environ, "CARGO_TARGET_DIR": str(work / "target"), **(env or {})},
            cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        found: set[str] = set()
        if out.exists():
            try:
                found = {f"{e['file']}:{e['line']}" for e in json.loads(out.read_text())}
            except ValueError:
                found = {"<unparseable findings json>"}
        ok = done.returncode == want_rc and found == set(want_found)
        for text in stderr_has:
            if text not in done.stderr:
                ok = False
                print(f"missing in stderr: {text!r}")
        for text in stderr_lacks:
            if text in done.stderr:
                ok = False
                print(f"unexpected in stderr: {text!r}")
        if ok:
            print(f"ok   - {name}")
        else:
            fail(f"{name}: exit {done.returncode} (want {want_rc}); findings {sorted(found)}, want {sorted(want_found)}")
            print(done.stderr)

    # The seven spellings, each in the harness = false lib and in the harness = false `it` target ----
    check("clean", 0, (), "--features", "quiet")
    check("plain #[test]", 1, both("fn plain"), "--features", "plain")
    check("#[tokio::test]", 1, both("fn tokio_test"), "--features", "tokio_test")
    check("#[core::prelude::v1::test]", 1, both("fn prelude_path"), "--features", "prelude_path")
    check("#[cfg_attr(all(), test)]", 1, both("fn cfg_attr_test"), "--features", "cfg_attr_test")
    check("renamed import, #[t]", 1, both("fn renamed"), "--features", "renamed")
    check("#[test] from macro_rules!", 1, both("macro_rules! emit"), "--features", "macro_rules")
    # One file compiled into the lib and `it`: flagged once.
    check("module shared with a libtest target", 1, {"src/shared.rs:1"}, "--features", "shared")

    # Release-only code ---------------------------------------------------------------------------------
    check("cfg(not(debug_assertions)) test, debug", 0, (), "--features", "release_only")
    check("cfg(not(debug_assertions)) test, release", 1, both("fn release_only"), "--features", "release_only", "--release")
    check("both profiles", 1, both("fn release_only"), "--features", "release_only", "--both-profiles")

    # `post_mono` (tests/pm.rs) is an error only code generation sees, so a test target must not be code-generated.
    check("no code generation for a test target, debug", 0, (), "--features", "post_mono")
    check("no code generation for a test target, release", 0, (), "--features", "post_mono", "--release")
    check("no code generation for a test target, powerset, both profiles", 1, both("fn ps_none"), "--feature-powerset",
          "--features", "post_mono", "--both-profiles",
          stderr_lacks=("failed without a libtest-attribute finding",))

    # One OS-gated test per OS: flagged on its own OS, absent elsewhere ---------------------------------
    for os_name in ("linux", "macos", "windows"):
        mine = os_name == host_os
        check(f"OS-gated #[tokio::test] for {os_name} (host: {host_os})", 1 if mine else 0,
              both(f"fn os_{os_name}") if mine else (), "--features", f"os_{os_name}")

    # A `test = false` bin is still compiled as a test and checked ---------------------------------------
    bin_hit = {f"src/bin_nt.rs:{line_of('src/bin_nt.rs', 'fn never_runs')}"}
    check("#[test] in a test = false bin", 1, bin_hit, "--features", "bin_test_false")
    check("#[test] in a test = false bin, release", 1, bin_hit, "--features", "bin_test_false", "--release")

    # The feature powerset ----------------------------------------------------------------------------------
    # The empty combination runs too: `ps_none` is only on when no feature is.
    check("feature powerset", 1, both("fn plain") | both("fn tokio_test") | both("fn ps_none"),
          "--feature-powerset", "--features", "plain,tokio_test")
    # Two findings in disjoint combinations: all of them are reported, not just the first.
    check("feature powerset: disjoint combinations", 1,
          both("fn ps_only_a") | both("fn ps_only_b") | both("fn ps_none"),
          "--feature-powerset", "--features", "ps_a,ps_b")
    check("no powerset: the combined features miss the subset-only cases", 0, (), "--features", "ps_a,ps_b")

    # Other architectures ------------------------------------------------------------------------------------
    both_arches = "arch_x86_64,arch_aarch64"
    check(f"arch-gated tests, native ({host_arch})", 1, both(f"fn arch_{host_arch}"), "--features", both_arches)
    check(f"arch-gated tests, --target {other_triple}", 1, both(f"fn arch_{other_arch}"),
          "--features", both_arches, "--target", other_triple)

    # A finding that cannot be silenced, and a compile that fails without one -------------------------------
    check("compile error without a finding fails, and says why", 1, (), "--features", "type_error",
          stderr_has=("E0308", "failed without a libtest-attribute finding"))
    check("crate-level allow(clippy::all) cannot silence the guard", 1, (), "--features", "crate_allow",
          stderr_has=("E0453",))

    # A compiler wrapper, from the environment or from cargo config, must not sit in front of clippy-driver
    check("RUSTC_WRAPPER is bypassed", 0, (), "--features", "quiet", env={"RUSTC_WRAPPER": "false"})
    check("CARGO_BUILD_RUSTC_WRAPPER is bypassed", 0, (), "--features", "quiet",
          env={"CARGO_BUILD_RUSTC_WRAPPER": "false"})
    check("build.rustc-wrapper in the cwd's cargo config is bypassed", 0, (), "--features", "quiet",
          cwd=work / "cwd-with-wrapper")

    # Manifest checks ---------------------------------------------------------------------------------------
    # A target on the default harness is refused, whatever its kind.
    for kind, files, section in (
        ("test", {"src/lib.rs": "", "tests/dh.rs": ""}, '[lib]\nharness = false\n'),
        ("bin", {"src/main.rs": "fn main() {}\n"}, ""),
    ):
        crate = work / f"default-harness-{kind}"
        crate.mkdir()
        (crate / "Cargo.toml").write_text(f'[package]\nname = "dh"\nversion = "0.0.0"\nedition = "2021"\n\n{section}')
        (crate / "Cargo.lock").write_text('version = 4\n\n[[package]]\nname = "dh"\nversion = "0.0.0"\n')
        for rel, text in files.items():
            (crate / rel).parent.mkdir(exist_ok=True)
            (crate / rel).write_text(text)
        check(f"default-harness {kind} target", 2, (), manifest=crate / "Cargo.toml",
              stderr_has=(f"target dh ({kind}) uses the default libtest harness",))

if failures:
    sys.exit(f"::error::{failures} libtest-guard self-test check(s) failed")
print(f"all {checks} libtest-guard self-test checks passed")
