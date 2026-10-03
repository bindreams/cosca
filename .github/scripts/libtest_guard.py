#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""The libtest guard.

A `harness = false` target never runs libtest's `#[test]` or `#[tokio::test]` (the attribute is
stripped), so such a test would silently never run. Two checks:

1. Manifest (exit 2). Every `test = true` target must be `harness = false` in Cargo.toml, or be
   listed in the unflipped file as `<kind>:<name>` (`lib:cosca`, `test:spawn_io`, `bin:tool`).
   Every unflipped entry must still name such a target.
2. Attribute (exit 1). Every other target of every kind (`test = false` ones included: a `#[test]`
   there never runs either) is compiled with `--test` under clippy::disallowed_macros, configured
   by .github/libtest-guard/clippy.toml. A plain `cargo clippy` does not see these: the attribute
   is gone before lints run unless the target is compiled as a test through
   `cargo rustc ... -- --test` with clippy-driver as the workspace wrapper. Findings are read from
   `--message-format=json`. The lint is forbidden (-F), so a crate-level `allow` is a compile
   error rather than a silencer, and a compile that fails without a finding fails the guard.

A `[[test]]` target (`--test=`) is type-checked, not built: the lint needs only the expanded
program. Every other kind (lib, bins, examples, benches), `test = true` or not, is built in the
debug test profile, with the final link replaced by `true`, so a cross-triple run needs a cross
linker and C compiler for build scripts and helper bins. The release profile is that same profile with debug assertions off, which
is the only difference in `cfg` between the two (the workspace sets no `[profile]` keys).

Limit: the guard compiles each target with cfg(test) on. Code written to hide a test from
cfg(test), such as `#[cfg_attr(not(test), test)]`, is not seen.

Needs cargo-hack for --feature-powerset.
"""

import argparse
import json
import os
import posixpath
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

CONF_DIR = Path(__file__).resolve().parent.parent / "libtest-guard"
LIB_KINDS = {"lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro"}


@dataclass
class Target:
    manifest: str
    flag: str
    harness: bool


@dataclass
class Run:
    cmd: list[str]
    rc: int
    findings: set[tuple[str, int]] = field(default_factory=set)
    errors: list[str] = field(default_factory=list)
    bad_lines: list[str] = field(default_factory=list)


def read_unflipped(path: Path) -> set[str]:
    lines = (line.split("#", 1)[0].strip() for line in path.read_text().splitlines())
    return {line for line in lines if line}


def plan(packages: list[dict], unflipped: set[str]) -> tuple[list[Target], list[str]]:
    """The targets to compile, and the manifest errors."""
    errors: list[str] = []
    default_harness_tests: set[str] = set()
    targets: list[Target] = []
    for package in packages:
        manifest = tomllib.loads(Path(package["manifest_path"]).read_text())
        for t in package["targets"]:
            kind = t["kind"][0]
            if kind == "custom-build":
                continue
            if LIB_KINDS & set(t["kind"]):
                kind = "lib"
                flag, table = "--lib", [manifest.get("lib", {})]
            elif kind in ("bin", "test", "example", "bench"):
                flag = f"--{kind}={t['name']}"
                table = [e for e in manifest.get(kind, []) if e.get("name") == t["name"]]
            else:
                errors.append(f"target {t['name']}: unknown kind {t['kind']}")
                continue
            # cargo metadata does not carry `harness`; it defaults to true, as cargo's does.
            harness = table[0].get("harness", True) if table else True
            key = f"{kind}:{t['name']}"
            if t["test"] and harness:
                default_harness_tests.add(key)
                if key not in unflipped:
                    errors.append(
                        f"target {t['name']} ({kind}) uses the default libtest harness: set `harness = false` "
                        f"and run it under skuld, or list `{key}` in .github/libtest-guard/unflipped.txt"
                    )
                continue
            targets.append(Target(package["manifest_path"], flag, harness))
    for entry in sorted(unflipped - default_harness_tests):
        errors.append(
            f"stale UNFLIPPED entry: {entry} (no such test target with the default harness; "
            "delete it from the unflipped file)"
        )
    return targets, errors


def commands(args: argparse.Namespace, t: Target, release: bool) -> list[list[str]]:
    # A `[[test]]` target (`--test=`) is type-checked (`--profile check`), not built: the lint needs
    # only the expanded program. The other kinds are test-compiled by `--profile test`, which also
    # brings in the dev-dependencies a check-mode unit would lack. Release is that profile with debug
    # assertions off; this holds while no `[profile]` in the workspace sets `panic`.
    profile = "check" if t.flag.startswith("--test=") else "test"
    config = ["--config", "profile.dev.debug-assertions=false"] if release else []
    tail = [*config, "--locked", "--manifest-path", t.manifest, "--message-format=json", t.flag, "--profile", profile]
    if args.target:
        tail = ["--target", args.target, *tail]
    # A `harness = true` target here is `test = false`: cargo already passes `--test` for it, and
    # a second one is rustc's "Option 'test' given more than once".
    rustc_args = ["--", *([] if t.harness else ["--test"])]
    rustc_args += ["-C", "linker=true", "-A", "warnings", "-A", "clippy::all", "-F", "clippy::disallowed_macros"]
    if not args.feature_powerset:
        features = ["--features", args.features] if args.features else []
        return [["cargo", "rustc", *features, *tail, *rustc_args]]
    powerset = ["cargo", "hack", "--feature-powerset", "--keep-going", "rustc"]
    if not args.features:
        return [[*powerset, *tail, *rustc_args]]
    # --include-features leaves out the empty combination, so it runs on its own.
    return [
        [*powerset, "--include-features", args.features, *tail, *rustc_args],
        ["cargo", "rustc", "--no-default-features", *tail, *rustc_args],
    ]


def execute(cmd: list[str], conf_dir: Path) -> Run:
    # A compiler cache (RUSTC_WRAPPER=sccache, as CI sets it) stays in front of rustc and clippy-driver.
    # sccache 0.18.0 cannot cache a `clippy-driver rustc ...` call (its argument parser sees multiple
    # inputs), so workspace crates always compile; only dependencies are served from the cache. A
    # finding is a compile error, which is never cached either.
    env = {
        **os.environ,
        "CLIPPY_CONF_DIR": str(conf_dir),
        "RUSTC_WORKSPACE_WRAPPER": "clippy-driver",
    }
    print(f"info: {' '.join(cmd)}", file=sys.stderr, flush=True)
    done = subprocess.run(cmd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE)
    run = Run(cmd, done.returncode)
    for line in done.stdout.decode("utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            m = json.loads(line)
        except ValueError:
            run.bad_lines.append(line)
            continue
        if not isinstance(m, dict) or m.get("reason") != "compiler-message":
            continue
        msg = m["message"]
        if (msg.get("code") or {}).get("code") == "clippy::disallowed_macros":
            for s in msg["spans"]:
                if s["is_primary"]:
                    run.findings.add((posixpath.normpath(s["file_name"].replace("\\", "/")), s["line_start"]))
        elif msg.get("level") in ("error", "error: internal compiler error"):
            run.errors.append(msg.get("rendered") or msg.get("message", ""))
    return run


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--target", help="target triple, as for clippy.sh")
    p.add_argument("--feature-powerset", action="store_true")
    p.add_argument("--release", action="store_true", help="check the release profile")
    p.add_argument("--both-profiles", action="store_true", help="check debug, then release")
    p.add_argument("--features", help="the features to enable; with --feature-powerset, the ones it is over")
    p.add_argument("--manifest-path")
    p.add_argument("--unflipped", type=Path, default=CONF_DIR / "unflipped.txt")
    p.add_argument("--findings-json", type=Path, help="write the unique {file, line} of every finding here")
    args = p.parse_args()

    meta_cmd = ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"]
    if args.manifest_path:
        meta_cmd += ["--manifest-path", args.manifest_path]
    packages = json.loads(subprocess.run(meta_cmd, check=True, stdout=subprocess.PIPE).stdout)["packages"]
    targets, errors = plan(packages, read_unflipped(args.unflipped))
    if errors:
        for e in errors:
            print(f"::error::{e}", file=sys.stderr)
        return 2

    profiles = [False, True] if args.both_profiles else [args.release]
    runs = [
        execute(cmd, CONF_DIR)
        for release in profiles
        for t in targets
        for cmd in commands(args, t, release)
    ]

    findings = {f for r in runs for f in r.findings}
    if args.findings_json:
        args.findings_json.write_text(json.dumps([{"file": f, "line": n} for f, n in sorted(findings)]))
    bad = False
    for f, n in sorted(findings):
        print(
            f"::error file={f},line={n}::libtest attribute (#[test] or #[tokio::test]) in a harness = false "
            "target never runs: use #[skuld::test]",
            file=sys.stderr,
        )
    for r in runs:
        if r.rc != 0 and not r.findings:
            print(f"::error::{' '.join(r.cmd)} failed without a libtest-attribute finding", file=sys.stderr)
            bad = True
        if r.rc != 0:
            for e in r.errors:
                print(e, file=sys.stderr)
        for line in r.bad_lines:
            print(f"::error::{' '.join(r.cmd)} printed a line that is not JSON: {line}", file=sys.stderr)
            bad = True
    return 1 if findings or bad else 0


if __name__ == "__main__":
    sys.exit(main())
