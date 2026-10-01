#!/usr/bin/env bash
# The libtest guard: a `harness = false` target never runs libtest's `#[test]` or `#[tokio::test]`
# (the attribute is stripped), so such a test would silently never run. Two checks:
#
#   1. Manifest (exit 2). Every `test = true` target must be `harness = false` in Cargo.toml, or be
#      listed in the unflipped file as `<kind>:<name>` (`lib:cosca`, `test:spawn_io`, `bin:tool`).
#      Every unflipped entry must still name such a target.
#   2. Attribute (exit 1). Every other target of every kind (`test = false` ones included: a
#      `#[test]` there never runs either) is compiled with `--test` under clippy::disallowed_macros,
#      configured by .github/libtest-guard/clippy.toml. A plain `cargo clippy` does not see these:
#      the attribute is gone before lints run unless the target is compiled as a test through
#      `cargo rustc ... -- --test` with clippy-driver as the workspace wrapper. Findings are read
#      from `--message-format=json`, not scraped from rendered text. The lint is forbidden (-F), so
#      a crate-level `allow` is a compile error rather than a silencer; a compile that fails
#      without a finding fails the guard.
#
# The final link is replaced by `true`: nothing runs the binary, so the guard needs no linker and
# can check any target triple from any host.
#
# Usage: libtest-guard.sh [--target TRIPLE] [--feature-powerset] [--release] [--features F]
#                         [--manifest-path P] [--unflipped FILE] [--findings-json OUT]
#
# --features F: the features to enable; with --feature-powerset, the features the powerset is over.
# --findings-json OUT: written with a JSON array of the unique {file, line} of every finding.
# --target/--feature-powerset/--release mean what they mean to clippy.sh, which calls this script.
#
# Needs python3 (>= 3.11, for tomllib) and cargo-hack for --feature-powerset.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# `pwd -W` is the native Windows form under Git Bash (cargo and clippy-driver are native programs
# and a `/d/a/...` path in CLIPPY_CONF_DIR names no directory to them); elsewhere it fails and
# plain `pwd` is used.
conf_dir="$(cd "${script_dir}/../libtest-guard" && { pwd -W 2>/dev/null || pwd; })"

target=""
powerset=0
release=0
features=""
manifest_path=""
unflipped="${conf_dir}/unflipped.txt"
findings_json=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)
            target="${2:?--target requires a value}"
            shift 2
            ;;
        --feature-powerset)
            powerset=1
            shift
            ;;
        --release)
            release=1
            shift
            ;;
        --features)
            features="${2:?--features requires a value}"
            shift 2
            ;;
        --manifest-path)
            manifest_path="${2:?--manifest-path requires a value}"
            shift 2
            ;;
        --unflipped)
            unflipped="${2:?--unflipped requires a value}"
            shift 2
            ;;
        --findings-json)
            findings_json="${2:?--findings-json requires a value}"
            shift 2
            ;;
        *)
            echo "::error::Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

work="$(mktemp -d)"
trap 'rm -rf "${work:?}"' EXIT

metadata_cmd=(cargo metadata --locked --no-deps --format-version 1)
if [[ -n "${manifest_path}" ]]; then
    metadata_cmd+=(--manifest-path "${manifest_path}")
fi
"${metadata_cmd[@]}" >"${work}/metadata.json"

# Manifest checks, and the list of targets to compile: one `manifest<TAB>cargo flag<TAB>harness`
# line per target. Exit status 2 on a manifest error. `harness` is read from Cargo.toml (cargo
# metadata does not carry it) and defaults to true, as cargo's does.
python3 - "${unflipped}" "${work}/metadata.json" >"${work}/targets.tsv" <<'PY'
import json, sys, tomllib

# Python on Windows would end each line with CRLF, and bash would read the CR into `harness`.
sys.stdout.reconfigure(newline="\n")

unflipped_path, metadata_path = sys.argv[1:3]
with open(unflipped_path) as f:
    unflipped = {line.strip() for line in f if line.strip() and not line.startswith("#")}
with open(metadata_path) as f:
    packages = json.load(f)["packages"]

LIB_KINDS = {"lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro"}
errors = []
default_harness_tests = set()
rows = []

for package in packages:
    with open(package["manifest_path"], "rb") as f:
        manifest = tomllib.load(f)
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
        rows.append((package["manifest_path"], flag, harness))

for entry in sorted(unflipped - default_harness_tests):
    errors.append(
        f"stale UNFLIPPED entry: {entry} (no such test target with the default harness; delete it from the unflipped file)"
    )

if errors:
    for e in errors:
        print(f"::error::{e}", file=sys.stderr)
    sys.exit(2)
for manifest_path, flag, harness in rows:
    print(f"{manifest_path}\t{flag}\t{'true' if harness else 'false'}")
PY

n=0
while IFS=$'\t' read -r pkg_manifest flag harness; do
    n=$((n + 1))
    # A `test = true` target is compiled in the profile that makes it a test target; the other kinds
    # are test-compiled by `--profile test` (debug) or `--profile bench` (release).
    case "${flag}" in
        --test=*) profile=$([[ "${release}" -eq 1 ]] && echo release || echo check) ;;
        *) profile=$([[ "${release}" -eq 1 ]] && echo bench || echo test) ;;
    esac

    cmd=(cargo)
    if [[ "${powerset}" -eq 1 ]]; then
        cmd+=(hack --feature-powerset rustc)
        [[ -n "${features}" ]] && cmd+=(--include-features "${features}")
    else
        cmd+=(rustc)
        [[ -n "${features}" ]] && cmd+=(--features "${features}")
    fi
    [[ -n "${target}" ]] && cmd+=(--target "${target}")
    cmd+=(--locked --manifest-path "${pkg_manifest}" --message-format=json "${flag}" --profile "${profile}" --)

    # A `harness = true` target here is `test = false`: cargo already passes `--test` for it, and a
    # second one is rustc's "Option 'test' given more than once".
    [[ "${harness}" == "false" ]] && cmd+=(--test)
    cmd+=(-C linker=true -A warnings -A clippy::all -F clippy::disallowed_macros)

    printf '%s\n' "${cmd[*]}" >"${work}/run-${n}.cmd"
    rc=0
    # A compiler cache in front of clippy-driver (CI sets RUSTC_WRAPPER=sccache; cargo config can set
    # build.rustc-wrapper) replays no lints, so the guard overrides both with an empty wrapper.
    env RUSTC_WRAPPER= CARGO_BUILD_RUSTC_WRAPPER= CLIPPY_CONF_DIR="${conf_dir}" \
        RUSTC_WORKSPACE_WRAPPER=clippy-driver "${cmd[@]}" >"${work}/run-${n}.json" </dev/null || rc=$?
    echo "${rc}" >"${work}/run-${n}.rc"
done <"${work}/targets.tsv"

# The report: every unique finding; a compile that failed without one fails the guard too.
python3 - "${work}" "${findings_json}" <<'PY'
import glob, json, os, posixpath, sys

work, out = sys.argv[1:3]
findings = set()
failed = []
for rc_path in sorted(glob.glob(os.path.join(work, "run-*.rc"))):
    base = rc_path[: -len(".rc")]
    with open(rc_path) as f:
        rc = int(f.read())
    mine = set()
    with open(base + ".json", errors="replace") as f:
        for line in f:
            try:
                m = json.loads(line)
            except ValueError:
                continue
            if not isinstance(m, dict) or m.get("reason") != "compiler-message":
                continue
            msg = m["message"]
            if (msg.get("code") or {}).get("code") != "clippy::disallowed_macros":
                continue
            for s in msg["spans"]:
                if s["is_primary"]:
                    mine.add((posixpath.normpath(s["file_name"].replace("\\", "/")), s["line_start"]))
    if rc != 0 and not mine:
        with open(base + ".cmd") as f:
            failed.append(f.read().strip())
    findings |= mine

result = [{"file": f, "line": l} for f, l in sorted(findings)]
if out:
    with open(out, "w") as f:
        json.dump(result, f)
for f, l in sorted(findings):
    print(
        f"::error file={f},line={l}::libtest attribute (#[test] or #[tokio::test]) in a harness = false target "
        "never runs: use #[skuld::test]",
        file=sys.stderr,
    )
for cmd in failed:
    print(f"::error::{cmd} failed without a libtest-attribute finding", file=sys.stderr)
sys.exit(1 if findings or failed else 0)
PY
