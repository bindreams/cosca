#!/usr/bin/env bash
# Self-test for libtest-guard.sh. Runs the guard on .github/fixtures/libtest-guard, a toy crate
# with one feature per case, and asserts the exit code and the (file, line) set the guard writes to
# --findings-json. The OS-gated cases assert the host's own OS only: each lint lane runs this
# script, so each OS is covered by its own lane.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
guard="${script_dir}/libtest-guard.sh"
fixture="${repo_root}/.github/fixtures/libtest-guard"
manifest="${fixture}/Cargo.toml"

work="$(mktemp -d)"
trap 'rm -rf "${work:?}"' EXIT
export CARGO_TARGET_DIR="${work}/target"

# Entries are `<kind>:<name>`. `lt` is the fixture's libtest target and `libtest-guard-fixture` its
# default-harness bin (src/main.rs); every case but the manifest ones lists both.
printf 'test:lt\nbin:libtest-guard-fixture\n' >"${work}/unflipped-lt.txt"
: >"${work}/unflipped-empty.txt"
printf 'test:lt\n' >"${work}/unflipped-no-bin.txt"
printf 'test:lt\nbin:libtest-guard-fixture\ntest:it\n' >"${work}/unflipped-stale-flipped.txt"
printf 'test:lt\nbin:libtest-guard-fixture\ntest:nope\n' >"${work}/unflipped-stale-missing.txt"
printf 'test:lt\nbin:libtest-guard-fixture\nlib:lt\n' >"${work}/unflipped-stale-kind.txt"

case "$(uname -s)" in
    Linux) host_os=linux ;;
    Darwin) host_os=macos ;;
    *) host_os=windows ;;
esac

# The same OS on the other architecture, which a `--target` run reaches and a native run does not.
host_triple="$(rustc --print host-tuple)"
case "${host_triple}" in
    x86_64-*) other_triple="aarch64-${host_triple#x86_64-}"; host_arch=x86_64; other_arch=aarch64 ;;
    aarch64-*) other_triple="x86_64-${host_triple#aarch64-}"; host_arch=aarch64; other_arch=x86_64 ;;
    *)
        echo "::error::unsupported host triple ${host_triple}" >&2
        exit 1
        ;;
esac

failures=0
checks=0

# line_of FILE PATTERN: the line of the fixture's one-line case holding PATTERN.
line_of() {
    local n
    n="$(grep -nF -m1 -- "$2" "${fixture}/$1" | cut -d: -f1)"
    if [[ -z "${n}" ]]; then
        echo "::error::fixture ${1} has no line containing '$2'" >&2
        exit 1
    fi
    echo "${n}"
}

# check NAME EXPECTED_EXIT EXPECTED_FINDINGS UNFLIPPED_FILE GUARD_ARGS...
# EXPECTED_FINDINGS is a newline-separated, sorted list of `file:line`, or empty.
check() {
    local name="$1" want_rc="$2" want_found="$3" unflipped="$4"
    shift 4
    local out="${work}/findings.json" rc=0 found
    rm -f "${out}"
    "${guard}" --manifest-path "${manifest}" --unflipped "${unflipped}" --findings-json "${out}" "$@" \
        >"${work}/stdout.log" 2>"${work}/stderr.log" || rc=$?
    found=""
    if [[ -f "${out}" ]]; then
        found="$(python3 -c 'import json, sys; print("\n".join(sorted({e["file"] + ":" + str(e["line"]) for e in json.load(open(sys.argv[1]))})))' "${out}")"
    fi
    checks=$((checks + 1))
    if [[ "${rc}" == "${want_rc}" && "${found}" == "${want_found}" ]]; then
        echo "ok   - ${name}"
    else
        echo "FAIL - ${name}: exit ${rc} (want ${want_rc}); findings:"
        echo "${found:-<none>}"
        echo "want:"
        echo "${want_found:-<none>}"
        echo "--- guard stderr:"
        cat "${work}/stderr.log"
        failures=$((failures + 1))
    fi
}

# both_targets CASE PATTERN: the findings of CASE in the lib and in the integration target.
both_targets() {
    printf 'src/lib.rs:%s\ntests/it.rs:%s\n' "$(line_of src/lib.rs "$2")" "$(line_of tests/it.rs "$2")" | LC_ALL=C sort -u
}

# The seven spellings, each in the harness = false lib and in the harness = false `it` target ----
check "clean" 0 "" "${work}/unflipped-lt.txt"
check "plain #[test]" 1 "$(both_targets plain 'fn plain')" "${work}/unflipped-lt.txt" --features plain
check "#[tokio::test]" 1 "$(both_targets tokio_test 'fn tokio_test')" "${work}/unflipped-lt.txt" --features tokio_test
check "#[core::prelude::v1::test]" 1 "$(both_targets prelude_path 'fn prelude_path')" "${work}/unflipped-lt.txt" --features prelude_path
check "#[cfg_attr(all(), test)]" 1 "$(both_targets cfg_attr_test 'fn cfg_attr_test')" "${work}/unflipped-lt.txt" --features cfg_attr_test
check "renamed import, #[t]" 1 "$(both_targets renamed 'fn renamed')" "${work}/unflipped-lt.txt" --features renamed
check "#[test] from macro_rules!" 1 "$(both_targets macro_rules 'macro_rules! emit')" "${work}/unflipped-lt.txt" --features macro_rules
# One file compiled into the lib, `it` and the libtest target `lt`: flagged once (lt is not compiled).
check "module shared with a libtest target" 1 "src/shared.rs:1" "${work}/unflipped-lt.txt" --features shared

# Release-only code ---------------------------------------------------------------------------------
check "cfg(not(debug_assertions)) test, debug" 0 "" "${work}/unflipped-lt.txt" --features release_only
check "cfg(not(debug_assertions)) test, release" 1 "$(both_targets release_only 'fn release_only')" "${work}/unflipped-lt.txt" --features release_only --release

# One OS-gated test per OS: flagged on its own OS, absent elsewhere ---------------------------------
for os in linux macos windows; do
    want=""
    if [[ "${os}" == "${host_os}" ]]; then
        want="$(both_targets "os_${os}" "fn os_${os}")"
    fi
    check "OS-gated #[tokio::test] for ${os} (host: ${host_os})" "$([[ -n "${want}" ]] && echo 1 || echo 0)" "${want}" "${work}/unflipped-lt.txt" --features "os_${os}"
done

# A `test = false` bin is still compiled as a test and checked ---------------------------------------
check "#[test] in a test = false bin" 1 "src/bin_nt.rs:$(line_of src/bin_nt.rs 'fn never_runs')" "${work}/unflipped-lt.txt" --features bin_test_false
check "#[test] in a test = false bin, release" 1 "src/bin_nt.rs:$(line_of src/bin_nt.rs 'fn never_runs')" "${work}/unflipped-lt.txt" --features bin_test_false --release

# The feature powerset flags a test in its own combination ---------------------------------------------
check "feature powerset" 1 "$({ both_targets plain 'fn plain'; both_targets tokio_test 'fn tokio_test'; } | LC_ALL=C sort -u)" "${work}/unflipped-lt.txt" --feature-powerset --features plain,tokio_test
# Flagged only with ps_a on and ps_b off: a single combined run of ps_a,ps_b never reaches it.
check "feature powerset, a proper subset" 1 "$(both_targets ps_only_a 'fn ps_only_a')" "${work}/unflipped-lt.txt" --feature-powerset --features ps_a,ps_b
check "no powerset: the combined features miss the subset-only case" 0 "" "${work}/unflipped-lt.txt" --features ps_a,ps_b

# Other architectures ------------------------------------------------------------------------------------
check "arch-gated tests, native (${host_arch})" 1 "$(both_targets "arch_${host_arch}" "fn arch_${host_arch}")" "${work}/unflipped-lt.txt" --features arch_x86_64,arch_aarch64
check "arch-gated tests, --target ${other_triple}" 1 "$(both_targets "arch_${other_arch}" "fn arch_${other_arch}")" "${work}/unflipped-lt.txt" --features arch_x86_64,arch_aarch64 --target "${other_triple}"

# A finding that cannot be silenced, and a compile that fails without one ----------------------------------
check "compile error without a finding fails" 1 "" "${work}/unflipped-lt.txt" --features type_error
check "crate-level allow(clippy::all) cannot silence the guard" 1 "" "${work}/unflipped-lt.txt" --features crate_allow

# A compiler wrapper, from the environment or from cargo config, must not sit in front of clippy-driver
RUSTC_WRAPPER=false check "RUSTC_WRAPPER is bypassed" 0 "" "${work}/unflipped-lt.txt"
CARGO_BUILD_RUSTC_WRAPPER=false check "build.rustc-wrapper is bypassed" 0 "" "${work}/unflipped-lt.txt"

# Manifest checks ---------------------------------------------------------------------------------------
# expect_stderr TEXT: the last check's guard stderr names TEXT.
expect_stderr() {
    checks=$((checks + 1))
    if ! grep -qF -- "$1" "${work}/stderr.log"; then
        echo "FAIL - the guard's message does not contain '$1':"
        cat "${work}/stderr.log"
        failures=$((failures + 1))
    fi
}

check "default-harness targets not listed" 2 "" "${work}/unflipped-empty.txt"
expect_stderr "target lt (test)"
expect_stderr "target libtest-guard-fixture (bin)"
# An entry for one kind of target does not cover another kind's target of the same name.
check "default-harness bin not listed" 2 "" "${work}/unflipped-no-bin.txt"
expect_stderr "target libtest-guard-fixture (bin)"
check "stale unflipped entry (already harness = false)" 2 "" "${work}/unflipped-stale-flipped.txt"
expect_stderr "stale UNFLIPPED entry: test:it"
check "stale unflipped entry (no such target)" 2 "" "${work}/unflipped-stale-missing.txt"
expect_stderr "stale UNFLIPPED entry: test:nope"
check "stale unflipped entry (wrong kind)" 2 "" "${work}/unflipped-stale-kind.txt"
expect_stderr "stale UNFLIPPED entry: lib:lt"

if [[ "${failures}" -gt 0 ]]; then
    echo "::error::${failures} libtest-guard self-test check(s) failed" >&2
    exit 1
fi
echo "all ${checks} libtest-guard self-test checks passed"
