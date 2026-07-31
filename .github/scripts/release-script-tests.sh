#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
normalize="${script_dir}/normalize-version.sh"
assert_tag="${script_dir}/assert-tag-absent.sh"
failures=0

# Asserts BOTH stdout and exit status. Checking stdout alone would pass a
# script that printed the right version and then exited non-zero — which the
# workflows consume under `set -euo pipefail`, so it would halt a release.
assert_accepts() {
    local description="$1" expected="$2" input="$3"
    local actual status=0
    actual="$(bash "$normalize" "$input" 2>/dev/null)" || status=$?
    if [[ "$status" -eq 0 && "$actual" == "$expected" ]]; then
        echo "ok   - ${description}"
    else
        echo "FAIL - ${description} (expected '${expected}' status 0, got '${actual}' status ${status})"
        failures=$((failures + 1))
    fi
}

assert_rejects() {
    local description="$1" input="$2"
    if bash "$normalize" "$input" >/dev/null 2>&1; then
        echo "FAIL - ${description} (expected rejection, got success)"
        failures=$((failures + 1))
    else
        echo "ok   - ${description}"
    fi
}

# normalize-version.sh -----------------------------------------------------

assert_accepts "passes a bare semver core"    "0.1.0"    "0.1.0"
assert_accepts "strips a leading v"           "0.1.0"    "v0.1.0"
assert_accepts "accepts multi-digit parts"    "10.20.30" "10.20.30"
assert_rejects "rejects a prerelease suffix"  "1.2.3-rc1"
assert_rejects "rejects build metadata"       "1.2.3+build"
assert_rejects "rejects two components"       "0.1"
assert_rejects "rejects four components"      "0.1.0.0"
assert_rejects "rejects an empty string"      ""
assert_rejects "rejects trailing whitespace"  "0.1.0 "
assert_rejects "rejects a command injection"  '0.1.0; rm -rf /'
assert_rejects "rejects a doubled v"          "vv0.1.0"
# v01.2.3 and v1.2.3 are different git tags, so a non-canonical component
# would silently produce a tag nobody expects.
assert_rejects "rejects a leading zero"       "01.2.3"
assert_rejects "rejects an inner leading zero" "1.02.3"

# assert-tag-absent.sh -----------------------------------------------------
# Drives the script against a stub `git` that exits with a chosen status, so
# all three branches are exercised without touching a real remote.

stub_dir="$(mktemp -d)"
trap 'rm -rf "$stub_dir"' EXIT

make_git_stub() {
    local exit_code="$1"
    cat > "${stub_dir}/git" <<EOF
#!/usr/bin/env bash
exit ${exit_code}
EOF
    chmod +x "${stub_dir}/git"
}

assert_tag_result() {
    local description="$1" git_exit="$2" want_success="$3"
    make_git_stub "$git_exit"
    if PATH="${stub_dir}:${PATH}" bash "$assert_tag" v0.1.0 >/dev/null 2>&1; then
        [[ "$want_success" == "yes" ]] && echo "ok   - ${description}" && return 0
    else
        [[ "$want_success" == "no" ]] && echo "ok   - ${description}" && return 0
    fi
    echo "FAIL - ${description} (git exit ${git_exit}, wanted success=${want_success})"
    failures=$((failures + 1))
}

assert_tag_result "tag present (git exit 0) is refused"        0   no
assert_tag_result "tag absent (git exit 2) is accepted"        2   yes
assert_tag_result "transient failure (git exit 1) is refused"  1   no
assert_tag_result "auth failure (git exit 128) is refused"     128 no

# --------------------------------------------------------------------------

if [[ "$failures" -gt 0 ]]; then
    echo "${failures} test(s) failed"
    exit 1
fi
echo "all tests passed"
