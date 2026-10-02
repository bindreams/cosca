#!/usr/bin/env bash
# Regression check for the root clippy.toml's disallowed-methods bans (pipes, raw spawns, tokio
# timers and process-cwd mutators).
# Runs clippy on the standalone .github/fixtures/disallowed-methods crate, which calls every
# banned path, against the REAL root clippy.toml (via CLIPPY_CONF_DIR, not a copy), and asserts a
# clippy::disallowed_methods diagnostic for each path clippy.toml lists. Reads
# --message-format=json, not clippy's rendered text, so it fails loudly instead of silently
# passing if the `disallowed-methods` key is renamed, a path is typo'd, or a dependency upgrade
# moves a function.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
fixture_manifest="${repo_root}/.github/fixtures/disallowed-methods/Cargo.toml"

# Kept in sync by hand with the root clippy.toml's disallowed-methods list; the check below fails
# if the two differ in either direction, so a new ban cannot land without a fixture call. Clippy
# skips a path whose crate isn't linked for the target, so each pass pins its target and lists the
# paths reachable there, so the result does not depend on the runner OS. Plain `cargo clippy
# --target` type-checks with the target's std (`rustup target add`); no linker or Windows SDK.
linux_target="x86_64-unknown-linux-gnu"
linux_paths=(
    "libc::pipe"
    "nix::unistd::pipe"
    "rustix::pipe::pipe"
    "std::process::Command::spawn"
    "std::process::Command::output"
    "std::process::Command::status"
    "tokio::process::Command::spawn"
    "tokio::process::Command::output"
    "tokio::process::Command::status"
    "tokio::time::timeout"
    "tokio::time::timeout_at"
    "tokio::time::sleep"
    "tokio::time::sleep_until"
    "tokio::time::interval"
    "tokio::time::interval_at"
    "tokio::time::Sleep::reset"
    "tokio::time::Interval::reset"
    "tokio::time::Interval::reset_immediately"
    "tokio::time::Interval::reset_after"
    "tokio::time::Interval::reset_at"
    "std::env::set_current_dir"
    "libc::chdir"
    "libc::fchdir"
    "libc::daemon"
    "nix::unistd::daemon"
    "nix::unistd::chdir"
    "nix::unistd::fchdir"
    "rustix::process::chdir"
    "rustix::process::fchdir"
    "rustix::fs::Dir::chdir"
)
# macOS: `nix::unistd::daemon` is absent there, `libc::daemon` is a different (Apple) item.
darwin_target="aarch64-apple-darwin"
darwin_paths=(
    "libc::pipe"
    "nix::unistd::pipe"
    "std::process::Command::spawn"
    "std::process::Command::output"
    "std::process::Command::status"
    "tokio::process::Command::spawn"
    "tokio::process::Command::output"
    "tokio::process::Command::status"
    "tokio::time::timeout"
    "tokio::time::timeout_at"
    "tokio::time::sleep"
    "tokio::time::sleep_until"
    "tokio::time::interval"
    "tokio::time::interval_at"
    "tokio::time::Sleep::reset"
    "tokio::time::Interval::reset"
    "tokio::time::Interval::reset_immediately"
    "tokio::time::Interval::reset_after"
    "tokio::time::Interval::reset_at"
    "std::env::set_current_dir"
    "libc::chdir"
    "libc::fchdir"
    "libc::daemon"
    "nix::unistd::chdir"
    "nix::unistd::fchdir"
)
windows_target="x86_64-pc-windows-msvc"
windows_paths=(
    "std::process::Command::spawn"
    "std::process::Command::output"
    "std::process::Command::status"
    "tokio::process::Command::spawn"
    "tokio::process::Command::output"
    "tokio::process::Command::status"
    "tokio::time::timeout"
    "tokio::time::timeout_at"
    "tokio::time::sleep"
    "tokio::time::sleep_until"
    "tokio::time::interval"
    "tokio::time::interval_at"
    "tokio::time::Sleep::reset"
    "tokio::time::Interval::reset"
    "tokio::time::Interval::reset_immediately"
    "tokio::time::Interval::reset_after"
    "tokio::time::Interval::reset_at"
    "std::env::set_current_dir"
    "libc::chdir"
    "windows::Win32::System::Environment::SetCurrentDirectoryA"
    "windows::Win32::System::Environment::SetCurrentDirectoryW"
    "windows_sys::Win32::System::Environment::SetCurrentDirectoryA"
    "windows_sys::Win32::System::Environment::SetCurrentDirectoryW"
)

listed="$(python3 -c '
import sys, tomllib
with open(sys.argv[1], "rb") as f:
    print("\n".join(e["path"] for e in tomllib.load(f)["disallowed-methods"]))
' "${repo_root}/clippy.toml" | LC_ALL=C sort)"
expected="$(printf '%s\n' "${linux_paths[@]}" "${darwin_paths[@]}" "${windows_paths[@]}" | LC_ALL=C sort -u)"
if [[ "${listed}" != "${expected}" ]]; then
    echo "::error::clippy.toml's disallowed-methods and this script's path lists differ:" >&2
    diff <(echo "${listed}") <(echo "${expected}") >&2 || true
    exit 1
fi

json_output="$(mktemp)"
fixture_target="$(mktemp -d)"
trap 'rm -f "${json_output}"; rm -rf "${fixture_target:?}"' EXIT

failures=0
checked=0

# check_pass LABEL TARGET PATH...: lints the fixture for TARGET and requires a
# clippy::disallowed_methods diagnostic for each PATH. clippy exits non-zero when
# disallowed_methods fires (that's the point, under -D warnings) — the JSON diagnostics are the
# pass/fail signal here, not its exit status. --locked: the fixture's Cargo.lock is tracked and
# pinned to the root's versions, so a crate release cannot change the result unannounced.
check_pass() {
    local label="$1" target="$2"
    shift 2
    CARGO_TARGET_DIR="${fixture_target}" \
        CLIPPY_CONF_DIR="${repo_root}" \
        cargo clippy --locked \
        --manifest-path "${fixture_manifest}" \
        --target "${target}" \
        --message-format=json \
        -- -D warnings \
        >"${json_output}" || true

    # Surface compile errors (anything but the expected disallowed_methods hits), else a fixture
    # that fails to build just reports every ban as silently broken.
    jq -r 'select(.reason == "compiler-message") | .message
        | select(.level == "error" and .code.code != "clippy::disallowed_methods")
        | .rendered' "${json_output}" >&2

    local path
    for path in "$@"; do
        checked=$((checked + 1))
        if jq -e --arg path "${path}" '
                select(.reason == "compiler-message")
                | .message
                | select(.code.code == "clippy::disallowed_methods")
                | select(.message == "use of a disallowed method `" + $path + "`")
            ' "${json_output}" >/dev/null; then
            echo "ok   - [${label}] clippy::disallowed_methods fired for ${path}"
        else
            echo "FAIL - [${label}] clippy::disallowed_methods did not fire for ${path} (ban silently broken?)"
            failures=$((failures + 1))
        fi
    done
}

check_pass linux "${linux_target}" "${linux_paths[@]}"
check_pass darwin "${darwin_target}" "${darwin_paths[@]}"
check_pass windows "${windows_target}" "${windows_paths[@]}"

if [[ "${failures}" -gt 0 ]]; then
    echo "::error::${failures} disallowed-methods path(s) in clippy.toml no longer fire" >&2
    exit 1
fi

echo "all ${checked} disallowed-methods checks fire correctly"
