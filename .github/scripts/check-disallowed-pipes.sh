#!/usr/bin/env bash
# Regression check for the root clippy.toml's pipe ban: runs clippy on the standalone
# .github/fixtures/disallowed-pipes crate (which calls every banned path) against the REAL root
# clippy.toml (via CLIPPY_CONF_DIR, not a copy), and asserts a clippy::disallowed_methods
# diagnostic for each path clippy.toml lists. Reads --message-format=json, not clippy's rendered
# text, so it fails loudly instead of silently passing if the `disallowed-methods` key is renamed,
# a path is typo'd, or a dependency upgrade moves a function — any of which would otherwise leave
# the ban a silent no-op.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
fixture_manifest="${repo_root}/.github/fixtures/disallowed-pipes/Cargo.toml"

# Kept in sync by hand with the root clippy.toml's disallowed-methods list.
expected_paths=(
    "libc::pipe"
    "nix::unistd::pipe"
    "rustix::pipe::pipe"
)

json_output="$(mktemp)"
fixture_target="$(mktemp -d)"
trap 'rm -f "${json_output}"; rm -rf "${fixture_target}"' EXIT

# clippy exits non-zero when disallowed_methods fires (that's the point, under -D warnings) — the
# JSON diagnostics below are the pass/fail signal here, not this exit status. Not --locked: the
# fixture's Cargo.lock isn't tracked (see .gitignore), so it resolves fresh every run.
CARGO_TARGET_DIR="${fixture_target}" \
    CLIPPY_CONF_DIR="${repo_root}" \
    cargo clippy \
    --manifest-path "${fixture_manifest}" \
    --message-format=json \
    -- -D warnings \
    >"${json_output}" || true

failures=0
for path in "${expected_paths[@]}"; do
    if jq -e --arg path "${path}" '
            select(.reason == "compiler-message")
            | .message
            | select(.code.code == "clippy::disallowed_methods")
            | select(.message == "use of a disallowed method `" + $path + "`")
        ' "${json_output}" >/dev/null; then
        echo "ok   - clippy::disallowed_methods fired for ${path}"
    else
        echo "FAIL - clippy::disallowed_methods did not fire for ${path} (ban silently broken?)"
        failures=$((failures + 1))
    fi
done

if [[ "${failures}" -gt 0 ]]; then
    echo "::error::${failures} disallowed-methods path(s) in clippy.toml no longer fire" >&2
    exit 1
fi

echo "all ${#expected_paths[@]} disallowed-methods paths fire correctly"
