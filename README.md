# cosca

Unified cross-platform subprocess management: spawning, stdio, process trees, stable identity, and elevation.

`std::process` hands you a child and little else. It cannot tell you whether the process you spawned is still the process you think it is, cannot tear down a process tree, cannot address a process it did not spawn, and cannot run one elevated. This crate covers those, with one API across Linux, macOS, and Windows, a `tokio` mirror behind a feature flag, and identities that can be written to disk and restored after a restart (`serde` feature).

On Linux, cosca needs `openat2` (kernel 5.6 or newer, and not blocked by a seccomp filter): it reads `/proc` only through a checked directory fd. Without it a spawn, or a by-pid identity read, fails with `Error::Unsupported` saying so.

The API is not stable; expect breaking changes in any 0.x release.

Platform requirements, including Linux 5.6 or newer, are in the crate documentation.

The design rules every change follows are in [docs/principles.md](docs/principles.md).

## Running tests

Use [`cargo nextest`](https://nexte.st/) (`cargo install cargo-nextest`), run as `cargo nextest
run`. It's what CI runs, and it's the recommended way to run cosca's suite: nextest
isolates each test in its own process, rather than sharing one process across the whole run the
way plain `cargo test` does.

The suite signals process groups and creates cgroup leaves and Job Objects, so run it in a VM
([`scripts/devvm`](scripts/README.md)), a container or CI, never directly on your machine. See
[principle 10](docs/principles.md#10-system-affecting-tests-run-in-a-sandbox).

nextest doesn't run doctests, so CI runs those separately with `cargo test --doc`. cosca has none
today. Claude Code agents in this repo deny plain `cargo test` (`.claude/settings.json`), so an
agent can't run that step locally either — it only runs in CI.

### Tests that need root

Two test groups run only as root (principles 9 and 10 in `docs/principles.md`):

- `ROOT` (`COSCA_TEST_ROOT`): the library tests that need a DAC bypass (`SKULD_LABELS=root`).
- `UID_SWITCH` (`COSCA_TEST_UID_SWITCH`): `foreign_kill_surfaces_permission_denied` in
  `tests/process_root.rs`. It runs as real root, spawns children under two other real uids and
  re-execs itself as one of them.

For each group, `=0` turns it off: the tests of `ROOT` and `UID_SWITCH` report as ignored. Otherwise `COSCA_TEST_<GROUP>_CONSENT=1` is required, and without it the test fails. An ordinary
(unprivileged) run sets both switches to `0`. CI does this workflow-wide; the root lanes in
`.github/workflows/ci.yaml` turn `ROOT` on, and turn `UID_SWITCH` on only in the lanes that are real
root (Linux root, `DAC_READ_SEARCH`, foreign `TMPDIR`, and macOS).

Run them in a throwaway container. Two steps, because `--network none` (below) cannot itself fetch anything: first a networked step
populates a named `CARGO_HOME` volume with cosca's own dependencies and `cargo-nextest` itself,
then the actual test run is fully offline and network-isolated:

```sh
( set -e
docker volume create cosca-root-test-cargo-home >/dev/null
docker volume create cosca-root-test-target >/dev/null

# 1. Networked: fetch dependencies and install cargo-nextest into the shared CARGO_HOME.
docker run --rm \
    -v "$PWD":/repo:ro \
    -v cosca-root-test-cargo-home:/usr/local/cargo \
    -v cosca-root-test-target:/target \
    -e CARGO_TARGET_DIR=/target \
    -w /repo \
    rust:1 \
    bash -c 'cargo fetch --locked && cargo install cargo-nextest --locked --quiet'

# 2. Offline and network-isolated: the two groups' tests (`PRIVILEGE_TESTS` in ci.yaml). Each
#    _CONSENT=1 consents to that group inside the sandbox; `=0` on the group would skip it.
docker run --rm --network none \
    -v "$PWD":/repo:ro \
    -v cosca-root-test-cargo-home:/usr/local/cargo:ro \
    -v cosca-root-test-target:/target \
    -e CARGO_TARGET_DIR=/target \
    -e CARGO_NET_OFFLINE=true \
    -e SKULD_LABELS=root \
    -e COSCA_TEST_ROOT_CONSENT=1 \
    -e COSCA_TEST_UID_SWITCH_CONSENT=1 \
    -w /repo \
    rust:1 \
    cargo nextest run --offline --no-tests=fail -E "binary(cosca) | binary(process_root)"
)
docker volume rm cosca-root-test-cargo-home cosca-root-test-target
```

- The container's default user is already root, so no `sudo` is needed inside it; the two
  `_CONSENT=1` variables unlock the tests' real privilege and stay inside the container. The repo
  is mounted read-only and the build goes to throwaway named volumes, so nothing on the host is
  touched.
- Don't lift the inner `cargo nextest run` out of the container and run it with `sudo` on the
  host: the consent variables are real, standing consent to switch uids and spawn/kill
  processes, and this project's own rule is that system-affecting tests run in a container or VM,
  never against this machine's own services.

## Linting

`prek` runs `.github/scripts/clippy.sh` and the libtest guard (`.github/scripts/libtest_guard.py`), a `uv` script: install [uv](https://docs.astral.sh/uv/). `cargo-hack` is needed only for `--feature-powerset`, which CI uses.

## License

<img align="right" width="150px" height="150px" src="https://www.apache.org/foundation/press/kit/img/the-apache-way-badge/ASF_Badge_apacheway-purple.png">

Copyright 2026, Anna Zhukova

This project is licensed under the Apache 2.0 license. The license text can be found at [LICENSE](/LICENSE).

`src/quote/posix.rs` is a Rust port of the `internal/foundation/shlex` package from [JetBrains qodana-cli](https://github.com/JetBrains/qodana-cli), used under that project's Apache 2.0 license.
