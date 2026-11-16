# Runs the DRIVE_MAPPING group's tests, the ones that map a drive letter (`DefineDosDeviceW`, visible to the whole logon
# session).
#
# Usage: drive-mapping-lane.ps1 <target>
# Run it from the checkout, on a machine that is a sandbox (a CI runner, a devvm guest): the group consents here. CI
# runs it under `run-nextest.ps1 drive-mapping`, which selects the nextest profile and collects the JUnit file.
$ErrorActionPreference = 'Stop'

$target = $args[0]
if (-not $target) { throw 'usage: drive-mapping-lane.ps1 <target>' }

$env:COSCA_TEST_DRIVE_MAPPING = '1'
$env:COSCA_TEST_DRIVE_MAPPING_CONSENT = '1'
$env:SKULD_LABELS = 'drive_mapping'
cargo nextest run --locked --target $target --test windows_process_cwd --no-tests=fail
exit $LASTEXITCODE
