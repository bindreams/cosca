# Wipes the upload staging directory before the "file" provisioner re-uploads into it.
#
# Vagrant's WinRM "file" provisioner upload is additive-only (it copies each file in the
# source but never deletes a destination file the source no longer has) — so without this,
# re-running `devvm.py sync` would leave files deleted on the host still present in the
# guest's staging copy, and from there in C:\cosca after the mirror step. Wiping the staging
# directory first makes the upload-into-empty-dir always produce an exact copy of the host's
# staged tree, which windows-mirror-tree.ps1 then mirrors (with deletions) into C:\cosca.

$ErrorActionPreference = "Stop"
$stagePath = "C:\cosca-stage"

if (Test-Path $stagePath) {
    Remove-Item -Path $stagePath -Recurse -Force
}
