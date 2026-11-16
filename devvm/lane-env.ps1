# Dot-sourced by a Windows lane command (`devvm/README.md`) before it runs tests, so the lane sees what a CI lane sees.
#
# The groups that are off by default are off here as in CI: `.github/test-group-defaults.env`, which the CI jobs apply to
# their environment; a lane turns on its own. A Windows guest's kernel has no floor to check.
foreach ($line in Get-Content -LiteralPath (Join-Path $PSScriptRoot '../.github/test-group-defaults.env')) {
    if ($line -match '^\s*(#|$)') { continue }
    $name, $value = $line -split '=', 2
    Set-Item -LiteralPath "Env:$name" -Value $value
}
