# Ensures the devvm Windows guest exposes UAC in its default, interactive-consent state,
# and that the account this tool connects as is an ordinary Administrators member — not the
# built-in RID-500 Administrator, which Windows elevates silently, without a UAC prompt,
# regardless of EnableLUA. Idempotent: safe to re-run on every `vagrant up --provision`.
#
# ConsentPromptBehaviorAdmin is only flipped away from the interactive default (5) when
# DEVVM_WINDOWS_AUTO_CONSENT=1 is set — see scripts/devvm.py's --allow-elevation flag and
# scripts/README.md#windows-guests. Never flipped silently.

$ErrorActionPreference = "Stop"
$policyKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

# 1. UAC itself stays on. Some eval/vanilla box images ship with it toggled off; force it
#    back to the Windows default so `runas` from an unelevated process actually goes through
#    Admin Approval Mode — the behaviour this VM exists to measure.
Set-ItemProperty -Path $policyKey -Name "EnableLUA" -Value 1 -Type DWord

# 2. Confirm the connecting account isn't the built-in Administrator (SID ...-500). Bento's
#    Windows boxes provision a "vagrant" local-admin account distinct from the built-in
#    Administrator; fail loudly instead of silently testing the wrong account if that ever
#    changes upstream.
$account = Get-LocalUser -Name $env:USERNAME -ErrorAction SilentlyContinue
if ($null -eq $account) {
    throw "devvm: could not resolve local account '$($env:USERNAME)' - cannot verify it isn't the built-in Administrator"
}
if ($account.SID.Value.EndsWith("-500")) {
    throw "devvm: the account this tool connects as ('$($env:USERNAME)') is the built-in Administrator (RID 500), which Windows elevates without a UAC prompt. This box no longer matches the 'ordinary admin, UAC on' guest this tool promises - update scripts/devvm/guests/windows-x64/Vagrantfile to connect as a non-built-in admin account."
}
$members = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
$isAdmin = @($members | Where-Object { $_.Name -like "*\$($env:USERNAME)" -or $_.Name -eq $env:USERNAME }).Count -gt 0
if (-not $isAdmin) {
    throw "devvm: account '$($env:USERNAME)' is not a member of Administrators"
}

# 3. The opt-in toggle: auto-approve consent (no secure-desktop prompt) for unattended probe
#    runs. Off (Windows default: prompt) unless the developer explicitly asked for it.
$autoConsent = $env:DEVVM_WINDOWS_AUTO_CONSENT -eq "1"
$consentValue = if ($autoConsent) { 0 } else { 5 }
Set-ItemProperty -Path $policyKey -Name "ConsentPromptBehaviorAdmin" -Value $consentValue -Type DWord

if ($autoConsent) {
    Write-Host "devvm: UAC consent auto-approve is ON (ConsentPromptBehaviorAdmin=0) - opt-in probe mode."
} else {
    Write-Host "devvm: UAC consent prompts are ON (ConsentPromptBehaviorAdmin=5) - Windows default."
}
