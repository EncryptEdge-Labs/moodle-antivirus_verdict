# Live VirusTotal certification (operator opt-in). Does not store API keys in the repo.
# Reuses VERDICT_LVT_API_KEY or the apikey saved in the Behat site (config_plugins).
#
# Usage:
#   $env:VERDICT_LVT_OPT_IN = '1'
#   .\scripts\run-live-vt-cert.ps1
# Optional: $env:VERDICT_LVT_BEHAT_BRANCH = '502'

$ErrorActionPreference = 'Stop'
if (-not $env:VERDICT_LVT_OPT_IN -or $env:VERDICT_LVT_OPT_IN.Trim() -ne '1') {
    Write-Error 'Set VERDICT_LVT_OPT_IN=1 before running live VirusTotal certification.'
}

$pluginRoot = Split-Path -Parent $PSScriptRoot
$verify = & 'C:\Tools\php84\php.exe' "$pluginRoot\scripts\behat-verify-vt-credential.php" 501
if ($LASTEXITCODE -ne 0) {
    $verify = & 'C:\Tools\php84\php.exe' "$pluginRoot\scripts\behat-verify-vt-credential.php" 502
}
Write-Host $verify

& 'C:\Tools\php84\php.exe' "$pluginRoot\scripts\run-live-vt-cert.php"
exit $LASTEXITCODE
