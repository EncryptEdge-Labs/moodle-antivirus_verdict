# Live VirusTotal certification (GAP-008). Does not store API keys in the repo.
# Usage:
#   $env:VERDICT_LVT_API_KEY = '<your-key>'
#   .\scripts\run-live-vt-cert.ps1

$ErrorActionPreference = 'Stop'
if (-not $env:VERDICT_LVT_API_KEY -or $env:VERDICT_LVT_API_KEY.Trim() -eq '') {
    Write-Error 'Set VERDICT_LVT_API_KEY in the environment first.'
}
$cacert = 'D:\CODE\moodle-dev\public\lib\cacert.pem'
if (-not (Test-Path $cacert)) {
    Write-Error "CA bundle not found: $cacert"
}
Set-Location 'D:\CODE\moodle-dev'
& 'C:\Tools\php84\php.exe' `
    -d "curl.cainfo=$cacert" `
    -d "openssl.cafile=$cacert" `
    vendor\phpunit\phpunit\phpunit `
    --testsuite antivirus_verdict_testsuite `
    --filter live_vt_certification
