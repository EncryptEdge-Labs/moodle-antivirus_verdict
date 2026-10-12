# Quick release QA progress (no secrets). Run from plugin root:
#   powershell -File scripts/qa-progress-report.ps1

$ErrorActionPreference = 'SilentlyContinue'
$root = Split-Path -Parent $PSScriptRoot
$logDir = Join-Path $root 'qa-logs'
Write-Host "Verdict QA progress - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
Write-Host "Log directory: $logDir"
Write-Host ""

function Show-Latest($pattern, $label) {
    $files = Get-ChildItem (Join-Path $logDir $pattern) | Sort-Object LastWriteTime -Descending
    if (-not $files) {
        Write-Host "[$label] No logs matching $pattern"
        return
    }
    $f = $files[0]
    Write-Host "[$label] $($f.Name) ($(Get-Date $f.LastWriteTime -Format 'yyyy-MM-dd HH:mm'))"
    Select-String -Path $f.FullName -Pattern 'Tests:|18 scenarios|Exit code:|ERRORS!|OK,|FAILURES!' |
        Select-Object -Last 6 | ForEach-Object { Write-Host ('  ' + $_.Line.Trim()) }
    Write-Host ""
}

Show-Latest 'phpunit-moodle-405-*.log' 'PHPUnit 405'
Show-Latest 'phpunit-moodle-500-*.log' 'PHPUnit 500'
Show-Latest 'phpunit-moodle-501-*.log' 'PHPUnit 501'
Show-Latest 'phpunit-moodle-502-*.log' 'PHPUnit 502'
Show-Latest 'behat-run-all-moodles-*.log' 'Behat aggregate'
Show-Latest 'live-vt-cert-501-*.log' 'Live VT cert'

Write-Host 'Tip: tail a log while a run is active:'
Write-Host '  Get-Content -Wait qa-logs\behat-run-502-*.log -Tail 5'
