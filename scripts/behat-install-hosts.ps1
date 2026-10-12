#Requires -RunAsAdministrator
# Adds behat*.local entries for Moodle Behat (see scripts/behat-hosts-snippet.txt).
$hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
$entries = @(
    '127.0.0.1 behat405.local',
    '127.0.0.1 behat500.local',
    '127.0.0.1 behat501.local',
    '127.0.0.1 behat502.local'
)
$content = Get-Content $hosts -Raw
foreach ($line in $entries) {
    $host = ($line -split '\s+', 2)[1]
    if ($content -notmatch [regex]::Escape($host)) {
        Add-Content -Path $hosts -Value $line
        Write-Host "Added: $line"
    } else {
        Write-Host "Already present: $host"
    }
}
