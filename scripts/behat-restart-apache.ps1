#Requires -RunAsAdministrator
# Reload Apache after editing httpd-moodle-vhosts.conf (e.g. per-vhost PHP for behat501.local).
$httpd = 'C:\Tools\Apache24\bin\httpd.exe'
if (-not (Test-Path $httpd)) {
    Write-Error "Apache not found at $httpd"
    exit 1
}
& $httpd -t
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $httpd -k restart
exit $LASTEXITCODE
