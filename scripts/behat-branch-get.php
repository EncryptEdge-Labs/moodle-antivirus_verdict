<?php
/**
 * Read one field from behat-branches.json for batch scripts (avoids PowerShell path issues).
 *
 * Usage: php behat-branch-get.php 502 php
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

if (php_sapi_name() !== 'cli') {
    die('CLI only');
}

$branch = $argv[1] ?? '';
$field = $argv[2] ?? '';
$map = json_decode(file_get_contents(__DIR__ . '/behat-branches.json'), true);
unset($map['chromedriver'], $map['chrome_browser']);
if (!isset($map[$branch][$field])) {
    fwrite(STDERR, "Unknown branch/field {$branch}/{$field}\n");
    exit(1);
}
echo $map[$branch][$field];
