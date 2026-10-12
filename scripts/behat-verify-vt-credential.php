<?php
/**
 * Verify VT API key presence for Behat branch without printing the secret (CLI).
 *
 * Usage: php behat-verify-vt-credential.php [502]
 * Exit 0 = configured (env or Behat DB); exit 1 = missing.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require __DIR__ . '/live-vt-credential-resolver.php';

$branch = $argv[1] ?? '';
$sources = [];
if (is_string(getenv('VERDICT_LVT_API_KEY')) && trim(getenv('VERDICT_LVT_API_KEY')) !== '') {
    $sources[] = 'environment:VERDICT_LVT_API_KEY';
}
if ($branch === '') {
    $branch = verdict_live_vt_behat_branch_with_credential();
    if ($branch !== '') {
        $sources[] = 'behat_db:antivirus_verdict/apikey@b' . $branch;
    }
} else {
    $behat = verdict_live_vt_read_behat_plugin_api_key($branch);
    if ($behat !== '') {
        $sources[] = 'behat_db:antivirus_verdict/apikey@b' . $branch;
    }
}

if ($sources === []) {
    fwrite(STDERR, "No VT credential (env or Behat config_plugins on branches 501/502/500/405).\n");
    exit(1);
}
if ($branch === '') {
    $branch = verdict_live_vt_behat_branch_with_credential();
}

echo 'VT credential: present (' . implode(', ', $sources) . ")\n";
echo "Key length: " . strlen(verdict_live_vt_resolve_api_key()) . " characters (value not shown).\n";
exit(0);
