<?php
/**
 * Operator-only live VirusTotal certification runner (CLI).
 *
 * Requires VERDICT_LVT_OPT_IN=1. Reuses VERDICT_LVT_API_KEY or Behat-stored apikey.
 * Never prints the API key.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

if (php_sapi_name() !== 'cli') {
    die('CLI only');
}

require __DIR__ . '/live-vt-credential-resolver.php';

$optin = getenv('VERDICT_LVT_OPT_IN');
if (!is_string($optin) || trim($optin) !== '1') {
    fwrite(STDERR, "Refusing live VT run: set VERDICT_LVT_OPT_IN=1 for explicit opt-in.\n");
    exit(2);
}

$key = verdict_live_vt_resolve_api_key();
if ($key === '') {
    fwrite(STDERR, "No credential: configure Behat plugin apikey or set VERDICT_LVT_API_KEY.\n");
    fwrite(STDERR, "Verify with: php scripts/behat-verify-vt-credential.php\n");
    exit(2);
}

if (!is_string(getenv('VERDICT_LVT_API_KEY')) || trim(getenv('VERDICT_LVT_API_KEY')) === '') {
    putenv('VERDICT_LVT_API_KEY=' . $key);
}

$branch = getenv('VERDICT_LVT_MOODLE_BRANCH');
if (!is_string($branch) || $branch === '') {
    $branch = verdict_live_vt_behat_branch_with_credential();
}
if ($branch === '') {
    $branch = getenv('VERDICT_LVT_BEHAT_BRANCH');
}
if (!is_string($branch) || $branch === '') {
    $branch = '501';
}

$map = json_decode(file_get_contents(__DIR__ . '/behat-branches.json'), true);
if (!isset($map[$branch])) {
    fwrite(STDERR, "Unknown VERDICT_LVT_MOODLE_BRANCH {$branch}\n");
    exit(2);
}

$moodleroot = rtrim($map[$branch]['moodleroot'], '/\\');
$php = $map[$branch]['php'] ?? 'php';
$pluginrel = str_replace('\\', '/', $map[$branch]['plugin_path']);
$plugindir = $moodleroot . '/' . $pluginrel;

if ($branch === '502' || $branch === '501') {
    $moodlerootforvendor = $moodleroot;
} else {
    $moodlerootforvendor = $moodleroot;
}

$phpunit = $moodlerootforvendor . DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR .
    'phpunit' . DIRECTORY_SEPARATOR . 'phpunit' . DIRECTORY_SEPARATOR . 'phpunit';
if (!is_readable($phpunit)) {
    fwrite(STDERR, "PHPUnit not found at {$phpunit}\n");
    exit(2);
}

$cacert = $moodleroot . DIRECTORY_SEPARATOR . 'public' . DIRECTORY_SEPARATOR . 'lib' . DIRECTORY_SEPARATOR . 'cacert.pem';
if (!is_readable($cacert) && is_readable($moodleroot . DIRECTORY_SEPARATOR . 'lib' . DIRECTORY_SEPARATOR . 'cacert.pem')) {
    $cacert = $moodleroot . DIRECTORY_SEPARATOR . 'lib' . DIRECTORY_SEPARATOR . 'cacert.pem';
}

$config = $plugindir . DIRECTORY_SEPARATOR . 'phpunit.xml';
if (!is_readable($config)) {
    fwrite(STDERR, "Plugin phpunit.xml not found at {$config}\n");
    exit(2);
}

$bootstrap = $moodleroot . DIRECTORY_SEPARATOR . 'public' . DIRECTORY_SEPARATOR . 'lib' . DIRECTORY_SEPARATOR .
    'phpunit' . DIRECTORY_SEPARATOR . 'bootstrap.php';
if (!is_readable($bootstrap)) {
    $bootstrap = $moodleroot . DIRECTORY_SEPARATOR . 'lib' . DIRECTORY_SEPARATOR . 'phpunit' .
        DIRECTORY_SEPARATOR . 'bootstrap.php';
}
if (!is_readable($bootstrap)) {
    fwrite(STDERR, "Moodle PHPUnit bootstrap not found for {$moodleroot}\n");
    exit(2);
}

$logdir = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'qa-logs';
if (!is_dir($logdir)) {
    mkdir($logdir, 0777, true);
}
$stamp = date('Ymd-His');
$log = $logdir . DIRECTORY_SEPARATOR . "live-vt-cert-{$branch}-{$stamp}.log";

echo "Live VT certification (branch {$branch}, credential present, key not shown).\n";
echo "Log: {$log}\n";

$cmd = escapeshellarg($php) . ' -d curl.cainfo=' . escapeshellarg($cacert) .
    ' -d openssl.cafile=' . escapeshellarg($cacert) . ' ' .
    escapeshellarg($phpunit) . ' --bootstrap ' . escapeshellarg($bootstrap) .
    ' --configuration ' . escapeshellarg($config) .
    ' --filter live_vt_certification --group live_vt 2>&1';

$descriptors = [0 => STDIN, 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
$proc = proc_open($cmd, $descriptors, $pipes, $plugindir);
if (!is_resource($proc)) {
    fwrite(STDERR, "Failed to start PHPUnit.\n");
    exit(1);
}

$output = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
fclose($pipes[1]);
fclose($pipes[2]);
$code = proc_close($proc);

file_put_contents($log, $output);
if (preg_match('/x-apikey\s*[:=]\s*\S+/i', $output)) {
    fwrite(STDERR, "SECURITY: log may contain credential material — review and redact {$log}\n");
    exit(1);
}

echo $output;
exit($code);
