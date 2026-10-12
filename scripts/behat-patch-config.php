<?php
/**
 * Add isolated Behat settings to a Moodle config.php if not already present.
 *
 * Does not print database passwords. Run from plugin root:
 *   php scripts/behat-patch-config.php 502
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

if (php_sapi_name() !== 'cli') {
    die('CLI only');
}

$branch = $argv[1] ?? '';
$mapfile = __DIR__ . '/behat-branches.json';
if (!is_readable($mapfile)) {
    fwrite(STDERR, "Missing {$mapfile}\n");
    exit(1);
}
$map = json_decode(file_get_contents($mapfile), true);
if (!isset($map[$branch])) {
    fwrite(STDERR, "Unknown branch {$branch}. Use: " . implode(', ', array_keys($map)) . "\n");
    exit(1);
}
$cfg = $map[$branch];
$configpath = rtrim($cfg['moodleroot'], '/\\') . DIRECTORY_SEPARATOR . 'config.php';
if (!is_readable($configpath)) {
    fwrite(STDERR, "config.php not found: {$configpath}\n");
    exit(1);
}
$content = file_get_contents($configpath);
if (strpos($content, 'VERDICT_BEHAT_ISOLATION') !== false) {
    echo "Behat block already present in {$configpath}\n";
    if (strpos($content, 'VERDICT_BEHAT_CHROME') === false) {
        $chromeblock = <<<PHP

// VERDICT_BEHAT_CHROME — ChromeDriver on port 9515 (EncryptEdge QA).
\$CFG->behat_profiles = [
    'chrome' => [
        'browser' => 'chrome',
        'wd_host' => 'http://localhost:9515',
    ],
];

PHP;
        $pos = strpos($content, 'require_once(__DIR__');
        if ($pos !== false) {
            $content = substr($content, 0, $pos) . $chromeblock . substr($content, $pos);
            file_put_contents($configpath, $content);
            echo "Added Chrome Behat profile to {$configpath}\n";
        }
    }
    exit(0);
}
$block = <<<PHP

// VERDICT_BEHAT_ISOLATION — dedicated Behat dataroot/prefix (EncryptEdge QA). Not production.
\$CFG->behat_dataroot = '{$cfg['behat_dataroot']}';
\$CFG->behat_prefix = '{$cfg['behat_prefix']}';
\$CFG->behat_wwwroot = '{$cfg['behat_wwwroot']}';
// VERDICT_BEHAT_CHROME — ChromeDriver on port 9515 (EncryptEdge QA).
\$CFG->behat_profiles = [
    'chrome' => [
        'browser' => 'chrome',
        'wd_host' => 'http://localhost:9515',
    ],
];

PHP;
$needle = 'require_once(__DIR__';
$pos = strpos($content, $needle);
if ($pos === false) {
    fwrite(STDERR, "Could not find require_once in config.php\n");
    exit(1);
}
$newcontent = substr($content, 0, $pos) . $block . substr($content, $pos);
file_put_contents($configpath, $newcontent);
echo "Patched {$configpath} with behat_prefix {$cfg['behat_prefix']}\n";
