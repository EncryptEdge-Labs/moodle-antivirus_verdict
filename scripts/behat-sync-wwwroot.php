<?php
/**
 * Sync behat_wwwroot in Moodle config.php from behat-branches.json (no other changes).
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

if (php_sapi_name() !== 'cli') {
    die('CLI only');
}

$branch = $argv[1] ?? '';
$map = json_decode(file_get_contents(__DIR__ . '/behat-branches.json'), true);
unset($map['chromedriver'], $map['chrome_browser']);
if (!isset($map[$branch])) {
    fwrite(STDERR, "Unknown branch {$branch}\n");
    exit(1);
}
$cfg = $map[$branch];
$configpath = rtrim($cfg['moodleroot'], '/\\') . DIRECTORY_SEPARATOR . 'config.php';
$content = file_get_contents($configpath);
if (!preg_match('/(\$CFG->behat_wwwroot\s*=\s*[\'"])([^\'"]+)([\'"];)/', $content, $m)) {
    fwrite(STDERR, "behat_wwwroot not found in {$configpath}\n");
    exit(1);
}
$old = $m[2];
$new = $cfg['behat_wwwroot'];
if ($old === $new) {
    echo "behat_wwwroot already {$new}\n";
    exit(0);
}
$content = preg_replace(
    '/\$CFG->behat_wwwroot\s*=\s*[\'"][^\'"]+[\'"];/',
    "\$CFG->behat_wwwroot = '{$new}';",
    $content,
    1
);
file_put_contents($configpath, $content);
echo "Updated behat_wwwroot: {$old} -> {$new}\n";
