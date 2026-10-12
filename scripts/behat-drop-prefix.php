<?php
/**
 * Drop all tables for a Behat prefix (CLI only). Uses branch behat_prefix from JSON.
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
$prefix = $map[$branch]['behat_prefix'];
$configpath = rtrim($map[$branch]['moodleroot'], '/\\') . DIRECTORY_SEPARATOR . 'config.php';
$content = file_get_contents($configpath);
$get = function (string $key) use ($content): string {
    if (preg_match('/\$CFG->' . preg_quote($key, '/') . '\s*=\s*[\'"]([^\'"]+)[\'"]/', $content, $m)) {
        return $m[1];
    }
    return '';
};
$host = $get('dbhost') ?: '127.0.0.1';
$user = $get('dbuser');
$pass = $get('dbpass');
$db = $get('dbname');
$port = 3306;
if (preg_match('/\'dbport\'\s*=>\s*(\d+)/', $content, $m)) {
    $port = (int) $m[1];
}
$mysqli = new mysqli($host, $user, $pass, $db, $port);
if ($mysqli->connect_error) {
    fwrite(STDERR, "DB connect failed\n");
    exit(1);
}
$like = $mysqli->real_escape_string($prefix) . '%';
$res = $mysqli->query("SHOW TABLES LIKE '{$like}'");
$tables = [];
while ($row = $res->fetch_array()) {
    $tables[] = $row[0];
}
foreach ($tables as $table) {
    $mysqli->query('DROP TABLE IF EXISTS `' . str_replace('`', '``', $table) . '`');
}
echo 'Dropped ' . count($tables) . " tables with prefix {$prefix}\n";
