<?php
/**
 * Behat environment diagnostics for one Moodle branch.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

if (php_sapi_name() !== 'cli') {
    die('CLI only');
}

$branch = $argv[1] ?? '502';
$mapfile = __DIR__ . '/behat-branches.json';
$map = json_decode(file_get_contents($mapfile), true);
$chromedriverdefault = $map['chromedriver'] ?? 'C:\\Tools\\chromedriver\\chromedriver.exe';
$chromedefault = $map['chrome_browser'] ?? '';
unset($map['chromedriver'], $map['chrome_browser']);
if (!isset($map[$branch])) {
    fwrite(STDERR, "Unknown branch {$branch}\n");
    exit(2);
}
$b = $map[$branch];
$php = $b['php'];
$root = $b['moodleroot'];
echo "Branch: {$branch} ({$b['label']})\n";
echo "Moodle root: {$root}\n";
echo "PHP CLI: {$php}\n";
passthru('"' . $php . '" -v', $code);

$driverexe = $chromedriverdefault;
echo "ChromeDriver executable: {$driverexe}\n";
echo "ChromeDriver readable: " . (is_readable($driverexe) ? 'yes' : 'NO') . "\n";
if (is_readable($driverexe)) {
    passthru('"' . $driverexe . '" --version', $dcode);
} else {
    echo "ChromeDriver version: (not available)\n";
    $dcode = 1;
}

$chromeexe = $chromedefault;
if ($chromeexe !== '' && is_readable($chromeexe)) {
    echo "Chrome browser: {$chromeexe}\n";
    $verinfo = pathinfo($chromeexe, PATHINFO_DIRNAME) . DIRECTORY_SEPARATOR . 'chrome.VisualElementsManifest.xml';
    $chromeversion = '';
    if (function_exists('shell_exec')) {
        $out = shell_exec('powershell -NoProfile -Command "(Get-Item \'' . str_replace("'", "''", $chromeexe) .
            '\').VersionInfo.ProductVersion" 2>$null');
        $chromeversion = trim((string) $out);
    }
    echo "Chrome version: " . ($chromeversion !== '' ? $chromeversion : '(unknown)') . "\n";
    if ($dcode === 0 && $chromeversion !== '' && preg_match('/(\d+)\./', $chromeversion, $cm) &&
            preg_match('/ChromeDriver\s+(\d+)\./', shell_exec('"' . $driverexe . '" --version 2>&1') ?? '', $dm)) {
        $compatible = ($cm[1] === $dm[1]) ? 'COMPATIBLE (major match)' : 'INCOMPATIBLE (major mismatch)';
        echo "ChromeDriver vs Chrome: {$compatible}\n";
    }
} else {
    echo "Chrome browser: not found at configured path\n";
}

$init = $root . DIRECTORY_SEPARATOR . str_replace('\\', DIRECTORY_SEPARATOR, $b['behat_init']);
echo "Behat init script: " . (is_readable($init) ? 'OK' : 'MISSING') . " ({$init})\n";
$config = $root . DIRECTORY_SEPARATOR . 'config.php';
echo "config.php: " . (is_readable($config) ? 'OK' : 'MISSING') . "\n";
if (is_readable($config)) {
    $c = file_get_contents($config);
    echo "Behat block in config: " . (strpos($c, 'VERDICT_BEHAT_ISOLATION') !== false ? 'yes' : 'no') . "\n";
    if (preg_match('/\$CFG->prefix\s*=\s*[\'"]([^\'"]+)[\'"]/', $c, $m)) {
        echo "Dev DB prefix: {$m[1]}\n";
    }
    if (preg_match('/\$CFG->behat_prefix\s*=\s*[\'"]([^\'"]+)[\'"]/', $c, $m)) {
        echo "Behat DB prefix: {$m[1]}\n";
    }
    if (preg_match('/\$CFG->dataroot\s*=\s*[\'"]([^\'"]+)[\'"]/', $c, $m)) {
        echo "Dev dataroot: {$m[1]}\n";
    }
    if (preg_match('/\$CFG->behat_dataroot\s*=\s*[\'"]([^\'"]+)[\'"]/', $c, $m)) {
        echo "Behat dataroot: {$m[1]}\n";
    }
    if (preg_match('/\$CFG->behat_wwwroot\s*=\s*[\'"]([^\'"]+)[\'"]/', $c, $m)) {
        echo "Behat wwwroot: {$m[1]}\n";
        $host = parse_url($m[1], PHP_URL_HOST);
        if ($host) {
            $resolved = gethostbyname($host);
            echo "Behat host resolves: {$host} -> {$resolved}\n";
        }
    }
}
$plugin = $root . DIRECTORY_SEPARATOR . str_replace('\\', DIRECTORY_SEPARATOR, $b['plugin_path']);
echo "Verdict plugin path: {$plugin}\n";
echo "Plugin version.php: " . (is_readable($plugin . '/version.php') ? 'OK' : 'MISSING') . "\n";
echo "Behat features: " . (is_readable($plugin . '/tests/behat/navigation.feature') ? 'OK' : 'MISSING') . "\n";

$util = $root . DIRECTORY_SEPARATOR . str_replace('\\', DIRECTORY_SEPARATOR, $b['behat_util']);
$utilcode = 1;
if (is_readable($util)) {
    echo "--- Moodle util.php --diag ---\n";
    $env = getenv('PATH') ?: '';
    $dir = dirname($driverexe);
    if ($dir !== '' && strpos($env, $dir) === false) {
        putenv('PATH=' . $dir . PATH_SEPARATOR . $env);
    }
    if (is_readable($driverexe)) {
        putenv('WEBDRIVER_CHROME_DRIVER=' . $driverexe);
    }
    passthru('"' . $php . '" "' . $util . '" --diag', $utilcode);
} else {
    echo "util.php missing; skip Moodle diag\n";
}

$running = trim((string) shell_exec('tasklist /FI "IMAGENAME eq chromedriver.exe" /NH 2>nul'));
echo "chromedriver.exe processes: " . (stripos($running, 'chromedriver.exe') !== false ? trim($running) : 'none') . "\n";

exit($utilcode === 0 ? 0 : 1);
