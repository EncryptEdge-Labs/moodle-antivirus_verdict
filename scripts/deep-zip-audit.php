<?php
/**
 * Deep audit of a release ZIP: raw ZipArchive names vs Moodle namelookup/extract.
 * CLI only — not plugin runtime.
 */
define('CLI_SCRIPT', true);
require 'D:/CODE/moodle-dev/public/config.php';
require_once($CFG->libdir . '/filelib.php');

$zippath = $argv[1] ?? '';
if ($zippath === '' || !is_readable($zippath)) {
    fwrite(STDERR, "Usage: php deep-zip-audit.php /path/to.zip\n");
    exit(2);
}

echo "=== Raw ZipArchive entry names ===\n";
$za = new ZipArchive();
$za->open($zippath);
$rawissues = [];
for ($i = 0; $i < $za->numFiles; $i++) {
    $stat = $za->statIndex($i);
    $raw = $stat['name'];
    $norm = str_replace('\\', '/', $raw);
    if (strpos($raw, '\\') !== false) {
        $rawissues[] = "backslash: $raw";
    }
    if (strpos($norm, '&') !== false) {
        $rawissues[] = "ampersand: $raw";
    }
    foreach (explode('/', $norm) as $seg) {
        if ($seg === '' || $seg === '.') {
            continue;
        }
        if ($seg !== clean_param($seg, PARAM_PATH)) {
            $rawissues[] = "PARAM_PATH segment [$seg] in $norm";
        }
    }
}
$za->close();
echo "entries={$za->numFiles} raw_issues=" . count($rawissues) . "\n";
foreach ($rawissues as $r) {
    echo "  $r\n";
}

echo "\n=== Moodle list_files + extract ===\n";
$fp = get_file_packer('application/zip');
$listed = $fp->list_files($zippath);
$roots = [];
foreach ($listed as $info) {
    $p = $info->pathname;
    $roots[explode('/', $p)[0] ?? ''] = true;
}
echo 'list_count=' . count($listed) . ' roots=' . implode(',', array_keys($roots)) . "\n";

$temp = make_request_directory();
$extracted = $fp->extract_to_pathname($zippath, $temp);
$bad = array_filter($extracted, fn($s) => $s !== true);
echo 'extract_bad=' . count($bad) . "\n";
foreach ($bad as $path => $status) {
    echo "  FAIL: $path => $status\n";
}

echo "\n=== unzip_plugin_file ===\n";
try {
    $pm = core_plugin_manager::instance();
    $tmp2 = make_request_directory();
    $pm->unzip_plugin_file($zippath, $tmp2, 'verdict');
    echo "unzip_plugin_file: OK\n";
} catch (Throwable $e) {
    echo "unzip_plugin_file: {$e->errorcode} — {$e->getMessage()}\n";
}

exit(count($bad) > 0 ? 1 : 0);
