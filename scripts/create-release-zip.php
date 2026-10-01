<?php
// Build a Moodle-compatible ZIP from a staged verdict/ tree (forward-slash paths only).
// CLI — not part of plugin runtime.
define('CLI_SCRIPT', true);

$config = 'D:/CODE/moodle-dev/public/config.php';
if (!is_readable($config)) {
    fwrite(STDERR, "Moodle config not found: $config\n");
    exit(2);
}
require $config;
require_once($CFG->libdir . '/filelib.php');

$verdictdir = $argv[1] ?? '';
$outzip = $argv[2] ?? '';
if ($verdictdir === '' || $outzip === '' || !is_dir($verdictdir)) {
    fwrite(STDERR, "Usage: php create-release-zip.php /path/to/staged/verdict /path/to/output.zip\n");
    exit(2);
}

$verdictdir = rtrim(str_replace('\\', '/', realpath($verdictdir)), '/');
if (!is_readable($verdictdir . '/version.php')) {
    fwrite(STDERR, "Missing version.php in staged verdict directory.\n");
    exit(2);
}

$files = [];
$iterator = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($verdictdir, FilesystemIterator::SKIP_DOTS),
    RecursiveIteratorIterator::SELF_FIRST
);

foreach ($iterator as $item) {
    /** @var SplFileInfo $item */
    $full = str_replace('\\', '/', $item->getPathname());
    $rel = substr($full, strlen($verdictdir) + 1);
    if ($rel === false || $rel === '') {
        continue;
    }
    $archivepath = 'verdict/' . $rel;
    if ($item->isDir()) {
        $files[$archivepath . '/'] = null;
    } else {
        $files[$archivepath] = $full;
    }
}

if (empty($files)) {
    fwrite(STDERR, "No files to pack.\n");
    exit(2);
}

$outdir = dirname($outzip);
if (!is_dir($outdir) && !mkdir($outdir, 0777, true) && !is_dir($outdir)) {
    fwrite(STDERR, "Cannot create output directory: $outdir\n");
    exit(2);
}

if (is_file($outzip)) {
    unlink($outzip);
}

$packer = get_file_packer('application/zip');
if (!$packer->archive_to_pathname($files, $outzip, false)) {
    fwrite(STDERR, "archive_to_pathname failed.\n");
    exit(1);
}

$za = new ZipArchive();
if ($za->open($outzip) !== true) {
    fwrite(STDERR, "Cannot open created ZIP.\n");
    exit(1);
}
for ($i = 0; $i < $za->numFiles; $i++) {
    $raw = $za->getNameIndex($i);
    if (strpos($raw, '\\') !== false) {
        fwrite(STDERR, "ZIP still contains backslash path: $raw\n");
        $za->close();
        exit(1);
    }
    if (strpos($raw, '&') !== false) {
        fwrite(STDERR, "ZIP contains ampersand path: $raw\n");
        $za->close();
        exit(1);
    }
}
$za->close();

echo 'Packed ' . count($files) . ' archive paths to ' . $outzip . PHP_EOL;
exit(0);
