<?php
$zip = $argv[1] ?? '';
$dest = sys_get_temp_dir() . '/vtest-' . uniqid();
mkdir($dest);

$za = new ZipArchive();
$za->open($zip);
$raw = $za->getNameIndex(0);
echo 'first_raw=' . json_encode($raw) . PHP_EOL;
$za->extractTo($dest, $raw);
$za->close();

echo 'forward_version=' . (file_exists($dest . '/verdict/version.php') ? 'yes' : 'no') . PHP_EOL;
$c = 0;
$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dest, FilesystemIterator::SKIP_DOTS));
foreach ($it as $f) {
    if ($f->isFile()) {
        $c++;
        if ($c <= 3) {
            echo 'file: ' . $f->getPathname() . PHP_EOL;
        }
    }
}
echo 'total_files=' . $c . PHP_EOL;
