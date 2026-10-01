<?php
$zip = $argv[1] ?? '';
if ($zip === '' || !is_readable($zip)) {
    exit(2);
}
$z = new ZipArchive();
if ($z->open($zip) !== true) {
    exit(2);
}
for ($i = 0; $i < $z->numFiles; $i++) {
    echo str_replace('\\', '/', $z->getNameIndex($i)), "\n";
}
$z->close();
