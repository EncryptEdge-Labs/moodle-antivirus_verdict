<?php
require 'D:/CODE/moodle-plugin-ci/vendor/autoload.php';

use Symfony\Component\Finder\Finder;
use MoodlePluginCI\Bridge\MoodlePlugin;

$root = dirname(__DIR__);
$plugin = new MoodlePlugin($root);
$plugin->context = 'phpcs';
$files = $plugin->getFiles(Finder::create()->name('*.php'));
$listfile = sys_get_temp_dir() . '/verdict-phpcs-files.txt';
file_put_contents($listfile, implode(PHP_EOL, $files));
$phpcs = 'D:/CODE/moodle-plugin-ci/vendor/squizlabs/php_codesniffer/bin/phpcs';
$cmd = [
    'php',
    $phpcs,
    '--standard=moodle',
    '--report=summary',
    '-s',
    '--file-list=' . $listfile,
];
passthru(implode(' ', array_map('escapeshellarg', $cmd)), $code);
exit($code);
