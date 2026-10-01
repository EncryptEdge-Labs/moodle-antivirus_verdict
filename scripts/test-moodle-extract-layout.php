<?php
define('CLI_SCRIPT', true);
require 'D:/CODE/moodle-dev/public/config.php';
require_once($CFG->libdir . '/filelib.php');

$zip = $argv[1] ?? '';
$temp = make_request_directory();
$fp = get_file_packer('application/zip');
$result = $fp->extract_to_pathname($zip, $temp, null, null, true);
echo 'success=' . ($result ? 'true' : 'false') . PHP_EOL;
echo 'version_forward=' . (file_exists($temp . '/verdict/version.php') ? 'yes' : 'no') . PHP_EOL;

$bad = 0;
$extracted = $fp->extract_to_pathname($zip, $temp . '2');
foreach ($extracted as $p => $s) {
    if ($s !== true) {
        $bad++;
        if ($bad <= 5) {
            echo "bad: $p => $s\n";
        }
    }
}
echo 'bad_count=' . $bad . PHP_EOL;
