<?php
// CLI helper — not part of plugin runtime.
define('CLI_SCRIPT', true);
require 'D:/CODE/moodle-dev/public/config.php';

$zip = $argv[1] ?? '';
if ($zip === '' || !is_readable($zip)) {
    fwrite(STDERR, "Usage: php zip-param-path-audit.php /path/to.zip\n");
    exit(2);
}

$fp = get_file_packer('application/zip');
$listed = $fp->list_files($zip);
$altered = [];
foreach ($listed as $info) {
    foreach (explode('/', $info->pathname) as $seg) {
        if ($seg === '') {
            continue;
        }
        $clean = clean_param($seg, PARAM_PATH);
        if ($seg !== $clean) {
            $altered[] = [
                'path' => $info->pathname,
                'segment' => $seg,
                'clean' => $clean,
            ];
        }
    }
}

echo 'entries=' . count($listed) . ' param_path_alterations=' . count($altered) . PHP_EOL;
foreach ($altered as $row) {
    echo $row['path'] . ' :: [' . $row['segment'] . '] -> [' . $row['clean'] . ']' . PHP_EOL;
}

exit(count($altered) > 0 ? 1 : 0);
