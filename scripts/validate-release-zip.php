<?php
// CLI helper for scripts/build-release-zip.ps1 — not part of the Moodle plugin runtime.
define('CLI_SCRIPT', true);

if ($argc < 2) {
    fwrite(STDERR, "Usage: php validate-release-zip.php /path/to/package.zip\n");
    exit(2);
}

$zip = $argv[1];
$config = 'D:/CODE/moodle-dev/public/config.php';
if (!is_readable($config)) {
    fwrite(STDERR, "Moodle config not found: $config\n");
    exit(2);
}
require $config;
require_once($CFG->libdir . '/filelib.php');
require_once($CFG->dirroot . '/admin/tool/installaddon/classes/installer.php');

$errors = [];

if (!is_readable($zip)) {
    $errors[] = "ZIP not readable: $zip";
} else {
    $fp = get_file_packer('application/zip');
    $listed = $fp->list_files($zip);
    if (empty($listed)) {
        $errors[] = 'ZIP list_files empty';
    } else {
        $roots = [];
        $za = new ZipArchive();
        if ($za->open($zip) === true) {
            for ($ri = 0; $ri < $za->numFiles; $ri++) {
                $raw = $za->getNameIndex($ri);
                if (strpos($raw, '\\') !== false) {
                    $errors[] = "Backslash in raw ZIP entry (Linux extract fails): $raw";
                }
            }
            $za->close();
        }

        foreach ($listed as $info) {
            $path = $info->pathname;
            if (strpos($path, '..') !== false) {
                $errors[] = "Path traversal in entry: $path";
            }
            if ($path !== '' && $path[0] === '/') {
                $errors[] = "Absolute path in entry: $path";
            }
            if (strpos($path, '&') !== false) {
                $errors[] = "Ampersand in entry: $path";
            }
            $parts = explode('/', $path);
            $root = $parts[0] ?? '';
            if ($root !== '') {
                $roots[$root] = true;
            }
            foreach ($parts as $seg) {
                if ($seg === '') {
                    continue;
                }
                if ($seg !== clean_param($seg, PARAM_PATH)) {
                    $errors[] = "PARAM_PATH would alter segment [$seg] in $path";
                }
            }
        }
        if (count($roots) !== 1 || !isset($roots['verdict'])) {
            $errors[] = 'Expected exactly one top-level directory: verdict/ (found: ' . implode(', ', array_keys($roots)) . ')';
        }
        $hasversion = false;
        foreach ($listed as $info) {
            if ($info->pathname === 'verdict/version.php' && !$info->is_directory) {
                $hasversion = true;
                break;
            }
        }
        if (!$hasversion) {
            $errors[] = 'Missing verdict/version.php in archive listing';
        }
    }

    $temp = make_request_directory();
    $extracted = $fp->extract_to_pathname($zip, $temp);
    $bad = [];
    foreach ($extracted as $path => $status) {
        if ($status !== true) {
            $bad[$path] = $status;
        }
    }
    if (!empty($bad)) {
        foreach ($bad as $path => $status) {
            $errors[] = "Extract failed: $path => $status";
        }
    }

    $pm = core_plugin_manager::instance();
    $root = $pm->get_plugin_zip_root_dir($zip);
    if ($root !== 'verdict') {
        $errors[] = "get_plugin_zip_root_dir returned: " . var_export($root, true);
    }

    try {
        $tmp2 = make_request_directory();
        $pm->unzip_plugin_file($zip, $tmp2, 'verdict');
    } catch (Throwable $e) {
        $errors[] = 'unzip_plugin_file: ' . $e->errorcode;
    }

    $installer = tool_installaddon_installer::instance();
    $component = $installer->detect_plugin_component($zip);
    if ($component !== 'antivirus_verdict') {
        $errors[] = 'detect_plugin_component: ' . var_export($component, true);
    }
}

$secretpatterns = [
    '/[a-f0-9]{64}/' => false,
];
if (is_readable($zip)) {
    $za = new ZipArchive();
    if ($za->open($zip) === true) {
        for ($i = 0; $i < $za->numFiles; $i++) {
            $name = $za->getNameIndex($i);
            if (!preg_match('/\.(php|md|txt|mustache|css|js|xml|json)$/i', $name)) {
                continue;
            }
            $content = $za->getFromIndex($i);
            if ($content === false) {
                continue;
            }
            $normname = str_replace('\\', '/', $name);
            $istest = (strpos($normname, 'verdict/tests/') !== false);
            // PHPUnit uses intentional fake key strings; only scan plugin runtime paths for those literals.
            if (!$istest && preg_match('/super-secret|phpunit-privacy-secret/i', $content)) {
                $errors[] = "Possible secret string in: $name";
            }
            // Hard-coded live VT key assignment (env/docs in tests are OK).
            if (preg_match('/VERDICT_LVT_API_KEY\s*=\s*[\'"][^\'"]{20,}[\'"]/i', $content)) {
                $errors[] = "Possible secret string in: $name";
            }
            if (!$istest && preg_match('/(?:sk_live_|AKIA[0-9A-Z]{16})/', $content)) {
                $errors[] = "Possible secret string in: $name";
            }
        }
        $za->close();
    }
}

if (!empty($errors)) {
    fwrite(STDERR, "VALIDATION FAIL\n");
    foreach ($errors as $e) {
        fwrite(STDERR, " - $e\n");
    }
    exit(1);
}

echo "VALIDATION PASS\n";
echo "entries=" . count($listed ?? []) . " extract_errors=0 root=verdict component=antivirus_verdict\n";
exit(0);
