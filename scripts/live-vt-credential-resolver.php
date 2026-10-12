<?php
/**
 * Resolve live VT credential for operator certification (CLI only). Never prints the key.
 *
 * Order: VERDICT_LVT_API_KEY env, then antivirus_verdict apikey in Behat DB prefix
 * for VERDICT_LVT_BEHAT_BRANCH (default 502).
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

if (php_sapi_name() !== 'cli') {
    die('CLI only');
}

/**
 * Return trimmed API key or empty string. Never logs the value.
 *
 * @return string
 */
function verdict_live_vt_resolve_api_key(): string {
    $fromenv = getenv('VERDICT_LVT_API_KEY');
    if (is_string($fromenv)) {
        $fromenv = trim($fromenv);
        if ($fromenv !== '') {
            return $fromenv;
        }
    }

    $branch = getenv('VERDICT_LVT_BEHAT_BRANCH');
    if (is_string($branch) && $branch !== '') {
        return verdict_live_vt_read_behat_plugin_api_key($branch);
    }

    foreach (['501', '502', '500', '405'] as $candidate) {
        $key = verdict_live_vt_read_behat_plugin_api_key($candidate);
        if ($key !== '') {
            putenv('VERDICT_LVT_BEHAT_BRANCH=' . $candidate);
            return $key;
        }
    }

    return '';
}

/**
 * Behat branch that currently holds a non-empty apikey, or empty string.
 *
 * @return string
 */
function verdict_live_vt_behat_branch_with_credential(): string {
    foreach (['501', '502', '500', '405'] as $candidate) {
        if (verdict_live_vt_read_behat_plugin_api_key($candidate) !== '') {
            return $candidate;
        }
    }
    return '';
}

/**
 * Whether a non-empty credential is available (env or Behat config).
 *
 * @return bool
 */
function verdict_live_vt_credential_configured(): bool {
    return verdict_live_vt_resolve_api_key() !== '';
}

/**
 * Read plugin apikey from Behat-isolated DB prefix only.
 *
 * @param string $branch behat-branches.json key (405|500|501|502).
 * @return string
 */
function verdict_live_vt_read_behat_plugin_api_key(string $branch): string {
    $mapfile = __DIR__ . '/behat-branches.json';
    if (!is_readable($mapfile)) {
        return '';
    }
    $map = json_decode(file_get_contents($mapfile), true);
    unset($map['chromedriver'], $map['chrome_browser']);
    if (!isset($map[$branch])) {
        return '';
    }

    $configpath = rtrim($map[$branch]['moodleroot'], '/\\') . DIRECTORY_SEPARATOR . 'config.php';
    if (!is_readable($configpath)) {
        return '';
    }
    $content = file_get_contents($configpath);
    $get = function (string $key) use ($content): string {
        if (preg_match('/\$CFG->' . preg_quote($key, '/') . '\s*=\s*[\'"]([^\'"]+)[\'"]/', $content, $m)) {
            return $m[1];
        }
        return '';
    };

    $prefix = $map[$branch]['behat_prefix'] ?? '';
    if ($prefix === '' && !preg_match('/\$CFG->behat_prefix\s*=\s*[\'"]([^\'"]+)[\'"]/', $content, $pm)) {
        return '';
    }
    if ($prefix === '') {
        $prefix = $pm[1];
    }

    $host = $get('dbhost') ?: '127.0.0.1';
    $user = $get('dbuser');
    $pass = $get('dbpass');
    $db = $get('dbname');
    $port = 3306;
    if (preg_match('/\'dbport\'\s*=>\s*(\d+)/', $content, $m)) {
        $port = (int) $m[1];
    }

    $mysqli = @new mysqli($host, $user, $pass, $db, $port);
    if ($mysqli->connect_error) {
        return '';
    }

    $table = $mysqli->real_escape_string($prefix . 'config_plugins');
    $res = $mysqli->query(
        "SELECT value FROM `{$table}` WHERE plugin = 'antivirus_verdict' AND name = 'apikey' LIMIT 1"
    );
    if (!$res) {
        $mysqli->close();
        return '';
    }
    $row = $res->fetch_assoc();
    $mysqli->close();
    if (!$row || !isset($row['value'])) {
        return '';
    }
    $value = trim((string) $row['value']);
    return $value !== '' ? $value : '';
}
