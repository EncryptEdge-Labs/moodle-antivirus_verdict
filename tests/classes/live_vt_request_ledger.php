<?php
// This file is part of Moodle - https://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <https://www.gnu.org/licenses/>.

/**
 * Shared rolling-window limiter for live VirusTotal certification (test-only).
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\tests;

/**
 * Enforces max 4 outbound VT HTTP starts per rolling 60s and 15s minimum spacing.
 *
 * Persists timestamps only (no secrets) under the PHPUnit cache directory.
 */
final class live_vt_request_ledger {
    /** Max request starts per rolling 60-second window. */
    public const MAX_PER_WINDOW = 4;

    /** Minimum seconds between consecutive request starts. */
    public const MIN_SPACING_SECONDS = 15;

    /** Rolling window length in seconds. */
    public const WINDOW_SECONDS = 60;

    /** @var string Ledger file path. */
    private static string $ledgerpath = '';

    /**
     * Block until a request slot is available, then record the start.
     *
     * @param string $category Endpoint category (hash_lookup, upload, analysis, other).
     * @param string $method HTTP method.
     * @param string $urlpath Safe path fragment (host + path category, no query secrets).
     * @throws \RuntimeException When budget cannot be satisfied within timeout.
     */
    public static function acquire_slot(string $category, string $method, string $urlpath): void {
        $deadline = microtime(true) + 180;
        while (microtime(true) < $deadline) {
            if (self::try_acquire_slot($category, $method, $urlpath)) {
                return;
            }
            usleep(500000);
        }
        throw new \RuntimeException(
            'Live VT request budget exceeded (max ' . self::MAX_PER_WINDOW . ' per ' .
            self::WINDOW_SECONDS . 's rolling window).'
        );
    }

    /**
     * Record HTTP status for the most recent ledger entry (same process).
     *
     * @param int $status HTTP status code.
     */
    public static function record_response_status(int $status): void {
        self::with_lock(function (array &$data) use ($status): void {
            if ($data['entries'] === []) {
                return;
            }
            $last = count($data['entries']) - 1;
            $data['entries'][$last]['status'] = $status;
        });
    }

    /**
     * Return ledger totals and redacted entries for assertions.
     *
     * @return array{total:int,recent:int,entries:array<int,array<string,mixed>>}
     */
    public static function snapshot(): array {
        $data = self::read_data();
        self::prune_old($data);
        return [
            'total' => count($data['entries']),
            'recent' => count($data['entries']),
            'entries' => $data['entries'],
        ];
    }

    /**
     * Clear the on-disk ledger (PHPUnit only).
     */
    public static function reset_for_tests(): void {
        self::with_lock(function (array &$data): void {
            $data = ['entries' => []];
        });
    }

    /**
     * Insert a synthetic ledger row for unit tests (PHPUnit only).
     *
     * @param array<string,mixed> $entry Must include started_at.
     */
    public static function append_entry_for_tests(array $entry): void {
        self::with_lock(function (array &$data) use ($entry): void {
            $data['entries'][] = $entry;
        });
    }

    /**
     * Attempt one ledger slot when spacing and window budget allow.
     *
     * @param string $category Category.
     * @param string $method Method.
     * @param string $urlpath Path.
     * @return bool
     */
    private static function try_acquire_slot(string $category, string $method, string $urlpath): bool {
        $acquired = false;
        self::with_lock(function (array &$data) use (
            $category,
            $method,
            $urlpath,
            &$acquired
        ): void {
            self::prune_old($data);
            $now = microtime(true);

            if ($data['entries'] !== []) {
                $last = $data['entries'][count($data['entries']) - 1];
                $elapsed = $now - (float) $last['started_at'];
                if ($elapsed < self::MIN_SPACING_SECONDS) {
                    return;
                }
            }

            if (count($data['entries']) >= self::MAX_PER_WINDOW) {
                return;
            }

            $data['entries'][] = [
                'started_at' => $now,
                'category' => $category,
                'method' => $method,
                'path' => self::redact_path($urlpath),
                'status' => null,
            ];
            $acquired = true;
        });
        return $acquired;
    }

    /**
     * Drop ledger entries outside the rolling window.
     *
     * @param array{entries:array<int,array<string,mixed>>} $data Ledger.
     */
    private static function prune_old(array &$data): void {
        $cutoff = microtime(true) - self::WINDOW_SECONDS;
        $data['entries'] = array_values(array_filter(
            $data['entries'],
            static fn(array $e): bool => (float) $e['started_at'] >= $cutoff
        ));
    }

    /**
     * Read-modify-write the ledger under an exclusive file lock.
     *
     * @param callable(array):void $mutator Mutates ledger data.
     */
    private static function with_lock(callable $mutator): void {
        $path = self::ledger_path();
        $fp = fopen($path, 'c+');
        if ($fp === false) {
            throw new \RuntimeException('Cannot open live VT ledger.');
        }
        try {
            if (!flock($fp, LOCK_EX)) {
                throw new \RuntimeException('Cannot lock live VT ledger.');
            }
            $raw = stream_get_contents($fp);
            $data = ['entries' => []];
            if (is_string($raw) && $raw !== '') {
                $decoded = json_decode($raw, true);
                if (is_array($decoded) && isset($decoded['entries']) && is_array($decoded['entries'])) {
                    $data = $decoded;
                }
            }
            $mutator($data);
            fseek($fp, 0);
            ftruncate($fp, 0);
            fwrite($fp, json_encode($data));
            fflush($fp);
        } finally {
            flock($fp, LOCK_UN);
            fclose($fp);
        }
    }

    /**
     * Load ledger JSON without acquiring a lock.
     *
     * @return array{entries:array<int,array<string,mixed>>}
     */
    private static function read_data(): array {
        $path = self::ledger_path();
        if (!is_readable($path)) {
            return ['entries' => []];
        }
        $decoded = json_decode((string) file_get_contents($path), true);
        if (!is_array($decoded) || !isset($decoded['entries']) || !is_array($decoded['entries'])) {
            return ['entries' => []];
        }
        return $decoded;
    }

    /**
     * Resolve the on-disk ledger path under the PHPUnit cache directory.
     *
     * @return string
     */
    private static function ledger_path(): string {
        if (self::$ledgerpath !== '') {
            return self::$ledgerpath;
        }
        $base = dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . '.phpunit.cache';
        if (!is_dir($base)) {
            @mkdir($base, 0777, true);
        }
        self::$ledgerpath = $base . DIRECTORY_SEPARATOR . 'live_vt_request_ledger.json';
        return self::$ledgerpath;
    }

    /**
     * Redact hash and analysis identifiers from a URL for logging.
     *
     * @param string $url URL or path.
     * @return string
     */
    private static function redact_path(string $url): string {
        $parts = parse_url($url);
        if (!is_array($parts)) {
            return 'virustotal';
        }
        $host = $parts['host'] ?? 'virustotal.com';
        $path = $parts['path'] ?? '/';
        if (preg_match('#/files/([a-f0-9]{64})#i', $path)) {
            $path = preg_replace('#/files/[a-f0-9]{64}#i', '/files/{sha256}', $path);
        }
        if (preg_match('#/analyses/[a-z0-9_-]+#i', $path)) {
            $path = preg_replace('#/analyses/[a-z0-9_-]+#i', '/analyses/{id}', $path);
        }
        return $host . $path;
    }

    /**
     * Classify outbound URL for ledger category.
     *
     * @param string $method HTTP method.
     * @param string $url URL.
     * @return string
     */
    public static function categorize_url(string $method, string $url): string {
        $path = parse_url($url, PHP_URL_PATH) ?? '';
        if (str_contains($path, '/files/upload_url')) {
            return 'upload_url';
        }
        if ($method === 'POST' && str_ends_with($path, '/files')) {
            return 'upload';
        }
        if (str_contains($path, '/analyses/')) {
            return 'analysis_poll';
        }
        if (str_contains($path, '/files/')) {
            return 'hash_lookup';
        }
        return 'other';
    }
}
