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
 * Map provider detection counts to product status.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

use antivirus_verdict\scan_status;


/**
 * Conservative product status from normalised engine counts.
 *
 * Does not apply administrator numeric thresholds. Malicious outranks
 * suspicious. Missing stats are not treated as clean.
 */
class result_normaliser {
    /**
     * Product status from provider stats.
     *
     * @param array|null $stats Keys malicious, suspicious, undetected, harmless, timeout.
     * @return string|null Status, or null when stats cannot be classified.
     */
    public function status_from_stats(?array $stats): ?string {
        if ($stats === null) {
            return null;
        }
        $malicious = $this->optional_count($stats, 'malicious');
        $suspicious = $this->optional_count($stats, 'suspicious');
        $harmless = $this->optional_count($stats, 'harmless');
        $undetected = $this->optional_count($stats, 'undetected');
        if ($malicious === null && $suspicious === null && $harmless === null && $undetected === null) {
            return null;
        }
        if (($malicious ?? 0) > 0) {
            return scan_status::MALICIOUS;
        }
        if (($suspicious ?? 0) > 0) {
            return scan_status::SUSPICIOUS;
        }
        return scan_status::CLEAN;
    }

    /**
     * Copy known count keys, preserving null when a key is absent.
     *
     * @param array|null $stats Provider stats.
     * @return array{malicious:?int,suspicious:?int,undetected:?int,harmless:?int,timeout:?int,totalengines:?int}
     */
    public function persistable_counts(?array $stats): array {
        $malicious = $this->optional_count($stats ?? [], 'malicious');
        $suspicious = $this->optional_count($stats ?? [], 'suspicious');
        $undetected = $this->optional_count($stats ?? [], 'undetected');
        $harmless = $this->optional_count($stats ?? [], 'harmless');
        $timeout = $this->optional_count($stats ?? [], 'timeout');
        $parts = [$malicious, $suspicious, $undetected, $harmless, $timeout];
        $present = array_filter($parts, static fn($value) => $value !== null);
        $total = $present === [] ? null : array_sum($present);
        return [
            'malicious' => $malicious,
            'suspicious' => $suspicious,
            'undetected' => $undetected,
            'harmless' => $harmless,
            'timeout' => $timeout,
            'totalengines' => $total,
        ];
    }

    /**
     * Official public GUI URL for a SHA-256. No API key.
     *
     * @param string $sha256 Lowercase hex SHA-256.
     * @return string|null
     */
    public static function public_report_url(string $sha256): ?string {
        if (!preg_match('/^[a-f0-9]{64}$/', $sha256)) {
            return null;
        }
        return 'https://www.virustotal.com/gui/file/' . $sha256;
    }

    /**
     * Integer count when present and numeric.
     *
     * @param array $stats Stats array.
     * @param string $key Key.
     * @return int|null
     */
    private function optional_count(array $stats, string $key): ?int {
        if (!array_key_exists($key, $stats) || !is_numeric($stats[$key])) {
            return null;
        }
        return (int) $stats[$key];
    }
}
