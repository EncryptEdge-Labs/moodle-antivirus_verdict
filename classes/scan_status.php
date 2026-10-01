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
 * User-facing scan status values.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;


/**
 * Filterable scan statuses shown in Moodle.
 */
class scan_status {
    /** Scan requested; lookup, upload, or analysis is still in progress. */
    public const PENDING = 'pending';

    /** Analysis completed; detections meet the clean policy. */
    public const CLEAN = 'clean';

    /** Analysis completed; detections meet the suspicious policy. */
    public const SUSPICIOUS = 'suspicious';

    /** Analysis completed; detections meet the malicious policy. */
    public const MALICIOUS = 'malicious';

    /** Scan could not be completed. */
    public const ERROR = 'error';

    /** Intentionally skipped (disabled, too large, or policy skip). */
    public const NOTSCANNED = 'notscanned';

    /**
     * Return all known user-facing status values.
     *
     * @return string[]
     */
    public static function all(): array {
        return [
            self::PENDING,
            self::CLEAN,
            self::SUSPICIOUS,
            self::MALICIOUS,
            self::ERROR,
            self::NOTSCANNED,
        ];
    }

    /**
     * Whether the value is a known user-facing status.
     *
     * @param string $status Candidate status.
     * @return bool
     */
    public static function is_valid(string $status): bool {
        return in_array($status, self::all(), true);
    }

    /**
     * Statuses that must not be advanced by process_scan.
     *
     * @return string[]
     */
    public static function terminal(): array {
        return [
            self::CLEAN,
            self::SUSPICIOUS,
            self::MALICIOUS,
            self::ERROR,
            self::NOTSCANNED,
        ];
    }

    /**
     * Whether the status is a completed, failed, or skipped outcome.
     *
     * @param string $status Candidate status.
     * @return bool
     */
    public static function is_terminal(string $status): bool {
        return in_array($status, self::terminal(), true);
    }

    /**
     * User-facing status implied by an internal phase that has no verdict yet.
     *
     * @param string $phase Internal phase.
     * @return string|null Status, or null when the phase needs detection stats.
     */
    public static function for_phase(string $phase): ?string {
        if (scan_phase::is_active($phase)) {
            return self::PENDING;
        }
        if ($phase === scan_phase::FAILED) {
            return self::ERROR;
        }
        if ($phase === scan_phase::SKIPPED) {
            return self::NOTSCANNED;
        }
        return null;
    }
}
