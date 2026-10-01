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
 * Internal asynchronous scan phases.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;


/**
 * Internal lifecycle phases for the scanning engine.
 *
 * These values are not a second public product vocabulary. User-facing pages
 * should present {@see scan_status} instead.
 */
class scan_phase {
    /** Scan record created; work has not started. */
    public const QUEUED = 'queued';

    /** SHA-256 lookup against VirusTotal is in progress. */
    public const HASHLOOKUP = 'hashlookup';

    /** Hash is unknown; file upload is required. */
    public const UPLOADREQUIRED = 'uploadrequired';

    /** File (or rescan) has been submitted; analysis id is known. */
    public const SUBMITTED = 'submitted';

    /** Scheduled task is polling VirusTotal for completion. */
    public const POLLING = 'polling';

    /** Analysis finished and a verdict was stored. */
    public const COMPLETED = 'completed';

    /** Analysis failed after retries or a terminal provider error. */
    public const FAILED = 'failed';

    /** Scan was skipped by policy (size, disabled, unsupported). */
    public const SKIPPED = 'skipped';

    /**
     * Return all known internal phase values.
     *
     * @return string[]
     */
    public static function all(): array {
        return [
            self::QUEUED,
            self::HASHLOOKUP,
            self::UPLOADREQUIRED,
            self::SUBMITTED,
            self::POLLING,
            self::COMPLETED,
            self::FAILED,
            self::SKIPPED,
        ];
    }

    /**
     * Phases that represent an in-flight scan (not history).
     *
     * @return string[]
     */
    public static function active(): array {
        return [
            self::QUEUED,
            self::HASHLOOKUP,
            self::UPLOADREQUIRED,
            self::SUBMITTED,
            self::POLLING,
        ];
    }

    /**
     * Whether the phase is still in progress.
     *
     * @param string $phase Internal phase.
     * @return bool
     */
    public static function is_active(string $phase): bool {
        return in_array($phase, self::active(), true);
    }
}
