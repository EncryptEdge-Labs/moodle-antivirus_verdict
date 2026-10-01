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
 * Outcome of post-upload enforcement for a malicious verdict.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;


/**
 * What Verdict did about a malicious verdict, recorded per scan.
 *
 * This is a third, deliberately narrow vocabulary. It does not replace
 * {@see scan_status} (the verdict) or {@see scan_phase} (the scan lifecycle).
 * A scan can only carry a non-empty value here when its status is malicious.
 *
 * Every value except {@see self::NONE} is final. Enforcement is never retried
 * for a scan that already has an outcome, which is what makes repeated
 * asynchronous processing safe.
 */
class enforcement_state {
    /** No enforcement outcome recorded. The only state that may be enforced. */
    public const NONE = 'none';

    /** Detected synchronously at the upload gate; Moodle core blocked the upload. */
    public const BLOCKED = 'blocked';

    /** Enforcement began and did not conclude. Requires administrator review. */
    public const PENDING = 'pending';

    /** Content quarantined and the verified Moodle file was deleted. */
    public const QUARANTINED = 'quarantined';

    /** Content quarantined from a plugin-owned copy; no live Moodle file was removed. */
    public const QUARANTINEDCOPY = 'quarantinedcopy';

    /** Detected and reported only, by administrator policy. Nothing was removed. */
    public const REPORTED = 'reported';

    /** Moodle's antivirus quarantine is disabled, so nothing was removed. */
    public const QUARANTINEOFF = 'quarantineoff';

    /** The scanned file no longer exists, so there was nothing to enforce against. */
    public const FILEMISSING = 'filemissing';

    /** A file exists at the recorded identity but its content is not the scanned content. */
    public const MISMATCH = 'mismatch';

    /** Enforcement was attempted and raised an error. The file may still be present. */
    public const FAILED = 'failed';

    /**
     * Return all known enforcement outcomes, including the empty state.
     *
     * @return string[]
     */
    public static function all(): array {
        return [
            self::NONE,
            self::BLOCKED,
            self::PENDING,
            self::QUARANTINED,
            self::QUARANTINEDCOPY,
            self::REPORTED,
            self::QUARANTINEOFF,
            self::FILEMISSING,
            self::MISMATCH,
            self::FAILED,
        ];
    }

    /**
     * Whether the value is a known enforcement outcome.
     *
     * @param string $state Candidate outcome.
     * @return bool
     */
    public static function is_valid(string $state): bool {
        return in_array($state, self::all(), true);
    }

    /**
     * Whether enforcement may still run for this outcome.
     *
     * Only the empty state qualifies. In particular {@see self::PENDING} does
     * not: an interrupted enforcement may already have quarantined or deleted
     * the file, so retrying it could act twice.
     *
     * @param string $state Recorded outcome.
     * @return bool
     */
    public static function requires_enforcement(string $state): bool {
        $state = trim($state);
        return $state === '' || $state === self::NONE;
    }

    /**
     * Whether the malicious content was captured for administrator review.
     *
     * @param string $state Recorded outcome.
     * @return bool
     */
    public static function is_quarantined(string $state): bool {
        return $state === self::QUARANTINED || $state === self::QUARANTINEDCOPY;
    }
}
