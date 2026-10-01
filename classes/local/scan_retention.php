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
 * Site-wide scan history retention rules.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

use antivirus_verdict\enforcement_state;
use antivirus_verdict\scan_phase;
use antivirus_verdict\scan_status;


/**
 * Eligibility rules for purging historical scan rows.
 *
 * Retention is independent of the Privacy API. Privacy deletion removes personal
 * data on request; retention removes old history according to site policy.
 */
class scan_retention {
    /** Config key for retention in days. */
    public const CONFIG_DAYS = 'scanretentiondays';

    /** Automatic purge disabled. Stored explicitly as -1. */
    public const RETENTION_NEVER = -1;

    /** Default retention for completed history. */
    public const DEFAULT_DAYS = 365;

    /** Minimum retention when automatic purge is enabled. */
    public const MIN_DAYS = 1;

    /** Maximum retention period administrators may configure. */
    public const MAX_DAYS = 3650;

    /**
     * Load and normalise the configured retention period.
     *
     * @return int Days, or {@see RETENTION_NEVER}.
     */
    public static function days_from_config(): int {
        $raw = get_config('antivirus_verdict', self::CONFIG_DAYS);
        if ($raw === false || $raw === null || $raw === '') {
            return self::DEFAULT_DAYS;
        }
        return self::normalise_days((int) $raw);
    }

    /**
     * Normalise a posted or stored day count.
     *
     * Zero and other invalid values fall back to the default. Only -1 disables purge.
     *
     * @param int $days Requested retention.
     * @return int
     */
    public static function normalise_days(int $days): int {
        if ($days === self::RETENTION_NEVER) {
            return self::RETENTION_NEVER;
        }
        if ($days < self::MIN_DAYS) {
            return self::DEFAULT_DAYS;
        }
        if ($days > self::MAX_DAYS) {
            return self::MAX_DAYS;
        }
        return $days;
    }

    /**
     * Whether automatic retention purge is enabled.
     *
     * @param int|null $days Optional override.
     * @return bool
     */
    public static function purge_enabled(?int $days = null): bool {
        $days = $days ?? self::days_from_config();
        return $days !== self::RETENTION_NEVER;
    }

    /**
     * Unix timestamp before which terminal scans may be purged.
     *
     * @param int $now Current time.
     * @param int|null $days Retention days, or null for site config.
     * @return int|null Null when purge is disabled.
     */
    public static function cutoff_timestamp(int $now, ?int $days = null): ?int {
        $days = $days ?? self::days_from_config();
        if (!self::purge_enabled($days)) {
            return null;
        }
        return $now - ($days * DAYSECS);
    }

    /**
     * Reference time used to decide whether a row is old enough.
     *
     * @param \stdClass $record Scan row.
     * @return int
     */
    public static function reference_time(\stdClass $record): int {
        $completed = (int) ($record->timecompleted ?? 0);
        if ($completed > 0) {
            return $completed;
        }
        return (int) ($record->timemodified ?? 0);
    }

    /**
     * Whether a scan row may be purged under the retention policy.
     *
     * @param \stdClass $record Scan row.
     * @param int $now Current unix time.
     * @param int|null $days Retention days, or null for site config.
     * @return bool
     */
    public static function is_eligible(\stdClass $record, int $now, ?int $days = null): bool {
        $days = $days ?? self::days_from_config();
        if (!self::purge_enabled($days)) {
            return false;
        }
        if (scan_phase::is_active((string) $record->phase)) {
            return false;
        }
        if (
            !in_array((string) $record->phase, [
                scan_phase::COMPLETED,
                scan_phase::FAILED,
                scan_phase::SKIPPED,
            ], true)
        ) {
            return false;
        }
        if ((string) $record->status === scan_status::PENDING) {
            return false;
        }
        if ((string) $record->status === scan_status::MALICIOUS) {
            $enforcement = (string) ($record->enforcement ?? enforcement_state::NONE);
            if (
                $enforcement === enforcement_state::NONE
                || $enforcement === enforcement_state::PENDING
            ) {
                return false;
            }
        }
        $reference = self::reference_time($record);
        if ($reference <= 0) {
            return false;
        }
        $cutoff = self::cutoff_timestamp($now, $days);
        return $cutoff !== null && $reference < $cutoff;
    }
}
