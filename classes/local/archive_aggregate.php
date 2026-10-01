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
 * Aggregate verdict precedence for archive member scans.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

use antivirus_verdict\archive_outcome;
use antivirus_verdict\scan_status;


/**
 * Combines member scan statuses into a container-facing status and outcome.
 */
class archive_aggregate {
    /**
     * Status precedence rank (higher wins).
     *
     * malicious > suspicious > error > pending/notscanned > clean
     *
     * @param string $status Scan status.
     * @return int
     */
    public static function status_rank(string $status): int {
        return match ($status) {
            scan_status::MALICIOUS => 500,
            scan_status::SUSPICIOUS => 400,
            scan_status::ERROR => 300,
            scan_status::PENDING => 200,
            scan_status::NOTSCANNED => 150,
            scan_status::CLEAN => 100,
            default => 0,
        };
    }

    /**
     * Pick the highest-precedence status from member rows.
     *
     * @param \stdClass[] $children Member scan records.
     * @return string
     */
    public static function aggregate_status(array $children): string {
        $best = scan_status::CLEAN;
        $rank = self::status_rank($best);
        foreach ($children as $child) {
            $status = (string) ($child->status ?? '');
            if (!scan_status::is_valid($status)) {
                continue;
            }
            $childrank = self::status_rank($status);
            if ($childrank > $rank) {
                $rank = $childrank;
                $best = $status;
            }
        }
        return $best;
    }

    /**
     * Whether any child scan is still active.
     *
     * @param \stdClass[] $children Member scan records.
     * @return bool
     */
    public static function has_active_children(array $children): bool {
        foreach ($children as $child) {
            if (\antivirus_verdict\scan_phase::is_active((string) ($child->phase ?? ''))) {
                return true;
            }
            if ((string) ($child->status ?? '') === scan_status::PENDING) {
                return true;
            }
        }
        return false;
    }

    /**
     * Resolve archive outcome for a finished member pass.
     *
     * @param bool $limitsexceeded Whether extraction hit limits.
     * @param bool $uninspectable Whether the archive could not be inspected.
     * @param \stdClass[] $children Member scans.
     * @return string archive_outcome constant.
     */
    public static function resolve_outcome(
        bool $limitsexceeded,
        bool $uninspectable,
        array $children
    ): string {
        if ($uninspectable) {
            return archive_outcome::EXTRACT_ERROR;
        }
        if ($limitsexceeded) {
            return archive_outcome::INCOMPLETE;
        }
        if (self::has_active_children($children)) {
            return archive_outcome::PROCESSING;
        }
        return archive_outcome::COMPLETE;
    }

    /**
     * Merge container VirusTotal status with member aggregate (take worse).
     *
     * @param string $containerstatus Current container scan status.
     * @param string $memberaggregate Aggregated member status.
     * @return string
     */
    public static function merge_container_status(string $containerstatus, string $memberaggregate): string {
        if (self::status_rank($memberaggregate) >= self::status_rank($containerstatus)) {
            return $memberaggregate;
        }
        return $containerstatus;
    }

    /**
     * Stable error code from the member that made the aggregate an error.
     *
     * When several children are errors, the lowest scan id with a non-empty
     * error code wins. This does not invent a new error taxonomy.
     *
     * @param \stdClass[] $children Member scan records.
     * @return string|null
     */
    public static function winning_errorcode(array $children): ?string {
        $bestid = null;
        $code = null;
        foreach ($children as $child) {
            if ((string) ($child->status ?? '') !== scan_status::ERROR) {
                continue;
            }
            $childcode = trim((string) ($child->errorcode ?? ''));
            if ($childcode === '') {
                continue;
            }
            $id = (int) ($child->id ?? 0);
            if ($bestid === null || $id < $bestid) {
                $bestid = $id;
                $code = $childcode;
            }
        }
        return $code;
    }
}
