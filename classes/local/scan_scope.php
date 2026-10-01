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
 * Product scanning scope for the native upload gate.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;


/**
 * Whether a native upload may enter provider analysis.
 *
 * Selected areas does not name the activity. Moodle has not established that
 * context when the antivirus gate runs.
 */
class scan_scope {
    /** Check every upload through the existing gate. */
    public const EVERY_UPLOAD = 'everyupload';

    /** Defer provider work to enabled contextual scanners. */
    public const SELECTED_AREAS = 'selectedareas';

    /**
     * Normalise a stored or posted scope.
     *
     * An empty or unknown value stays on every-upload so existing sites keep
     * upload-time protection.
     *
     * @param string $value Candidate scope.
     * @return string
     */
    public static function normalise(string $value): string {
        $value = strtolower(trim($value));
        if ($value === self::SELECTED_AREAS) {
            return self::SELECTED_AREAS;
        }
        return self::EVERY_UPLOAD;
    }
}
