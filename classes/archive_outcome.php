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
 * Archive member-scan lifecycle outcomes on container scan rows.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;


/**
 * Values stored in antivirus_verdict_scans.archiveoutcome for container scans.
 */
class archive_outcome {
    /** Container scan is not an archive parent or member phase has not started. */
    public const NONE = '';

    /** Member extraction or child scans are in progress. */
    public const PROCESSING = 'processing';

    /** All planned members were scanned; aggregate verdict applied. */
    public const COMPLETE = 'complete';

    /** Scanning stopped early (limits, partial extraction). Aggregate is not "clean-only". */
    public const INCOMPLETE = 'incomplete';

    /** Format is not supported with portable PHP (7z, RAR, etc.). */
    public const UNSUPPORTED = 'unsupported';

    /** Archive could not be opened or extracted safely. */
    public const EXTRACT_ERROR = 'extract_error';

    /**
     * Known archive outcome values.
     *
     * @return string[]
     */
    public static function all(): array {
        return [
            self::NONE,
            self::PROCESSING,
            self::COMPLETE,
            self::INCOMPLETE,
            self::UNSUPPORTED,
            self::EXTRACT_ERROR,
        ];
    }
}
