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
 * Scan service double that fails enqueue for assignment tests.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\tests;

use antivirus_verdict\local\scan_service;
use antivirus_verdict\provider\provider_exception;


/**
 * Throws on enqueue so assignment handling can prove it does not fatal.
 */
class throwing_scan_service extends scan_service {
    /**
     * Always fail as a network error.
     *
     * @param \stored_file $file Moodle file.
     * @param string $source Scan source.
     * @param int $userid Associated user.
     * @param bool $forcerescan Whether a stored verdict must not be reused.
     * @param int $parentscanid Container scan id for archive members.
     * @param string|null $auditfilepath Member path inside container for audit.
     * @param int $submissionid Assignment submission id when known.
     * @param int $initiatedby Scan operator when distinct from userid.
     * @return \stdClass
     */
    public function enqueue_file_scan(
        \stored_file $file,
        string $source,
        int $userid = 0,
        bool $forcerescan = false,
        int $parentscanid = 0,
        ?string $auditfilepath = null,
        int $submissionid = 0,
        int $initiatedby = 0
    ): \stdClass {
        throw new provider_exception('error_network');
    }
}
