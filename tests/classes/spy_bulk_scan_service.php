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
 * Records bulk sweep arguments without queuing adhoc tasks.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\tests;

use antivirus_verdict\local\bulk_scan_service;
use antivirus_verdict\local\plugin_config;
use antivirus_verdict\local\scan_repository;
use antivirus_verdict\local\scan_service;


/**
 * Spy for restore/bulk integration tests.
 */
class spy_bulk_scan_service extends bulk_scan_service {
    /** @var array<int, array{0:int,1:int,2:bool,3:string}> Recorded queue_course_sweep calls. */
    public array $sweepcalls = [];

    /**
     * Internal helper.
     *
     * @param int $courseid Target course.
     * @param int $userid Requesting user.
     * @param bool $onlymissing Skip completed rows.
     * @param string $source Scan source label.
     * @return bool
     */
    public function queue_course_sweep(
        int $courseid,
        int $userid,
        bool $onlymissing = true,
        string $source = \antivirus_verdict\scan_source::BULK
    ): bool {
        $this->sweepcalls[] = [$courseid, $userid, $onlymissing, $source];
        return $this->can_start() && $courseid > 0;
    }
}
