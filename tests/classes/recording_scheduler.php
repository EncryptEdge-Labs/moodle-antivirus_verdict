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
 * Records queued scan ids instead of writing Moodle adhoc tasks.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\tests;

use core\task\adhoc_task;
use antivirus_verdict\local\adhoc_scan_scheduler;


/**
 * Test scheduler that does not touch the task queue.
 */
class recording_scheduler extends adhoc_scan_scheduler {
    /** @var int[] Queued scan ids. */
    public array $queued = [];
    /** @var int[] Requested retry delays in seconds. */
    public array $retries = [];
    /** @var int[] Scan ids queued with the forced-rescan flag. */
    public array $forced = [];

    /**
     * Record the scan id and whether a forced rescan was requested.
     *
     * @param int $scanid Scan record id.
     * @param bool $forcerescan Whether the stored verdict must not be reused.
     */
    public function queue_scan(int $scanid, bool $forcerescan = false): bool {
        $this->queued[] = $scanid;
        if ($forcerescan) {
            $this->forced[] = $scanid;
        }
        return true;
    }

    /**
     * Record the delay and, for recording_task, the softdelay property.
     *
     * @param adhoc_task $task Current task.
     * @param int $delayseconds Seconds.
     */
    public function schedule_retry(adhoc_task $task, int $delayseconds): void {
        $this->retries[] = $delayseconds;
        if ($task instanceof recording_task) {
            $task->softdelay = $delayseconds;
        }
    }
}
