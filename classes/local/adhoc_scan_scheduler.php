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
 * Queue adhoc processing for a submitted scan.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

use core\task\adhoc_task;
use core\task\manager;
use antivirus_verdict\task\process_scan;


/**
 * Schedules process_scan adhoc tasks. Tests may substitute a recorder.
 *
 * Moodle 5.1 and 5.2 can delay the running adhoc task in place with
 * set_soft_retry_delay. Moodle 4.5 and 5.0 delete the task after a successful
 * execute(), so a delayed successor must be inserted first. Do not use
 * checkforexisting or reschedule_or_queue_adhoc_task for that successor: both
 * would target the still-running row, which Moodle then deletes.
 */
class adhoc_scan_scheduler {
    /**
     * Queue background analysis retrieval for a scan id.
     *
     * The force flag is only written when set, so ordinary scans keep the
     * custom data shape that queue_adhoc_task() deduplicates on.
     *
     * @param int $scanid Scan record id.
     * @param bool $forcerescan Whether this scan must not reuse a stored verdict.
     */
    public function queue_scan(int $scanid, bool $forcerescan = false): bool {
        $task = new process_scan();
        $data = ['scanid' => $scanid];
        if ($forcerescan) {
            $data['force'] = true;
        }
        $task->set_custom_data($data);
        if (manager::queue_adhoc_task($task, true)) {
            return true;
        }
        return (bool) manager::queue_adhoc_task($task, false);
    }

    /**
     * Delay the next process_scan attempt by the retry policy interval.
     *
     * Must not return unless the next attempt is actually scheduled. A pending
     * scan must not be left without a worker.
     *
     * @param adhoc_task $task Current running process_scan task.
     * @param int $delayseconds Seconds until the next attempt.
     */
    public function schedule_retry(adhoc_task $task, int $delayseconds): void {
        if ($delayseconds <= 0) {
            throw new \coding_exception('Retry delay must be a positive number of seconds.');
        }
        if ($this->can_soft_retry($task)) {
            $task->set_soft_retry_delay($delayseconds);
            return;
        }
        $this->queue_delayed_successor($task, $delayseconds);
    }

    /**
     * Whether this Moodle build can delay the current adhoc task in place.
     *
     * @param adhoc_task $task Current task.
     * @return bool
     */
    protected function can_soft_retry(adhoc_task $task): bool {
        return method_exists($task, 'set_soft_retry_delay')
            && method_exists($task, 'is_adhoc_task_delayed');
    }

    /**
     * Insert a future process_scan row that survives deletion of the current task.
     *
     * @param adhoc_task $task Current running task.
     * @param int $delayseconds Seconds until the successor is due.
     */
    private function queue_delayed_successor(adhoc_task $task, int $delayseconds): void {
        $successor = new process_scan();
        $successor->set_custom_data($task->get_custom_data());
        $userid = $task->get_userid();
        if (!empty($userid)) {
            $successor->set_userid($userid);
        }
        $successor->set_next_run_time(time() + $delayseconds);
        // The running task is still in task_adhoc. checkforexisting would skip.
        $queued = manager::queue_adhoc_task($successor, false);
        if (!$queued) {
            debugging('antivirus_verdict: could not queue process_scan successor task', DEBUG_DEVELOPER);
        }
    }
}
