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
 * Scheduler that always uses the Moodle 4.5/5.0 successor-queue path.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\tests;

use core\task\adhoc_task;
use antivirus_verdict\local\adhoc_scan_scheduler;


/**
 * Forces delayed successor insertion even when soft retry exists.
 */
class legacy_retry_scheduler extends adhoc_scan_scheduler {
    /**
     * Never use set_soft_retry_delay.
     *
     * @param adhoc_task $task Current task.
     * @return bool
     */
    protected function can_soft_retry(adhoc_task $task): bool {
        return false;
    }
}
