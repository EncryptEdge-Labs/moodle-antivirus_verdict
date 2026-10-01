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
 * Adhoc task that processes one bulk or restore scan batch.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\task;

use antivirus_verdict\local\bulk_scan_service;
use antivirus_verdict\scan_source;
use core\task\adhoc_task;
use core\task\manager;


/**
 * Processes a slice of course files, then re-queues itself when more remain.
 */
class process_bulk_scan_batch extends adhoc_task {
    /**
     * Task name shown to administrators.
     *
     * @return string
     */
    public function get_name(): string {
        return get_string('task_process_bulk_scan', 'antivirus_verdict');
    }

    /**
     * Process one batch and optionally queue the next.
     */
    public function execute(): void {
        $data = $this->get_custom_data();
        if (!is_object($data)) {
            return;
        }

        $courseid = (int) ($data->courseid ?? 0);
        $userid = (int) ($data->userid ?? 0);
        $afterfileid = (int) ($data->afterfileid ?? 0);
        $onlymissing = !empty($data->onlymissing);
        $source = (string) ($data->source ?? scan_source::BULK);
        if (!scan_source::is_valid($source)) {
            $source = scan_source::BULK;
        }

        $service = bulk_scan_service::from_site_config();
        $next = $service->process_batch($courseid, $userid, $afterfileid, $onlymissing, $source);
        if ($next <= 0) {
            return;
        }

        $successor = new self();
        $successor->set_custom_data((object) [
            'courseid' => $courseid,
            'userid' => $userid,
            'afterfileid' => $next,
            'onlymissing' => $onlymissing,
            'source' => $source,
        ]);
        $successor->set_userid($userid);
        manager::queue_adhoc_task($successor, true);
    }
}
