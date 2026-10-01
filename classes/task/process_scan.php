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
 * Adhoc task that retrieves a VirusTotal analysis for one scan.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\task;

use core\task\adhoc_task;
use antivirus_verdict\local\scan_service;


/**
 * Processes a previously authorised scan.
 *
 * Custom data may contain only scanid and the optional force flag set by an
 * explicit rescan. It never carries file content or credentials.
 */
class process_scan extends adhoc_task {
    /**
     * Task name shown to administrators.
     *
     * @return string
     */
    public function get_name(): string {
        return get_string('task_process_scan', 'antivirus_verdict');
    }

    /**
     * Load the scan id and continue analysis retrieval.
     */
    public function execute(): void {
        $data = $this->get_custom_data();
        $scanid = 0;
        $force = false;
        if (is_object($data) && isset($data->scanid)) {
            $scanid = (int) $data->scanid;
            $force = !empty($data->force);
        } else if (is_array($data) && isset($data['scanid'])) {
            $scanid = (int) $data['scanid'];
            $force = !empty($data['force']);
        }
        if ($scanid <= 0) {
            return;
        }

        $service = scan_service::from_site_config();
        $service->process_scan($scanid, $this, $force);
    }
}
