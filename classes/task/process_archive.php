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
 * Adhoc task: extract archive members and queue scans.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\task;

use antivirus_verdict\local\archive_scanner;


/**
 * Runs bounded archive extraction outside the process_scan request path.
 */
class process_archive extends \core\task\adhoc_task {
    /**
     * Extract members and queue child scans for one container scan id.
     */
    public function execute(): void {
        $data = $this->get_custom_data();
        $scanid = is_object($data) ? (int) ($data->scanid ?? 0) : 0;
        if ($scanid <= 0) {
            return;
        }
        archive_scanner::from_site_config()->process_container($scanid);
    }
}
