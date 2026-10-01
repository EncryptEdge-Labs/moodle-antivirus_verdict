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
 * Re-queue or fail scans whose adhoc work was lost.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\task;

use core\task\scheduled_task;
use antivirus_verdict\local\scan_service;


/**
 * Recovery only. Does not poll VirusTotal or scan files itself.
 */
class recover_stale_scans extends scheduled_task {
    /**
     * Task name shown to administrators.
     *
     * @return string
     */
    public function get_name(): string {
        return get_string('task_recover_stale_scans', 'antivirus_verdict');
    }

    /**
     * Re-queue stuck scans or mark them stale. No VirusTotal HTTP.
     */
    public function execute(): void {
        scan_service::from_site_config()->recover_stale_scans();
    }
}
