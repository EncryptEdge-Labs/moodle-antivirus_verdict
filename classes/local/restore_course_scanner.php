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
 * Post-restore course file scanning.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

use antivirus_verdict\scan_source;


/**
 * Queues a restore sweep using the bulk scan engine with a restore source label.
 */
class restore_course_scanner {
    /** @var bulk_scan_service Bulk engine. */
    private bulk_scan_service $bulk;

    /** @var plugin_config Operational settings. */
    private plugin_config $config;

    /**
     * Create a restore scanner.
     *
     * @param bulk_scan_service $bulk Bulk engine.
     * @param plugin_config $config Operational settings.
     */
    public function __construct(bulk_scan_service $bulk, plugin_config $config) {
        $this->bulk = $bulk;
        $this->config = $config;
    }

    /**
     * Production scanner using site configuration.
     *
     * @return self
     */
    public static function from_site_config(): self {
        return new self(bulk_scan_service::from_site_config(), plugin_config::from_site_config());
    }

    /**
     * Queue scanning for files materialised by a course restore.
     *
     * @param int $courseid Restored course id.
     * @param int $userid User who performed the restore.
     * @return bool
     */
    public function queue_course(int $courseid, int $userid): bool {
        if (!$this->config->restore_auto_scan_enabled() || $courseid <= 0) {
            return false;
        }
        return $this->bulk->queue_course_sweep($courseid, $userid, true, scan_source::RESTORE);
    }
}
