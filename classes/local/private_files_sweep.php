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
 * Automated sweep of user private files.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

use antivirus_verdict\scan_source;


/**
 * Queues newly stored private files since the last successful sweep.
 */
class private_files_sweep {
    /** Config key storing the last sweep unix time. */
    public const CONFIG_LAST_RUN = 'privatesweep_lastrun';

    /** Maximum files processed per scheduled run. */
    public const BATCH_LIMIT = 100;

    /** @var file_area_scanner File consumer. */
    private file_area_scanner $scanner;

    /** @var plugin_config Operational settings. */
    private plugin_config $config;

    /**
     * Internal helper.
     *
     * @param file_area_scanner $scanner File consumer.
     * @param plugin_config $config Operational settings.
     */
    public function __construct(file_area_scanner $scanner, plugin_config $config) {
        $this->scanner = $scanner;
        $this->config = $config;
    }

    /**
     * Internal helper.
     *
     * @return self
     */
    public static function from_site_config(): self {
        return new self(file_area_scanner::from_site_config(), plugin_config::from_site_config());
    }

    /**
     * Process one scheduled batch.
     *
     * @return int Number of files queued.
     */
    public function run_scheduled_batch(): int {
        if (!$this->config->private_auto_scan_enabled()) {
            return 0;
        }

        global $DB;
        $since = (int) get_config('antivirus_verdict', self::CONFIG_LAST_RUN);
        if ($since <= 0) {
            $since = time() - DAYSECS;
        }

        $now = time();
        $records = $DB->get_records_select(
            'files',
            "component = :component AND filearea = :filearea AND filename <> '.'
                AND filesize > 0 AND timecreated > :since AND timecreated <= :now",
            [
                'component' => 'user',
                'filearea' => 'private',
                'since' => $since,
                'now' => $now,
            ],
            'timecreated ASC, id ASC',
            'id, contextid, userid',
            0,
            self::BATCH_LIMIT
        );

        $fs = get_file_storage();
        $queued = 0;
        foreach ($records as $record) {
            $file = $fs->get_file_by_id((int) $record->id);
            if (!$file) {
                continue;
            }
            if ($this->scanner->queue_file($file, scan_source::PRIVATE, (int) $record->userid)) {
                $queued++;
            }
        }

        set_config(self::CONFIG_LAST_RUN, $now, 'antivirus_verdict');
        return $queued;
    }
}
