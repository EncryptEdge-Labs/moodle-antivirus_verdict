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
 * Notifier that records calls and can throw without touching the scan row.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\tests;

use antivirus_verdict\local\plugin_config;
use antivirus_verdict\local\scan_notifications;

/**
 * Captures scan_finished calls for lifecycle tests.
 */
class recording_notifier extends scan_notifications {
    /** @var int Calls observed. */
    public int $calls = 0;

    /** @var string[] Status values passed to scan_finished. */
    public array $statuses = [];

    /** @var bool When true, scan_finished throws after recording the call. */
    public bool $throw = false;

    /**
     * Create a recording notifier.
     *
     * @param plugin_config|null $config Operational settings.
     */
    public function __construct(?plugin_config $config = null) {
        parent::__construct($config ?? plugin_config::from_site_config());
    }

    /**
     * Record the call. Does not send Moodle messages.
     *
     * @param \stdClass $record Scan row after persistence.
     */
    public function scan_finished(\stdClass $record): void {
        $this->calls++;
        $this->statuses[] = (string) $record->status;
        if ($this->throw) {
            throw new \moodle_exception('error_generic', 'antivirus_verdict');
        }
    }
}
