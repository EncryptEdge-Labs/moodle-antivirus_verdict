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
 * Notification double that always fails delivery.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\tests;

use antivirus_verdict\local\scan_notifications;


/**
 * Throws from scan_finished so tests can prove verdicts stay intact.
 */
class throwing_notifications extends scan_notifications {
    /** @var int How many times scan_finished was invoked. */
    public int $calls = 0;

    /**
     * Always fail after recording the attempt.
     *
     * @param \stdClass $record Scan row.
     */
    public function scan_finished(\stdClass $record): void {
        $this->calls++;
        throw new \moodle_exception('error_generic', 'antivirus_verdict');
    }
}
