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
 * Reservation store that cannot decide whether a slot is available.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\tests;

use antivirus_verdict\local\operation_reservation;
use antivirus_verdict\local\reservation_result;

/**
 * Used to prove a reservation failure does not call the provider or mark a file clean.
 */
class failing_operation_reservation extends operation_reservation {
    /**
     * Storage cannot answer.
     *
     * @param int $ceiling Local ceiling.
     * @return reservation_result
     */
    public function reserve_poll(int $ceiling): reservation_result {
        return new reservation_result(reservation_result::FAILED);
    }
}
