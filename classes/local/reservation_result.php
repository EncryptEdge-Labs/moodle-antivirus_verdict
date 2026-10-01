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
 * Outcome of one provider-operation reservation.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

/**
 * Allowed, ceiling denied, or reservation storage failed.
 *
 * These are distinct. A boolean cannot represent both a reached ceiling
 * and a database failure.
 */
final class reservation_result {
    /** The slot was reserved, or the local ceiling is disabled. */
    public const ALLOWED = 'allowed';

    /** The local ceiling is already consumed. No provider call is authorised. */
    public const DENIED = 'denied';

    /** Reservation state could not be read or written. */
    public const FAILED = 'failed';

    /** @var string allowed, denied, or failed. */
    public readonly string $outcome;

    /**
     * Store the reservation outcome.
     *
     * @param string $outcome Reservation outcome.
     */
    public function __construct(string $outcome) {
        $this->outcome = $outcome;
    }
}
