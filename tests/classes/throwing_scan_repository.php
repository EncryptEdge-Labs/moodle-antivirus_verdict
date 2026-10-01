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
 * Repository whose completed-verdict read fails.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\tests;

use antivirus_verdict\local\scan_repository;


/**
 * Forces the native-gate local lookup to fail while inserts still persist.
 */
class throwing_scan_repository extends scan_repository {
    /**
     * Fail the completed-verdict read.
     *
     * @param string $sha256 Hex SHA-256.
     * @return \stdClass|null
     */
    public function find_completed_verdict_by_sha256(string $sha256): ?\stdClass {
        throw new \RuntimeException('local verdict lookup failed');
    }
}
