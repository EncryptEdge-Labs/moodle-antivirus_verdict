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
 * Provider analysis state. Product clean/malicious policy is applied later.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\provider;


/**
 * Normalised analysis retrieval result.
 */
final class analysis_result {
    /** @var string Analysis identifier. */
    public readonly string $id;
    /** @var string Provider analysis status (queued, completed, ...). */
    public readonly string $status;
    /** @var array|null Engine counts when the provider supplies them. */
    public readonly ?array $stats;

    /**
     * Create a normalised analysis result.
     *
     * @param string $id Analysis identifier.
     * @param string $status Provider analysis status (queued, completed, ...).
     * @param array|null $stats Engine counts when the provider supplies them.
     */
    public function __construct(string $id, string $status, ?array $stats = null) {
        $this->id = $id;
        $this->status = $status;
        $this->stats = $stats;
    }
}
