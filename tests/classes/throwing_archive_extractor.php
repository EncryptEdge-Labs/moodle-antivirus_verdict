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
 * Archive extractor that fails during extraction for cleanup tests.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\tests;

use antivirus_verdict\local\archive_extract_result;
use antivirus_verdict\local\archive_extractor;
use antivirus_verdict\local\archive_limits;


/**
 * Records the work directory then throws so callers can assert finally cleanup.
 */
class throwing_archive_extractor extends archive_extractor {
    /** @var string Last work directory passed to extract_zip_path. */
    public string $lastworkdir = '';

    /**
     * Create a throwing extractor with loose limits for unit tests.
     */
    public function __construct() {
        parent::__construct(new archive_limits(50, 1, 1024 * 1024, 1024 * 1024));
    }

    /**
     * Internal helper.
     *
     * @param string $zippath Temp zip path.
     * @param string $workdir Extraction directory.
     * @param int|null $deadline Unused.
     * @return archive_extract_result
     */
    public function extract_zip_path(
        string $zippath,
        string $workdir,
        ?int $deadline = null
    ): archive_extract_result {
        $this->lastworkdir = $workdir;
        throw new \RuntimeException('simulated extract failure');
    }
}
