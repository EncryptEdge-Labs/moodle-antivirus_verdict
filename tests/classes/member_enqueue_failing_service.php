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

namespace antivirus_verdict\tests;

use antivirus_verdict\local\scan_service;

/**
 * Scan service that fails enqueue for one archive member filename.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class member_enqueue_failing_service extends scan_service {
    /** @var string Member filename whose enqueue must throw. */
    public string $failfilename = '';

    /**
     * Enqueue a file, or throw for the configured member name.
     *
     * @param \stored_file $file Moodle file.
     * @param string $source Scan source.
     * @param int $userid User id.
     * @param bool $forcerescan Whether to skip stored-verdict reuse.
     * @param int $parentscanid Container scan id.
     * @param string|null $auditfilepath Archive-internal directory.
     * @param int $submissionid Assignment submission id.
     * @param int $initiatedby Initiating user id.
     * @return \stdClass
     */
    public function enqueue_file_scan(
        \stored_file $file,
        string $source,
        int $userid = 0,
        bool $forcerescan = false,
        int $parentscanid = 0,
        ?string $auditfilepath = null,
        int $submissionid = 0,
        int $initiatedby = 0
    ): \stdClass {
        if ($this->failfilename !== '' && $file->get_filename() === $this->failfilename) {
            throw new \RuntimeException('member enqueue failed');
        }
        return parent::enqueue_file_scan(
            $file,
            $source,
            $userid,
            $forcerescan,
            $parentscanid,
            $auditfilepath,
            $submissionid,
            $initiatedby
        );
    }
}
