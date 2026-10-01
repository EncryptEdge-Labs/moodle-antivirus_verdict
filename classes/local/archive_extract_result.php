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
 * Result of a bounded archive extraction pass.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;


/**
 * Plain result object for archive_extractor.
 */
class archive_extract_result {
    /** @var bool Whether any members were extracted for scanning. */
    public bool $hasscanmembers = false;

    /** @var bool Extraction stopped because a limit was reached. */
    public bool $limitsexceeded = false;

    /** @var bool Archive could not be inspected (corrupt, encrypted, unsupported). */
    public bool $uninspectable = false;

    /** @var string Stable reason when uninspectable or limited. */
    public string $reason = '';

    /**
     * Extracted regular files ready for scanning.
     *
     * Each element: abspath, relpath, size, depth.
     *
     * @var array<int, array{abspath:string,relpath:string,size:int,depth:int}>
     */
    public array $members = [];

    /**
     * Members that were not queued, with a stable reason.
     *
     * Directory entries and zero-length entries are not recorded. A reason of
     * error_archive_member means a real file could not be extracted.
     * error_archive_limits means the declared size was rejected before inflate.
     *
     * @var array<int, array{relpath:string,reason:string}>
     */
    public array $skipped = [];

    /**
     * Internal helper.
     *
     * @param bool $hasscanmembers Whether scan members exist.
     * @param bool $limitsexceeded Whether limits were hit.
     * @param bool $uninspectable Whether the archive could not be inspected.
     * @param string $reason Stable reason code.
     * @param array $members Member descriptors.
     * @param array $skipped Skipped member descriptors.
     */
    public function __construct(
        bool $hasscanmembers = false,
        bool $limitsexceeded = false,
        bool $uninspectable = false,
        string $reason = '',
        array $members = [],
        array $skipped = []
    ) {
        $this->hasscanmembers = $hasscanmembers;
        $this->limitsexceeded = $limitsexceeded;
        $this->uninspectable = $uninspectable;
        $this->reason = $reason;
        $this->members = $members;
        $this->skipped = $skipped;
    }
}
