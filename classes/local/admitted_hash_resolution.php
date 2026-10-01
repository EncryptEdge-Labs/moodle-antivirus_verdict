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
 * Outcome of one admitted hash resolution.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

use antivirus_verdict\provider\file_lookup_result;


/**
 * Local reuse, an in-flight join, or a provider hash lookup.
 *
 * The native gate applies Moodle's upload result. It does not call the provider.
 */
class admitted_hash_resolution {
    /** A completed reusable verdict already exists. */
    public const REUSED = 'reused';

    /** An in-flight scan of this SHA already exists. */
    public const JOINED = 'joined';

    /** The provider hash lookup ran. */
    public const LOOKUP = 'lookup';

    /** @var string reused, joined, or lookup. */
    public readonly string $kind;

    /** @var \stdClass|null Local scan row for reuse or join. */
    public readonly ?\stdClass $row;

    /** @var file_lookup_result|null Provider lookup when kind is lookup. */
    public readonly ?file_lookup_result $lookup;

    /**
     * Create a resolution.
     *
     * @param string $kind Resolution kind.
     * @param \stdClass|null $row Local row.
     * @param file_lookup_result|null $lookup Provider lookup.
     */
    public function __construct(
        string $kind,
        ?\stdClass $row = null,
        ?file_lookup_result $lookup = null
    ) {
        $this->kind = $kind;
        $this->row = $row;
        $this->lookup = $lookup;
    }
}
