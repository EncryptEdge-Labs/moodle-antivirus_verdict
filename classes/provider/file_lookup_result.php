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
 * Known-file lookup outcome. Does not apply Moodle clean/malicious policy.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\provider;


/**
 * Normalised hash lookup result.
 */
final class file_lookup_result {
    /** @var bool Whether VirusTotal has a file object for the hash. */
    public readonly bool $found;
    /** @var string|null SHA-256 from the provider, when found. */
    public readonly ?string $sha256;
    /** @var array|null Engine counts when present. */
    public readonly ?array $lastanalysisstats;
    /** @var int|null Unix time of last analysis, when present. */
    public readonly ?int $lastanalysistime;
    /** @var string|null Provider filename hint, when present. */
    public readonly ?string $meaningfulname;

    /**
     * Create a hash lookup result.
     *
     * @param bool $found Whether VirusTotal has a file object for the hash.
     * @param string|null $sha256 SHA-256 from the provider, when found.
     * @param array|null $lastanalysisstats Engine counts when present.
     * @param int|null $lastanalysistime Unix time of last analysis, when present.
     * @param string|null $meaningfulname Provider filename hint, when present.
     */
    public function __construct(
        bool $found,
        ?string $sha256 = null,
        ?array $lastanalysisstats = null,
        ?int $lastanalysistime = null,
        ?string $meaningfulname = null
    ) {
        $this->found = $found;
        $this->sha256 = $sha256;
        $this->lastanalysisstats = $lastanalysisstats;
        $this->lastanalysistime = $lastanalysistime;
        $this->meaningfulname = $meaningfulname;
    }

    /**
     * Unknown hash (HTTP 404 from the file object endpoint).
     *
     * @param string $sha256 Requested hash.
     * @return self
     */
    public static function not_found(string $sha256): self {
        return new self(false, $sha256);
    }
}
