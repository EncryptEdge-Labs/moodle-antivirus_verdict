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
 * VirusTotal credential provider contract.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;


/**
 * Supplies the site VirusTotal API key from trusted server-side configuration.
 *
 * Callers must never accept an API key from request, session, or browser data.
 */
interface credential_provider {
    /**
     * Return the configured API key.
     *
     * @return string Non-empty API key.
     * @throws \antivirus_verdict\provider\provider_exception When no key is configured.
     */
    public function get_api_key(): string;

    /**
     * Whether a non-empty API key is configured.
     *
     * @return bool
     */
    public function has_api_key(): bool;
}
