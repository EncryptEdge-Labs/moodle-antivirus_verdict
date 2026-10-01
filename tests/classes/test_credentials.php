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
 * Test double for VirusTotal credentials.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\tests;

use antivirus_verdict\local\credential_provider;
use antivirus_verdict\provider\provider_exception;


/**
 * In-memory credentials for PHPUnit. Never used in production.
 */
class test_credentials implements credential_provider {
    /** @var string Fake API key. */
    private string $key;

    /**
     * Create in-memory credentials.
     *
     * @param string $key Fake API key.
     */
    public function __construct(string $key) {
        $this->key = $key;
    }

    /**
     * Return the fake API key.
     *
     * @return string
     */
    public function get_api_key(): string {
        if ($this->key === '') {
            throw new provider_exception('error_nokey');
        }
        return $this->key;
    }

    /**
     * Whether a non-empty fake key was supplied.
     *
     * @return bool
     */
    public function has_api_key(): bool {
        return $this->key !== '';
    }
}
