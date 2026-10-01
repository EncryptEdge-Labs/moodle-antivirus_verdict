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
 * Testable VirusTotal client with seams for PHPUnit.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\tests;

use antivirus_verdict\provider\virustotal\client;


/**
 * Exposes protected URL helpers and reduced upload thresholds for tests.
 */
class testable_vt_client extends client {
    /** @var int|null Override for the direct-upload threshold. */
    public ?int $directmax = null;

    /** @var int|null Override for the large-upload threshold. */
    public ?int $largemax = null;

    /**
     * Expose URL construction for tests.
     *
     * @param string $path Relative path.
     * @return string
     */
    public function public_build_api_url(string $path): string {
        return $this->build_api_url($path);
    }

    /**
     * Expose upload URL host validation for tests.
     *
     * @param string $url Candidate URL.
     */
    public function public_assert_upload_url(string $url): void {
        $this->assert_virustotal_upload_url($url);
    }

    /**
     * Expose Retry-After parsing for tests.
     *
     * @param \Psr\Http\Message\ResponseInterface $response HTTP response.
     * @return int|null
     */
    public function public_parse_retry_after(\Psr\Http\Message\ResponseInterface $response): ?int {
        return $this->parse_retry_after($response);
    }

    /**
     * Direct-upload size limit, optionally overridden in tests.
     *
     * @return int
     */
    protected function get_direct_upload_max(): int {
        return $this->directmax ?? parent::get_direct_upload_max();
    }

    /**
     * Large-upload size limit, optionally overridden in tests.
     *
     * @return int
     */
    protected function get_large_upload_max(): int {
        return $this->largemax ?? parent::get_large_upload_max();
    }
}
