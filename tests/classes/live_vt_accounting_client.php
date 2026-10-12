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
 * VirusTotal client that accounts for every outbound HTTP request in live certification.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\tests;

use antivirus_verdict\provider\virustotal\client;
use Psr\Http\Message\ResponseInterface;


/**
 * Wraps {@see client::send()} with the shared live VT ledger (test-only).
 */
final class live_vt_accounting_client extends client {
    /**
     * Perform HTTP via parent while recording the request in the live VT ledger.
     *
     * @param string $method HTTP method.
     * @param string $url URL.
     * @param array $options Options.
     * @param bool $forceprobe Force probe flag.
     * @return ResponseInterface
     */
    protected function send(
        string $method,
        string $url,
        array $options,
        bool $forceprobe = false
    ): ResponseInterface {
        $category = live_vt_request_ledger::categorize_url($method, $url);
        live_vt_request_ledger::acquire_slot($category, $method, $url);
        try {
            $response = parent::send($method, $url, $options, $forceprobe);
            live_vt_request_ledger::record_response_status($response->getStatusCode());
            return $response;
        } catch (\Throwable $e) {
            live_vt_request_ledger::record_response_status(0);
            throw $e;
        }
    }
}
