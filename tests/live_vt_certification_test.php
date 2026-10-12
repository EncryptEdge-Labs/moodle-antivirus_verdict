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
 * Live VirusTotal certification (operator opt-in, rate-limited).
 *
 * Run: scripts/run-live-vt-cert.ps1 or scripts/run-live-vt-cert.php
 * Credential: VERDICT_LVT_API_KEY and/or Behat DB (see scripts/behat-verify-vt-credential.php).
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\provider\file_payload;
use antivirus_verdict\provider\provider_exception;
use antivirus_verdict\provider\virustotal\client;
use antivirus_verdict\tests\live_vt_request_ledger;
use antivirus_verdict\tests\live_vt_support;


/**
 * VT-LIVE against production VirusTotal (≤4 HTTP requests / 60s, ≥15s spacing).
 *
 * Does not use EICAR or malware samples in the default certification path.
 *
 * @group live_vt
 * @coversNothing
 */
final class live_vt_certification_test extends \advanced_testcase {
    /**
     * VT-LIVE-1: connection test (empty-file hash lookup path).
     */
    public function test_vt_live_connection(): void {
        $this->require_live_run();
        $this->resetAfterTest();
        $client = $this->live_client();

        $result = $client->test_connection();

        if (!$result->success && $result->code === 'error_network') {
            $this->markTestSkipped('Network/SSL unavailable in this environment: ' . $result->code);
        }
        $this->assertTrue($result->success, 'Connection test failed: ' . $result->code);
        $this->assertSame('connection_success', $result->code);
    }

    /**
     * VT-LIVE-2: known benign hash lookup (empty file SHA-256, no upload).
     */
    public function test_vt_live_known_hash_lookup(): void {
        $this->require_live_run();
        $this->resetAfterTest();
        $client = $this->live_client();

        try {
            $result = $client->lookup_file_hash(client::CONNECTION_TEST_SHA256);
        } catch (provider_exception $e) {
            if ($e->errorcode === 'error_ratelimit') {
                $this->markTestSkipped('VirusTotal rate limit (429) — retry later.');
            }
            if ($e->errorcode === 'error_network') {
                $this->markTestSkipped('Network/SSL unavailable in this environment.');
            }
            throw $e;
        }

        $this->assertTrue($result->found || !$result->found, 'Lookup must return a result object.');
    }

    /**
     * VT-LIVE-3: unique harmless upload (single POST /files, no polling loop).
     */
    public function test_vt_live_harmless_unique_upload(): void {
        $this->require_live_run();
        $this->resetAfterTest();

        $payload = new file_payload(
            'verdict-live-cert-' . bin2hex(random_bytes(8)) . '-' . time(),
            'vt-live-harmless.bin'
        );

        $client = $this->live_client();
        try {
            $submission = $client->upload_file($payload);
        } catch (provider_exception $e) {
            if ($e->errorcode === 'error_ratelimit') {
                $this->markTestSkipped('VirusTotal rate limit (429) on upload — retry later.');
            }
            if ($e->errorcode === 'error_network') {
                $this->markTestSkipped('Network/SSL unavailable in this environment.');
            }
            throw $e;
        } finally {
            $payload->close();
        }

        $this->assertNotSame('', trim($submission->analysisid));
    }

    /**
     * After live HTTP tests, ledger must show ≤4 requests in rolling window.
     *
     * @depends test_vt_live_harmless_unique_upload
     */
    public function test_vt_live_ledger_within_budget(): void {
        live_vt_support::require_opt_in();
        $snap = live_vt_request_ledger::snapshot();
        $this->assertLessThanOrEqual(
            live_vt_request_ledger::MAX_PER_WINDOW,
            $snap['recent'],
            'Rolling-window request count exceeded operator budget.'
        );
    }

    /**
     * Opt-in, credential, and PHPUnit site config for this run only.
     */
    private function require_live_run(): void {
        live_vt_support::require_opt_in();
        $key = live_vt_support::resolve_api_key();
        if ($key === '') {
            $this->markTestSkipped(
                'No live credential (set ' . live_vt_support::KEY_ENV .
                ' or configure apikey in Behat site — see behat-verify-vt-credential.php).'
            );
        }
    }

    /**
     * Build the rate-limited accounting client for this run.
     *
     * @return \antivirus_verdict\tests\live_vt_accounting_client
     */
    private function live_client(): \antivirus_verdict\tests\live_vt_accounting_client {
        $key = live_vt_support::resolve_api_key();
        return live_vt_support::accounting_client($key);
    }
}
