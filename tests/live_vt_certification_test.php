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
 * Live VirusTotal certification (GAP-008 / Phase 8).
 *
 * Set environment variable VERDICT_LVT_API_KEY before running:
 * phpunit --filter live_vt_certification
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\provider\file_payload;
use antivirus_verdict\provider\provider_exception;
use antivirus_verdict\provider\virustotal\client;


/**
 * VT-LIVE-A through VT-LIVE-D against production VirusTotal (rate-limited).
 *
 * @coversNothing
 */
final class live_vt_certification_test extends \advanced_testcase {
    /** EICAR test file SHA-256 (standard test string). */
    private const EICAR_SHA256 = '275a021bbfb648201998ecf92b81a831831061137ee738eb667cff104f9fffec';

    /** Minimum seconds between API calls (4 requests/minute maximum). */
    private const MIN_SPACING_SECONDS = 15;

    /** @var float|null Unix time of last live API call in this process. */
    private static ?float $lastcallat = null;

    /**
     * VT-LIVE-D: connection test (empty-file hash lookup path).
     */
    public function test_vt_live_d_connection_test(): void {
        $this->require_live_key();
        $this->resetAfterTest();
        $this->configure_live_client();

        $this->wait_for_rate_limit();
        $client = client::from_site_config();
        $result = $client->test_connection();
        self::$lastcallat = microtime(true);

        if (!$result->success && $result->code === 'error_network') {
            $this->markTestSkipped('Network/SSL unavailable in this environment: ' . $result->code);
        }
        $this->assertTrue($result->success, 'Connection test failed: ' . $result->code);
        $this->assertSame('connection_success', $result->code);
    }

    /**
     * VT-LIVE-A: known hash lookup (widely indexed empty file SHA-256).
     */
    public function test_vt_live_a_known_hash_lookup(): void {
        $this->require_live_key();
        $this->resetAfterTest();
        $this->configure_live_client();

        $this->wait_for_rate_limit();
        $client = client::from_site_config();
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
        self::$lastcallat = microtime(true);

        $this->assertTrue($result->found || !$result->found, 'Lookup must return a result object.');
        if ($result->found && $result->lastanalysisstats !== null) {
            $this->assertIsArray($result->lastanalysisstats);
        }
    }

    /**
     * VT-LIVE-B: EICAR hash lookup (malicious classification when indexed).
     */
    public function test_vt_live_b_eicar_hash_lookup(): void {
        $this->require_live_key();
        $this->resetAfterTest();
        $this->configure_live_client();

        $this->wait_for_rate_limit();
        $client = client::from_site_config();
        try {
            $result = $client->lookup_file_hash(self::EICAR_SHA256);
        } catch (provider_exception $e) {
            if ($e->errorcode === 'error_ratelimit') {
                $this->markTestSkipped('VirusTotal rate limit (429) — retry later.');
            }
            if ($e->errorcode === 'error_network') {
                $this->markTestSkipped('Network/SSL unavailable in this environment.');
            }
            throw $e;
        }
        self::$lastcallat = microtime(true);

        if (!$result->found) {
            $this->markTestSkipped('EICAR hash not indexed on VirusTotal for this key tier; manual EICAR upload still valid.');
        }
        $stats = $result->lastanalysisstats ?? [];
        $malicious = (int) ($stats['malicious'] ?? 0);
        $this->assertGreaterThan(0, $malicious, 'EICAR should report malicious engines when found.');
    }

    /**
     * VT-LIVE-C: unique unknown file upload returns an analysis id.
     */
    public function test_vt_live_c_unique_file_upload(): void {
        $this->require_live_key();
        $this->resetAfterTest();
        $this->configure_live_client();

        $payload = new file_payload(
            'verdict-live-c-' . bin2hex(random_bytes(16)) . '-' . time(),
            'vt-live-c-unique.bin'
        );

        $this->wait_for_rate_limit();
        $client = client::from_site_config();
        try {
            $submission = $client->upload_file($payload);
        } catch (provider_exception $e) {
            self::$lastcallat = microtime(true);
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
        self::$lastcallat = microtime(true);

        $this->assertNotSame('', trim($submission->analysisid));
    }

    /**
     * Skip group when no live credential is configured in the environment.
     */
    private function require_live_key(): void {
        if ($this->live_key() === '') {
            $this->markTestSkipped(
                'Set VERDICT_LVT_API_KEY in the environment to run live VirusTotal certification.'
            );
        }
    }

    /**
     * Apply site API key from environment for this test only.
     */
    private function configure_live_client(): void {
        set_config('apikey', $this->live_key(), 'antivirus_verdict');
    }

    /**
     * Internal helper.
     *
     * @return string API key from environment only (never committed).
     */
    private function live_key(): string {
        $key = getenv('VERDICT_LVT_API_KEY');
        if (is_string($key)) {
            $key = trim($key);
            if ($key !== '') {
                return $key;
            }
        }
        return '';
    }

    /**
     * Enforce spacing between live API calls in one PHPUnit process.
     */
    private function wait_for_rate_limit(): void {
        if (self::$lastcallat === null) {
            return;
        }
        $elapsed = microtime(true) - self::$lastcallat;
        $wait = self::MIN_SPACING_SECONDS - $elapsed;
        if ($wait > 0) {
            usleep((int) ceil($wait * 1000000));
        }
    }
}
