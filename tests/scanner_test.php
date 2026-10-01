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
 * Tests for the native Moodle Antivirus scanner.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use core\http_client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use antivirus_verdict\local\antivirus_gate;
use antivirus_verdict\local\file_hasher;
use antivirus_verdict\local\plugin_config;
use antivirus_verdict\local\provider_health;
use antivirus_verdict\local\scan_policy;
use antivirus_verdict\local\scan_repository;
use antivirus_verdict\provider\file_lookup_result;
use antivirus_verdict\provider\provider_exception;
use antivirus_verdict\tests\fake_provider;
use antivirus_verdict\tests\recording_scheduler;


/**
 * Native scanner contract, policies, and fail-closed behaviour.
 *
 * @covers \antivirus_verdict\scanner
 * @covers \antivirus_verdict\local\antivirus_gate
 * @covers \antivirus_verdict\local\scan_policy
 */
final class scanner_test extends \advanced_testcase {
    /** SHA-256 of "hello". */
    private const HELLO_SHA256 = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';

    /**
     * Scanner extends the Moodle core scanner and uses the 4.5–5.2 source signature.
     */
    public function test_scanner_matches_core_contract(): void {
        $this->resetAfterTest();
        $scanner = new scanner();
        $this->assertInstanceOf(\core\antivirus\scanner::class, $scanner);
        $method = new \ReflectionMethod(scanner::class, 'scan_file');
        $this->assertSame(2, $method->getNumberOfParameters());
        $this->assertSame(0, scanner::SCAN_RESULT_OK);
        $this->assertSame(1, scanner::SCAN_RESULT_FOUND);
        $this->assertSame(2, scanner::SCAN_RESULT_ERROR);
    }

    /**
     * is_configured requires a non-empty API key and does not invent another switch.
     */
    public function test_is_configured(): void {
        $this->resetAfterTest();
        unset_config('apikey', 'antivirus_verdict');
        $scanner = new scanner();
        $this->assertFalse($scanner->is_configured());

        set_config('apikey', '   ', 'antivirus_verdict');
        $scanner = new scanner();
        $this->assertFalse($scanner->is_configured());

        set_config('apikey', 'phpunit-scanner-key', 'antivirus_verdict');
        $scanner = new scanner();
        $this->assertTrue($scanner->is_configured());
    }

    /**
     * Known clean hashes return OK and persist clean, never pending.
     */
    public function test_known_clean_is_ok(): void {
        global $DB;

        $this->resetAfterTest();
        $path = $this->temp_file('hello');
        $provider = $this->known_provider(0, 0);
        $scanner = $this->make_scanner($provider);

        $this->assertSame(scanner::SCAN_RESULT_OK, $scanner->scan_file($path, 'clean.bin'));
        $this->assertSame(1, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
        $row = $DB->get_record('antivirus_verdict_scans', ['sha256' => self::HELLO_SHA256], '*', MUST_EXIST);
        $this->assertSame(scan_status::CLEAN, $row->status);
        $this->assertSame(scan_source::ANTIVIRUS, $row->source);
        $this->assertNotEquals(scan_status::PENDING, $row->status);
    }

    /**
     * Known malicious hashes return FOUND.
     */
    public function test_known_malicious_is_found(): void {
        global $DB;

        $this->resetAfterTest();
        $provider = $this->known_provider(3, 0);
        $scanner = $this->make_scanner($provider);
        $found = $scanner->scan_file($this->temp_file('hello'), 'eicar-adobe-acrobat-attachment.pdf');
        $this->assertSame(scanner::SCAN_RESULT_FOUND, $found);
        $this->assertSame(0, $provider->uploadcount);
        $row = $DB->get_record('antivirus_verdict_scans', ['sha256' => self::HELLO_SHA256], '*', MUST_EXIST);
        $this->assertSame(scan_status::MALICIOUS, $row->status);
        $this->assertSame(3, (int) $row->malicious);
        $this->assertSame(0, $DB->count_records('files', ['filename' => 'eicar-adobe-acrobat-attachment.pdf']));
    }

    /**
     * Native malware-found UX uses the Verdict language string, not core virusfound.
     */
    public function test_virus_found_message_is_plugin_string(): void {
        $this->resetAfterTest();
        $scanner = new scanner();
        $message = $scanner->get_virus_found_message();
        $this->assertSame('error_malwareblocked', $message['string']);
        $this->assertSame('antivirus_verdict', $message['component']);
        $this->assertSame([], $message['placeholders']);

        $placeholders = array_merge(['item' => 'eicar-adobe-acrobat-attachment.pdf'], $message['placeholders']);
        $exception = new \core\antivirus\scanner_exception(
            $message['string'],
            '',
            $placeholders,
            null,
            $message['component']
        );
        $this->assertSame('error_malwareblocked', $exception->errorcode);
        $this->assertNotEquals('virusfound', $exception->errorcode);
        $this->assertStringContainsString('eicar-adobe-acrobat-attachment.pdf', $exception->getMessage());
        $this->assertStringContainsString('malware', \core_text::strtolower($exception->getMessage()));
        $this->assertStringNotContainsString('antivirus_verdict\\', $exception->getMessage());
        $this->assertStringNotContainsString('VirusTotal', $exception->getMessage());
        $this->assertEmpty($exception->debuginfo);
    }

    /**
     * last_analysis_results without last_analysis_stats still become FOUND.
     */
    public function test_engine_results_without_stats_object_are_malicious_found(): void {
        global $DB;

        $this->resetAfterTest();
        \cache::make('antivirus_verdict', provider_health::CACHE_AREA)->purge();
        $body = json_encode([
            'data' => [
                'id' => self::HELLO_SHA256,
                'type' => 'file',
                'attributes' => [
                    'sha256' => self::HELLO_SHA256,
                    'last_analysis_results' => [
                        'EngineA' => ['category' => 'malicious'],
                        'EngineB' => ['category' => 'malicious'],
                        'EngineC' => ['category' => 'undetected'],
                    ],
                ],
            ],
        ]);
        $http = new http_client([
            'mock' => new MockHandler([new Response(200, [], $body)]),
            'http_errors' => false,
            'timeout' => 5,
            'connect_timeout' => 5,
            'ignoresecurity' => true,
        ]);
        $client = new \antivirus_verdict\tests\testable_vt_client(
            new \antivirus_verdict\tests\test_credentials('phpunit-derived-stats-key'),
            $http,
            new \antivirus_verdict\tests\testable_provider_health()
        );
        $gate = new antivirus_gate(
            $client,
            new scan_repository(),
            new file_hasher(),
            new plugin_config(true, 1048576, false),
            new recording_scheduler()
        );
        $scanner = new scanner();
        $scanner->set_gate($gate);

        $this->assertSame(
            scanner::SCAN_RESULT_FOUND,
            $scanner->scan_file($this->temp_file('hello'), 'eicar-adobe-acrobat-attachment.pdf')
        );
        $row = $DB->get_record('antivirus_verdict_scans', ['sha256' => self::HELLO_SHA256], '*', MUST_EXIST);
        $this->assertSame(scan_status::MALICIOUS, $row->status);
        $this->assertSame(2, (int) $row->malicious);
        $this->assertNotEquals(scan_status::ERROR, $row->status);
        $this->assertNotEquals(scan_status::CLEAN, $row->status);
        $this->assertStringNotContainsString('phpunit-derived-stats-key', (string) json_encode($row));
        $this->assertStringNotContainsString(
            'could not complete a VirusTotal check',
            $scanner->get_scanning_notice()
        );
    }

    /**
     * A found hash with unusable stats is malformed, not clean or malicious.
     */
    public function test_malformed_known_lookup_is_blocked_not_verdict(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->lookupresult = new file_lookup_result(true, self::HELLO_SHA256, null);
        $scanner = $this->make_scanner($provider);
        try {
            $scanner->scan_file($this->temp_file('hello'), 'odd.bin');
            $this->fail('Malformed known lookup should block.');
        } catch (\core\antivirus\scanner_exception $e) {
            $this->assertSame('error_malformed', $e->errorcode);
            $this->assertStringContainsString('unexpected response', $e->getMessage());
            $this->assertStringNotContainsString('could not complete a VirusTotal check', $e->getMessage());
            $this->assertNotEquals('virusfound', $e->errorcode);
        }
    }

    /**
     * Suspicious + allow returns OK and stores suspicious, not clean.
     */
    public function test_suspicious_allow_is_ok_not_clean(): void {
        global $DB;

        $this->resetAfterTest();
        $provider = $this->known_provider(0, 2);
        $scanner = $this->make_scanner($provider, scan_policy::ALLOW, scan_policy::ALLOW);
        $this->assertSame(scanner::SCAN_RESULT_OK, $scanner->scan_file($this->temp_file('hello'), 'odd.bin'));
        $row = $DB->get_record('antivirus_verdict_scans', ['sha256' => self::HELLO_SHA256], '*', MUST_EXIST);
        $this->assertSame(scan_status::SUSPICIOUS, $row->status);
        $this->assertNotEquals(scan_status::CLEAN, $row->status);
    }

    /**
     * Suspicious + block refuses the upload without SCAN_RESULT_FOUND.
     */
    public function test_suspicious_block_throws(): void {
        $this->resetAfterTest();
        $scanner = $this->make_scanner($this->known_provider(0, 2), scan_policy::ALLOW, scan_policy::BLOCK);
        try {
            $scanner->scan_file($this->temp_file('hello'), 'odd.bin');
            $this->fail('Suspicious + block should throw.');
        } catch (\core\antivirus\scanner_exception $e) {
            $this->assertSame('error_suspiciousblocked', $e->errorcode);
        }
    }

    /**
     * Unknown + allow returns OK and persists pending, never clean.
     */
    public function test_unknown_allow_is_pending_not_clean(): void {
        global $DB;

        $this->resetAfterTest();
        $provider = new fake_provider();
        $scheduler = new recording_scheduler();
        $scanner = $this->make_scanner($provider, scan_policy::ALLOW, scan_policy::ALLOW, scan_policy::BLOCK, $scheduler);
        $this->assertSame(scanner::SCAN_RESULT_OK, $scanner->scan_file($this->temp_file('hello'), 'new.bin'));
        $row = $DB->get_record('antivirus_verdict_scans', ['sha256' => self::HELLO_SHA256], '*', MUST_EXIST);
        $this->assertSame(scan_status::PENDING, $row->status);
        $this->assertNotEquals(scan_status::CLEAN, $row->status);
        $this->assertSame([(int) $row->id], $scheduler->queued);
        $this->assertSame(0, $provider->uploadcount);
    }

    /**
     * Unknown + block refuses the upload and does not call the file malware.
     */
    public function test_unknown_block_throws(): void {
        $this->resetAfterTest();
        $scanner = $this->make_scanner(new fake_provider(), scan_policy::BLOCK);
        try {
            $scanner->scan_file($this->temp_file('hello'), 'new.bin');
            $this->fail('Unknown + block should throw.');
        } catch (\core\antivirus\scanner_exception $e) {
            $this->assertSame('error_unknownblocked', $e->errorcode);
            $this->assertStringNotContainsString('virusfound', $e->errorcode);
        }
    }

    /**
     * Provider 429 accepts the upload as pending, never clean or malicious.
     */
    public function test_rate_limit_is_not_clean(): void {
        global $DB;

        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->lookupexception = new provider_exception('error_ratelimit', '', 429, 10);
        $scheduler = new recording_scheduler();
        $scanner = $this->make_scanner(
            $provider,
            scan_policy::BLOCK,
            scan_policy::ALLOW,
            scan_policy::BLOCK,
            $scheduler
        );
        $result = $scanner->scan_file($this->temp_file('hello'), 'rl.bin');
        $this->assertSame(scanner::SCAN_RESULT_OK, $result);
        $this->assertNotEquals(scanner::SCAN_RESULT_FOUND, $result);
        $this->assertNotEquals(scanner::SCAN_RESULT_ERROR, $result);
        $row = $DB->get_record('antivirus_verdict_scans', ['filename' => 'rl.bin'], '*', MUST_EXIST);
        $this->assertSame(scan_status::PENDING, $row->status);
        $this->assertNotEquals(scan_status::CLEAN, $row->status);
        $this->assertNotEquals(scan_status::MALICIOUS, $row->status);
        $this->assertSame('error_ratelimit', $row->errorcode);
        $this->assertSame([(int) $row->id], $scheduler->queued);
        $this->assertStringContainsString('queued for retry', $scanner->get_scanning_notice());
        $this->assertStringNotContainsString('Try again later.', $scanner->get_scanning_notice());
    }

    /**
     * Provider errors with the default block policy refuse the upload.
     */
    public function test_provider_error_block_throws(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->lookupexception = new provider_exception('error_network', '', 0);
        $scanner = $this->make_scanner($provider);
        try {
            $scanner->scan_file($this->temp_file('hello'), 'net.bin');
            $this->fail('Provider error + block should throw.');
        } catch (\core\antivirus\scanner_exception $e) {
            $this->assertSame('error_network', $e->errorcode);
            $this->assertStringContainsString('could not be reached', $e->getMessage());
            $this->assertStringNotContainsString('could not complete a VirusTotal check', $e->getMessage());
            $this->assertStringNotContainsString('phpunit', $e->getMessage());
        }
    }

    /**
     * Circuit-open unavailability accepts the upload as pending, never clean.
     */
    public function test_provider_unavailable_block_throws(): void {
        global $DB;

        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->lookupexception = new provider_exception('error_providerunavailable');
        $scheduler = new recording_scheduler();
        $scanner = $this->make_scanner($provider, scan_policy::ALLOW, scan_policy::ALLOW, scan_policy::BLOCK, $scheduler);
        $result = $scanner->scan_file($this->temp_file('hello'), 'outage.bin');
        $this->assertSame(scanner::SCAN_RESULT_OK, $result);
        $this->assertNotEquals(scanner::SCAN_RESULT_FOUND, $result);
        $row = $DB->get_record('antivirus_verdict_scans', ['filename' => 'outage.bin'], '*', MUST_EXIST);
        $this->assertSame(scan_status::PENDING, $row->status);
        $this->assertNotEquals(scan_status::CLEAN, $row->status);
        $this->assertSame('error_providerunavailable', $row->errorcode);
        $this->assertSame([(int) $row->id], $scheduler->queued);
        $this->assertStringContainsString('queued for retry', $scanner->get_scanning_notice());
    }

    /**
     * Circuit-open with report policy is still pending, never a verdict.
     */
    public function test_provider_unavailable_report_is_error_not_verdict(): void {
        global $DB;

        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->lookupexception = new provider_exception('error_providerunavailable');
        $scanner = $this->make_scanner($provider, scan_policy::ALLOW, scan_policy::ALLOW, scan_policy::REPORT);
        $result = $scanner->scan_file($this->temp_file('hello'), 'outage.bin');
        $this->assertSame(scanner::SCAN_RESULT_OK, $result);
        $this->assertNotEquals(scanner::SCAN_RESULT_FOUND, $result);
        $row = $DB->get_record('antivirus_verdict_scans', ['filename' => 'outage.bin'], '*', MUST_EXIST);
        $this->assertSame(scan_status::PENDING, $row->status);
        $this->assertNotEquals(scan_status::CLEAN, $row->status);
    }

    /**
     * HTTP 401 remains a provider error, distinct from 429.
     */
    public function test_auth_failure_is_not_rate_limit(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->lookupexception = new provider_exception('error_auth', '', 401);
        $scanner = $this->make_scanner($provider);
        try {
            $scanner->scan_file($this->temp_file('hello'), 'auth.bin');
            $this->fail('401 should still refuse the upload under block policy.');
        } catch (\core\antivirus\scanner_exception $e) {
            $this->assertSame('error_auth', $e->errorcode);
            $this->assertStringNotContainsString('rate-limit', $e->getMessage());
            $this->assertStringNotContainsString('phpunit', $e->getMessage());
        }
    }

    /**
     * Provider-error report policy is not a clean verdict.
     */
    public function test_provider_error_report_is_not_clean(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->lookupexception = new provider_exception('error_server', '', 503);
        $scanner = $this->make_scanner($provider, scan_policy::ALLOW, scan_policy::ALLOW, scan_policy::REPORT);
        $result = $scanner->scan_file($this->temp_file('hello'), 'srv.bin');
        $this->assertSame(scanner::SCAN_RESULT_ERROR, $result);
        $this->assertNotEquals(scanner::SCAN_RESULT_OK, $result);
        $this->assertNotEquals(scanner::SCAN_RESULT_FOUND, $result);
    }

    /**
     * Unreadable files fail closed.
     */
    public function test_unreadable_file_fails_closed(): void {
        $this->resetAfterTest();
        $scanner = $this->make_scanner(new fake_provider(), scan_policy::ALLOW, scan_policy::ALLOW, scan_policy::REPORT);
        $missing = make_request_directory() . '/missing.bin';
        $this->assertSame(scanner::SCAN_RESULT_ERROR, $scanner->scan_file($missing, 'missing.bin'));
    }

    /**
     * The same SHA-256 does not create a second VirusTotal lookup.
     */
    public function test_deduplicates_known_hash(): void {
        $this->resetAfterTest();
        $provider = $this->known_provider(0, 0);
        $scanner = $this->make_scanner($provider);
        $path = $this->temp_file('hello');
        $this->assertSame(scanner::SCAN_RESULT_OK, $scanner->scan_file($path, 'a.bin'));
        $this->assertSame(scanner::SCAN_RESULT_OK, $scanner->scan_file($path, 'b.bin'));
        $this->assertSame(1, $provider->lookupcount);
    }

    /**
     * API keys and file bytes never appear in notices or scan rows.
     */
    public function test_no_secret_or_content_leak(): void {
        global $DB;

        $this->resetAfterTest();
        set_config('apikey', 'super-secret-scanner-key', 'antivirus_verdict');
        $provider = $this->known_provider(1, 0);
        $scanner = $this->make_scanner($provider);
        $scanner->scan_file($this->temp_file('hello'), 'secret.bin');
        $notice = $scanner->get_scanning_notice();
        $this->assertStringNotContainsString('super-secret-scanner-key', $notice);
        $this->assertStringNotContainsString('x-apikey', $notice);
        $row = $DB->get_record('antivirus_verdict_scans', ['filename' => 'secret.bin'], '*', MUST_EXIST);
        $encoded = json_encode($row);
        $this->assertStringNotContainsString('super-secret-scanner-key', $encoded);
        $this->assertStringNotContainsString('hello', (string) $row->errorcode);
    }

    /**
     * The scanner source is not a capability bypass.
     */
    public function test_scanner_has_no_capability_check(): void {
        $source = file_get_contents(__DIR__ . '/../classes/scanner.php');
        $this->assertStringNotContainsString('has_capability', $source);
        $gate = file_get_contents(__DIR__ . '/../classes/local/antivirus_gate.php');
        $this->assertStringNotContainsString('has_capability', $gate);
        $this->assertStringNotContainsString('SCAN_RESULT_OK', explode('is_configured', $source)[0]);
    }

    /**
     * A disabled archive setting does not scan a ZIP upload, and still scans other files.
     */
    public function test_disabled_archive_setting_skips_zip_upload(): void {
        global $DB;

        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->lookupresult = new file_lookup_result(true, self::HELLO_SHA256, [
            'malicious' => 3,
            'suspicious' => 0,
            'undetected' => 1,
            'harmless' => 0,
            'timeout' => 0,
        ]);
        $gate = new antivirus_gate(
            $provider,
            new scan_repository(),
            new file_hasher(),
            new plugin_config(
                true,
                1048576,
                false,
                scan_policy::ALLOW,
                scan_policy::ALLOW,
                scan_policy::BLOCK,
                scan_policy::ASYNC_ENFORCEMENT_DEFAULT,
                false,
                false,
                false,
                true,
                false
            ),
            new recording_scheduler()
        );
        $scanner = new scanner();
        $scanner->set_gate($gate);

        $this->assertSame(scanner::SCAN_RESULT_OK, $scanner->scan_file($this->temp_file('plugin-zip'), 'verdict.zip'));
        $this->assertSame(0, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
        $this->assertFalse($DB->record_exists('antivirus_verdict_scans', ['filename' => 'verdict.zip']));

        $this->assertSame(scanner::SCAN_RESULT_FOUND, $scanner->scan_file($this->temp_file('hello'), 'notes.txt'));
        $this->assertSame(1, $provider->lookupcount);
        $this->assertTrue($DB->record_exists('antivirus_verdict_scans', ['filename' => 'notes.txt']));
    }

    /**
     * Build a scanner with an injected gate.
     *
     * @param fake_provider $provider Fake provider.
     * @param string $unknown Unknown policy.
     * @param string $suspicious Suspicious policy.
     * @param string $providererror Provider-error policy.
     * @param recording_scheduler|null $scheduler Scheduler.
     * @return scanner
     */
    private function make_scanner(
        fake_provider $provider,
        string $unknown = scan_policy::ALLOW,
        string $suspicious = scan_policy::ALLOW,
        string $providererror = scan_policy::BLOCK,
        ?recording_scheduler $scheduler = null
    ): scanner {
        $gate = new antivirus_gate(
            $provider,
            new scan_repository(),
            new file_hasher(),
            new plugin_config(true, 1048576, false, $unknown, $suspicious, $providererror),
            $scheduler ?? new recording_scheduler()
        );
        $scanner = new scanner();
        $scanner->set_gate($gate);
        return $scanner;
    }

    /**
     * Fake provider that reports a known hash.
     *
     * @param int $malicious Malicious count.
     * @param int $suspicious Suspicious count.
     * @return fake_provider
     */
    private function known_provider(int $malicious, int $suspicious): fake_provider {
        $provider = new fake_provider();
        $provider->lookupresult = new file_lookup_result(true, self::HELLO_SHA256, [
            'malicious' => $malicious,
            'suspicious' => $suspicious,
            'undetected' => 10,
            'harmless' => 5,
            'timeout' => 0,
        ]);
        return $provider;
    }

    /**
     * Write bytes to a request-scoped temp file.
     *
     * @param string $contents File bytes.
     * @return string
     */
    private function temp_file(string $contents): string {
        $path = make_request_directory() . '/verdict-' . random_int(1, 100000000) . '.bin';
        file_put_contents($path, $contents);
        return $path;
    }
}
