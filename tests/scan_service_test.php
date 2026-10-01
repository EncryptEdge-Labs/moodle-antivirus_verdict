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
 * Tests for the hash-first scan service.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\file_hasher;
use antivirus_verdict\local\plugin_config;
use antivirus_verdict\local\scan_repository;
use antivirus_verdict\local\scan_service;
use antivirus_verdict\provider\analysis_result;
use antivirus_verdict\provider\file_lookup_result;
use antivirus_verdict\provider\provider_exception;
use antivirus_verdict\provider\submission_result;
use antivirus_verdict\tests\fake_provider;
use antivirus_verdict\tests\recording_scheduler;


/**
 * Scan orchestration against a fake provider.
 *
 * @covers \antivirus_verdict\local\scan_service
 */
final class scan_service_test extends \advanced_testcase {
    /**
     * A new file creates a scan, looks up the hash, uploads when unknown, and queues work.
     */
    public function test_unknown_file_uploads_and_persists_analysis_id(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $scheduler = new recording_scheduler();
        $service = $this->make_service($provider, $scheduler, true, 1024 * 1024);
        $file = $this->create_file('unknown.bin', 'payload-bytes');

        $scan = $service->queue_file_scan($file, scan_source::MANUAL, 7);

        $this->assertSame(1, $provider->lookupcount);
        $this->assertSame(1, $provider->uploadcount);
        $this->assertSame(['unknown.bin'], $provider->uploadednames);
        $this->assertSame([strlen('payload-bytes')], $provider->uploadedsizes);
        $this->assertSame('analysis-fake-1', $scan->vtanalysisid);
        $this->assertSame(scan_status::PENDING, $scan->status);
        $this->assertSame(scan_phase::POLLING, $scan->phase);
        $this->assertSame([ (int) $scan->id ], $scheduler->queued);
        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $scan->sha256);
        $this->assertSame(7, (int) $scan->userid);
        $this->assertGreaterThan(0, (int) $scan->timesubmitted);
    }

    /**
     * Known VirusTotal files are completed from lookup stats and are not uploaded.
     */
    public function test_known_file_skips_upload(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->lookupresult = new file_lookup_result(
            true,
            str_repeat('a', 64),
            ['malicious' => 0, 'suspicious' => 0, 'undetected' => 40, 'harmless' => 10, 'timeout' => 0]
        );
        $scheduler = new recording_scheduler();
        $service = $this->make_service($provider, $scheduler);
        $file = $this->create_file('known.bin', 'known-content');

        $scan = $service->queue_file_scan($file, scan_source::MANUAL);

        $this->assertSame(1, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
        $this->assertSame([], $scheduler->queued);
        $this->assertSame(scan_status::CLEAN, $scan->status);
        $this->assertSame(scan_phase::COMPLETED, $scan->phase);
        $this->assertSame(0, (int) $scan->malicious);
        $this->assertNull($scan->vtanalysisid);
    }

    /**
     * Duplicate in-flight requests for the same Moodle file reuse the active row.
     */
    public function test_duplicate_active_scan_is_prevented(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $scheduler = new recording_scheduler();
        $service = $this->make_service($provider, $scheduler);
        $file = $this->create_file('dup.bin', 'same-bytes');

        $first = $service->queue_file_scan($file, scan_source::MANUAL, 1);
        $second = $service->queue_file_scan($file, scan_source::ASSIGN, 2);

        $this->assertEquals($first->id, $second->id);
        $this->assertSame(1, $provider->lookupcount);
        $this->assertSame(1, $provider->uploadcount);
        $this->assertCount(1, $scheduler->queued);
    }

    /**
     * Async processing still runs when the native antivirus plugin is not enabled.
     */
    public function test_async_processing_ignores_antivirus_enablement(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $service = $this->make_service($provider, new recording_scheduler(), false);
        $scan = $service->queue_file_scan($this->create_file('off.bin', 'x'), scan_source::MANUAL);
        $this->assertGreaterThan(0, $provider->lookupcount);
        $this->assertNotEquals(scan_status::CLEAN, $scan->status);
        $this->assertNotEquals('error_disabled', (string) $scan->errorcode);
    }

    /**
     * Oversized files are skipped without a partial upload.
     */
    public function test_oversized_file_is_rejected(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $service = $this->make_service($provider, new recording_scheduler(), true, 4);
        $scan = $service->queue_file_scan($this->create_file('big.bin', '12345'), scan_source::MANUAL);
        $this->assertSame(0, $provider->uploadcount);
        $this->assertSame(1, $provider->lookupcount);
        $this->assertSame(scan_status::NOTSCANNED, $scan->status);
        $this->assertSame('error_filetoolarge', $scan->errorcode);
    }

    /**
     * Directories are rejected before persistence.
     */
    public function test_directory_is_rejected(): void {
        $this->resetAfterTest();
        global $DB;
        $fs = get_file_storage();
        $dir = $fs->create_directory(\context_system::instance()->id, 'antivirus_verdict', 'unittest', 99, '/');
        $service = $this->make_service(new fake_provider(), new recording_scheduler());
        $this->expectException(\invalid_parameter_exception::class);
        try {
            $service->queue_file_scan($dir, scan_source::MANUAL);
        } finally {
            $this->assertEquals(0, $DB->count_records('antivirus_verdict_scans'));
        }
    }

    /**
     * Manual enqueue queues work; process_scan completes a known hash without cron.
     */
    public function test_manual_enqueue_kickoff_completes_known_hash(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->lookupresult = new file_lookup_result(
            true,
            str_repeat('e', 64),
            ['malicious' => 0, 'suspicious' => 0, 'undetected' => 40, 'harmless' => 10, 'timeout' => 0]
        );
        $scheduler = new recording_scheduler();
        $service = $this->make_service($provider, $scheduler);
        $file = $this->create_file('known-manual.html', '<html></html>');

        $scan = $service->enqueue_file_scan($file, scan_source::MANUAL, 3);
        $this->assertSame(0, $provider->lookupcount);
        $this->assertSame(scan_phase::QUEUED, $scan->phase);

        $this->assertFalse($service->process_scan((int) $scan->id));
        $scan = (new scan_repository())->get_by_id((int) $scan->id);

        $this->assertSame(1, $provider->lookupcount);
        $this->assertSame(scan_status::CLEAN, $scan->status);
        $this->assertSame(scan_phase::COMPLETED, $scan->phase);
        $this->assertSame(scan_source::MANUAL, $scan->source);
        $this->assertNotSame('error_archive_unsupported', $scan->errorcode);
    }

    /**
     * enqueue_file_scan persists a queued row and does not call VirusTotal.
     */
    public function test_enqueue_file_scan_does_not_call_provider(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $scheduler = new recording_scheduler();
        $service = $this->make_service($provider, $scheduler);
        $file = $this->create_file('async.bin', 'async-bytes');

        $scan = $service->enqueue_file_scan($file, scan_source::ASSIGN, 9);

        $this->assertSame(0, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
        $this->assertSame(0, $provider->analysiscount);
        $this->assertSame(scan_status::PENDING, $scan->status);
        $this->assertSame(scan_phase::QUEUED, $scan->phase);
        $this->assertSame('', $scan->sha256);
        $this->assertSame(scan_source::ASSIGN, $scan->source);
        $this->assertSame(9, (int) $scan->userid);
        $this->assertSame([(int) $scan->id], $scheduler->queued);
    }

    /**
     * Background processing continues an enqueued scan through the same engine.
     */
    public function test_process_scan_advances_enqueued_scan(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $scheduler = new recording_scheduler();
        $service = $this->make_service($provider, $scheduler);
        $scan = $service->enqueue_file_scan($this->create_file('later.bin', 'later-bytes'), scan_source::ASSIGN);

        $this->assertTrue($service->process_scan((int) $scan->id));
        $updated = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame(1, $provider->lookupcount);
        $this->assertSame(1, $provider->uploadcount);
        $this->assertSame(scan_phase::POLLING, $updated->phase);
        $this->assertSame('analysis-fake-1', $updated->vtanalysisid);
        $this->assertSame([(int) $scan->id], $scheduler->queued);
    }

    /**
     * Duplicate enqueue of the same in-flight file reuses the active row.
     */
    public function test_enqueue_duplicate_reuses_active_scan(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $scheduler = new recording_scheduler();
        $service = $this->make_service($provider, $scheduler);
        $file = $this->create_file('once.bin', 'once-bytes');

        $first = $service->enqueue_file_scan($file, scan_source::ASSIGN, 1);
        $second = $service->enqueue_file_scan($file, scan_source::ASSIGN, 2);

        $this->assertEquals($first->id, $second->id);
        $this->assertCount(1, $scheduler->queued);
        $this->assertSame(0, $provider->lookupcount);
    }

    /**
     * Provider auth failures are terminal errors, not clean.
     */
    public function test_provider_error_becomes_error(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->lookupexception = new provider_exception('error_auth', '', 401);
        $scan = $this->make_service($provider, new recording_scheduler())
            ->queue_file_scan($this->create_file('auth.bin', 'x'), scan_source::MANUAL);
        $this->assertSame(scan_status::ERROR, $scan->status);
        $this->assertSame(scan_phase::FAILED, $scan->phase);
        $this->assertSame('error_auth', $scan->errorcode);
        $this->assertSame(0, $provider->uploadcount);
    }

    /**
     * Suspicious lookup stats map to suspicious, not clean.
     */
    public function test_suspicious_lookup_status(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->lookupresult = new file_lookup_result(
            true,
            str_repeat('d', 64),
            ['malicious' => 0, 'suspicious' => 2, 'undetected' => 40, 'harmless' => 1]
        );
        $scan = $this->make_service($provider, new recording_scheduler())
            ->queue_file_scan($this->create_file('sus.bin', 's'), scan_source::MANUAL);
        $this->assertSame(scan_status::SUSPICIOUS, $scan->status);
        $this->assertSame(scan_phase::COMPLETED, $scan->phase);
    }

    /**
     * Malicious lookup stats map to malicious.
     */
    public function test_malicious_lookup_status(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->lookupresult = new file_lookup_result(
            true,
            str_repeat('e', 64),
            ['malicious' => 3, 'suspicious' => 1, 'undetected' => 20]
        );
        $scan = $this->make_service($provider, new recording_scheduler())
            ->queue_file_scan($this->create_file('mal.bin', 'm'), scan_source::MANUAL);
        $this->assertSame(scan_status::MALICIOUS, $scan->status);
        $this->assertSame(3, (int) $scan->malicious);
    }

    /**
     * Pending analysis does not become clean.
     */
    public function test_pending_analysis_stays_pending(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->analysisresult = new analysis_result('analysis-fake-1', 'queued', null);
        $scheduler = new recording_scheduler();
        $service = $this->make_service($provider, $scheduler);
        $scan = $service->queue_file_scan($this->create_file('pend.bin', 'p'), scan_source::MANUAL);
        $retry = $service->process_scan((int) $scan->id);
        $updated = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertTrue($retry);
        $this->assertSame(scan_status::PENDING, $updated->status);
        $this->assertSame(scan_phase::POLLING, $updated->phase);
        $this->assertNull($updated->malicious);
    }

    /**
     * Completed analysis finalises the scan.
     */
    public function test_completed_analysis_finalises_clean(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $service = $this->make_service($provider, new recording_scheduler());
        $scan = $service->queue_file_scan($this->create_file('done.bin', 'd'), scan_source::MANUAL);
        $this->assertFalse($service->process_scan((int) $scan->id));
        $updated = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame(scan_status::CLEAN, $updated->status);
        $this->assertSame(scan_phase::COMPLETED, $updated->phase);
        $this->assertGreaterThan(0, (int) $updated->timecompleted);
    }

    /**
     * Deleted Moodle files do not fatal when a later poll needs the bytes.
     */
    public function test_deleted_file_during_upload_retry_fails_safely(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->uploadexception = new provider_exception('error_network');
        $service = $this->make_service($provider, new recording_scheduler());
        $file = $this->create_file('gone.bin', 'g');
        $scan = $service->queue_file_scan($file, scan_source::MANUAL);
        $this->assertSame(scan_phase::UPLOADREQUIRED, $scan->phase);
        $file->delete();
        $provider->uploadexception = null;
        $service->process_scan((int) $scan->id);
        $updated = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame(scan_status::ERROR, $updated->status);
        $this->assertSame('error_invalidfile', $updated->errorcode);
    }

    /**
     * An interrupted large-file POST is retried once, then fails without a verdict.
     */
    public function test_upload_interrupted_is_capped_and_not_a_verdict(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->uploadexception = new provider_exception('error_uploadinterrupted');
        $scheduler = new recording_scheduler();
        $service = $this->make_service($provider, $scheduler);
        $file = $this->create_file('big.bin', 'large-payload');
        $scan = $service->enqueue_file_scan($file, scan_source::ASSIGN);

        $this->assertTrue($service->process_scan((int) $scan->id));
        $afterfirst = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame(scan_status::PENDING, $afterfirst->status);
        $this->assertSame('error_uploadinterrupted', $afterfirst->errorcode);
        $this->assertSame(1, $provider->uploadcount);
        $this->assertSame(1, (int) $afterfirst->pollattempts);

        $this->assertFalse($service->process_scan((int) $scan->id));
        $updated = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame(2, $provider->uploadcount);
        $this->assertSame(scan_status::ERROR, $updated->status);
        $this->assertSame(scan_phase::FAILED, $updated->phase);
        $this->assertSame('error_uploadinterrupted', $updated->errorcode);
        $this->assertNotEquals(scan_status::CLEAN, $updated->status);
        $this->assertNotEquals(scan_status::MALICIOUS, $updated->status);
    }

    /**
     * Authentication failure during upload is permanent after one attempt.
     */
    public function test_upload_auth_failure_is_not_retried(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->uploadexception = new provider_exception('error_auth', '', 401);
        $service = $this->make_service($provider, new recording_scheduler());
        $scan = $service->queue_file_scan($this->create_file('authup.bin', 'x'), scan_source::MANUAL);
        $this->assertSame(1, $provider->uploadcount);
        $this->assertSame(scan_status::ERROR, $scan->status);
        $this->assertSame('error_auth', $scan->errorcode);
        $this->assertFalse($service->process_scan((int) $scan->id));
        $this->assertSame(1, $provider->uploadcount);
    }

    /**
     * A provider outage leaves the scan pending or failed, never clean or malicious.
     */
    public function test_provider_unavailable_is_not_a_verdict(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->lookupexception = new provider_exception('error_providerunavailable');
        $scan = $this->make_service($provider, new recording_scheduler())
            ->queue_file_scan($this->create_file('outage.bin', 'x'), scan_source::MANUAL);
        $this->assertSame(scan_status::PENDING, $scan->status);
        $this->assertSame('error_providerunavailable', $scan->errorcode);
        $this->assertNotEquals(scan_status::CLEAN, $scan->status);
        $this->assertNotEquals(scan_status::MALICIOUS, $scan->status);
        $this->assertSame(0, $provider->uploadcount);
    }

    /**
     * Build a service with injected doubles.
     *
     * @param fake_provider $provider Fake provider.
     * @param recording_scheduler $scheduler Fake scheduler.
     * @param bool $enabled Scanning enabled.
     * @param int $maxbytes Size limit.
     * @return scan_service
     */
    private function make_service(
        fake_provider $provider,
        recording_scheduler $scheduler,
        bool $enabled = true,
        int $maxbytes = 1048576
    ): scan_service {
        return new scan_service(
            $provider,
            new scan_repository(),
            new file_hasher(),
            new plugin_config($enabled, $maxbytes),
            $scheduler
        );
    }

    /**
     * Create a stored file.
     *
     * @param string $filename File name.
     * @param string $content Bytes.
     * @return \stored_file
     */
    private function create_file(string $filename, string $content): \stored_file {
        $fs = get_file_storage();
        return $fs->create_file_from_string([
            'contextid' => \context_system::instance()->id,
            'component' => 'antivirus_verdict',
            'filearea' => 'unittest',
            'itemid' => random_int(1, 100000000),
            'filepath' => '/',
            'filename' => $filename,
        ], $content);
    }
}
