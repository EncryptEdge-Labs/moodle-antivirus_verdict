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
 * Tests for the process_scan adhoc task payload handling.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\file_hasher;
use antivirus_verdict\local\plugin_config;
use antivirus_verdict\local\retry_policy;
use antivirus_verdict\local\scan_repository;
use antivirus_verdict\local\scan_service;
use antivirus_verdict\provider\analysis_result;
use antivirus_verdict\provider\file_lookup_result;
use antivirus_verdict\provider\provider_exception;
use antivirus_verdict\task\process_scan;
use antivirus_verdict\tests\fake_provider;
use antivirus_verdict\tests\recording_scheduler;
use antivirus_verdict\tests\recording_task;


/**
 * Adhoc task and process_scan retry behaviour.
 *
 * @covers \antivirus_verdict\task\process_scan
 * @covers \antivirus_verdict\local\scan_service
 */
final class process_scan_task_test extends \advanced_testcase {
    /**
     * After a successful unknown-file upload, the running adhoc task is delayed
     * for polling instead of queueing a duplicate that Moodle would skip.
     */
    public function test_successful_upload_soft_retries_current_task(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->analysisresult = new analysis_result('analysis-fake-1', 'queued', null);
        $scheduler = new recording_scheduler();
        $service = new scan_service(
            $provider,
            new scan_repository(),
            new file_hasher(),
            new plugin_config(true, 1048576),
            $scheduler
        );
        $scan = $service->enqueue_file_scan($this->create_file('poll.bin', 'poll-bytes'), scan_source::MANUAL);
        $this->assertSame([(int) $scan->id], $scheduler->queued);
        $scheduler->queued = [];

        $task = new recording_task();
        $this->assertTrue($service->process_scan((int) $scan->id, $task));

        $updated = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame(scan_status::PENDING, $updated->status);
        $this->assertSame(scan_phase::POLLING, $updated->phase);
        $this->assertSame('analysis-fake-1', $updated->vtanalysisid);
        $this->assertGreaterThan(0, (int) $updated->timesubmitted);
        $this->assertSame(0, (int) $updated->timecompleted);
        $this->assertSame(retry_policy::DELAY_PENDING, $task->softdelay);
        $this->assertSame([], $scheduler->queued);
        $this->assertSame(0, $provider->analysiscount);
    }

    /**
     * In-progress VirusTotal analysis stays pending and schedules another poll.
     */
    public function test_in_progress_analysis_stays_pending_and_polls_again(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->analysisresult = new analysis_result('analysis-fake-1', 'in-progress', null);
        $service = $this->make_service($provider);
        $scan = $service->enqueue_file_scan($this->create_file('prog.bin', 'p'), scan_source::MANUAL);
        $this->assertTrue($service->process_scan((int) $scan->id));
        $task = new recording_task();
        $this->assertTrue($service->process_scan((int) $scan->id, $task));
        $updated = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame(scan_status::PENDING, $updated->status);
        $this->assertSame(scan_phase::POLLING, $updated->phase);
        $this->assertNull($updated->malicious);
        $this->assertSame(retry_policy::DELAY_PENDING, $task->softdelay);
    }

    /**
     * Completed analysis with malicious engines is persisted as malicious.
     */
    public function test_completed_poll_persists_malicious(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->analysisresult = new analysis_result('analysis-fake-1', 'completed', [
            'malicious' => 4,
            'suspicious' => 1,
            'undetected' => 10,
            'harmless' => 2,
            'timeout' => 0,
        ]);
        $service = $this->make_service($provider);
        $scan = $service->enqueue_file_scan($this->create_file('malp.bin', 'm'), scan_source::MANUAL);
        $this->assertTrue($service->process_scan((int) $scan->id));
        $this->assertFalse($service->process_scan((int) $scan->id));
        $updated = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame(scan_status::MALICIOUS, $updated->status);
        $this->assertSame(scan_phase::COMPLETED, $updated->phase);
        $this->assertSame(4, (int) $updated->malicious);
        $this->assertGreaterThan(0, (int) $updated->timecompleted);
    }

    /**
     * Completed analysis with only suspicious engines is persisted as suspicious.
     */
    public function test_completed_poll_persists_suspicious(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->analysisresult = new analysis_result('analysis-fake-1', 'completed', [
            'malicious' => 0,
            'suspicious' => 3,
            'undetected' => 10,
            'harmless' => 2,
            'timeout' => 0,
        ]);
        $service = $this->make_service($provider);
        $scan = $service->enqueue_file_scan($this->create_file('susp.bin', 's'), scan_source::MANUAL);
        $this->assertTrue($service->process_scan((int) $scan->id));
        $this->assertFalse($service->process_scan((int) $scan->id));
        $updated = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame(scan_status::SUSPICIOUS, $updated->status);
        $this->assertSame(0, (int) $updated->malicious);
        $this->assertSame(3, (int) $updated->suspicious);
        $this->assertGreaterThan(0, (int) $updated->timecompleted);
    }

    /**
     * Completed analysis with no detections is persisted as clean.
     */
    public function test_completed_poll_persists_clean(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->analysisresult = new analysis_result('analysis-fake-1', 'completed', [
            'malicious' => 0,
            'suspicious' => 0,
            'undetected' => 40,
            'harmless' => 10,
            'timeout' => 0,
        ]);
        $service = $this->make_service($provider);
        $scan = $service->enqueue_file_scan($this->create_file('cleanp.bin', 'c'), scan_source::MANUAL);
        $this->assertTrue($service->process_scan((int) $scan->id));
        $this->assertFalse($service->process_scan((int) $scan->id));
        $updated = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame(scan_status::CLEAN, $updated->status);
        $this->assertSame(scan_phase::COMPLETED, $updated->phase);
        $this->assertSame(0, (int) $updated->malicious);
        $this->assertSame(0, (int) $updated->suspicious);
        $this->assertGreaterThan(0, (int) $updated->timecompleted);
    }

    /**
     * Missing scans are ignored.
     */
    public function test_missing_scan_is_safe(): void {
        $this->resetAfterTest();
        $service = $this->make_service(new fake_provider());
        $this->assertFalse($service->process_scan(99999999));
        $this->assertFalse($service->process_scan(0));
        $this->assertFalse($service->process_scan(-3));
    }

    /**
     * Invalid task custom data does not throw.
     */
    public function test_invalid_task_payload_is_ignored(): void {
        $this->resetAfterTest();
        $task = new process_scan();
        $task->set_custom_data(['scanid' => 'nope']);
        $task->execute();
        $task->set_custom_data(['other' => 1]);
        $task->execute();
        $this->assertTrue(true);
    }

    /**
     * Completed analysis finalises through process_scan.
     */
    public function test_valid_scan_processed(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $service = $this->make_service($provider);
        $scan = $service->queue_file_scan($this->create_file('t.bin', 't'), scan_source::MANUAL);
        $this->assertFalse($service->process_scan((int) $scan->id));
        $updated = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame(scan_phase::COMPLETED, $updated->phase);
        $this->assertGreaterThanOrEqual(1, $provider->analysiscount);
    }

    /**
     * Retryable errors request another attempt until the bound is reached.
     */
    public function test_retryable_error_does_not_complete(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->analysisexception = new provider_exception('error_network');
        $service = $this->make_service($provider);
        $scan = $service->queue_file_scan($this->create_file('n.bin', 'n'), scan_source::MANUAL);
        $this->assertTrue($service->process_scan((int) $scan->id));
        $updated = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame(scan_status::PENDING, $updated->status);
        $this->assertSame('error_network', $updated->errorcode);
        $this->assertSame(1, (int) $updated->pollattempts);
    }

    /**
     * Permanent errors stop retrying.
     */
    public function test_permanent_error_does_not_retry(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->analysisexception = new provider_exception('error_forbidden', '', 403);
        $service = $this->make_service($provider);
        $scan = $service->queue_file_scan($this->create_file('f.bin', 'f'), scan_source::MANUAL);
        $this->assertFalse($service->process_scan((int) $scan->id));
        $updated = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame(scan_status::ERROR, $updated->status);
        $this->assertSame('error_forbidden', $updated->errorcode);
    }

    /**
     * Exhausted provider-failure attempts fail the scan.
     */
    public function test_max_attempts_stops_retry(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->analysisexception = new provider_exception('error_network');
        $service = $this->make_service($provider);
        $scan = $service->queue_file_scan($this->create_file('r.bin', 'r'), scan_source::MANUAL);
        $repo = new scan_repository();
        $record = $repo->get_by_id((int) $scan->id);
        $record->pollattempts = retry_policy::MAX_ATTEMPTS;
        $record->phase = scan_phase::POLLING;
        $record->vtanalysisid = 'analysis-fake-1';
        $repo->update($record);
        $this->assertFalse($service->process_scan((int) $scan->id));
        $updated = $repo->get_by_id((int) $scan->id);
        $this->assertSame(scan_status::ERROR, $updated->status);
        $this->assertSame('error_maxattempts', $updated->errorcode);
    }

    /**
     * A still-running provider analysis does not consume the failure budget.
     */
    public function test_in_progress_analysis_ignores_failure_budget(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->analysisresult = new analysis_result('analysis-fake-1', 'queued', null);
        $service = $this->make_service($provider);
        $scan = $service->queue_file_scan($this->create_file('waitcap.bin', 'w'), scan_source::MANUAL);
        $repo = new scan_repository();
        $record = $repo->get_by_id((int) $scan->id);
        $record->pollattempts = retry_policy::MAX_ATTEMPTS;
        $record->phase = scan_phase::POLLING;
        $record->vtanalysisid = 'analysis-fake-1';
        $record->status = scan_status::PENDING;
        $repo->update($record);
        $task = new recording_task();
        $this->assertTrue($service->process_scan((int) $scan->id, $task));
        $updated = $repo->get_by_id((int) $scan->id);
        $this->assertSame(scan_status::PENDING, $updated->status);
        $this->assertSame(scan_phase::POLLING, $updated->phase);
        $this->assertSame(retry_policy::MAX_ATTEMPTS, (int) $updated->pollattempts);
        $this->assertNotSame('error_maxattempts', (string) $updated->errorcode);
        $this->assertSame(retry_policy::DELAY_PENDING, $task->softdelay);
    }

    /**
     * Terminal scans are not processed again.
     */
    public function test_terminal_scan_exits_safely(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $service = $this->make_service($provider);
        $scan = $service->queue_file_scan($this->create_file('done.bin', 'd'), scan_source::MANUAL);
        $this->assertFalse($service->process_scan((int) $scan->id));
        $lookups = $provider->lookupcount;
        $uploads = $provider->uploadcount;
        $analyses = $provider->analysiscount;
        $this->assertFalse($service->process_scan((int) $scan->id));
        $updated = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame(scan_status::CLEAN, $updated->status);
        $this->assertSame($lookups, $provider->lookupcount);
        $this->assertSame($uploads, $provider->uploadcount);
        $this->assertSame($analyses, $provider->analysiscount);
    }

    /**
     * Duplicate process_scan after upload reuses the stored analysis id.
     */
    public function test_existing_analysis_id_is_reused(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $service = $this->make_service($provider);
        $scan = $service->enqueue_file_scan($this->create_file('up.bin', 'upload-me'), scan_source::MANUAL);
        $this->assertTrue($service->process_scan((int) $scan->id));
        $this->assertSame(1, $provider->uploadcount);
        $this->assertSame(1, $provider->lookupcount);
        $mid = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame('analysis-fake-1', $mid->vtanalysisid);
        $this->assertFalse($service->process_scan((int) $scan->id));
        $this->assertSame(1, $provider->uploadcount);
        $this->assertGreaterThanOrEqual(1, $provider->analysiscount);
        $updated = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame(scan_phase::COMPLETED, $updated->phase);
        $this->assertFalse($service->process_scan((int) $scan->id));
        $this->assertSame(1, $provider->uploadcount);
    }

    /**
     * Pending VirusTotal analysis reschedules with backoff.
     */
    public function test_pending_analysis_reschedules_with_backoff(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->analysisresult = new analysis_result('analysis-fake-1', 'queued', null);
        $service = $this->make_service($provider);
        $scan = $service->queue_file_scan($this->create_file('wait.bin', 'w'), scan_source::MANUAL);
        $task = new recording_task();
        $this->assertTrue($service->process_scan((int) $scan->id, $task));
        $updated = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame(scan_status::PENDING, $updated->status);
        $this->assertSame(scan_phase::POLLING, $updated->phase);
        $this->assertSame(retry_policy::DELAY_PENDING, $task->softdelay);
        $this->assertSame(0, (int) $updated->pollattempts);

        $task2 = new recording_task();
        $this->assertTrue($service->process_scan((int) $scan->id, $task2));
        $again = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame(retry_policy::DELAY_PENDING, $task2->softdelay);
        $this->assertSame(0, (int) $again->pollattempts);
    }

    /**
     * Rate-limit Retry-After is used instead of a tight loop.
     */
    public function test_rate_limit_uses_retry_after(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->analysisexception = new provider_exception('error_ratelimit', '', 429, 90);
        $service = $this->make_service($provider);
        $scan = $service->queue_file_scan($this->create_file('rl.bin', 'r'), scan_source::MANUAL);
        $task = new recording_task();
        $this->assertTrue($service->process_scan((int) $scan->id, $task));
        $this->assertSame(90, $task->softdelay);
        $updated = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame(scan_status::PENDING, $updated->status);
        $this->assertSame('error_ratelimit', $updated->errorcode);
        $this->assertSame('analysis-fake-1', $updated->vtanalysisid);
    }

    /**
     * A later successful lookup completes the same scan row after HTTP 429.
     */
    public function test_rate_limit_then_success_completes_same_scan(): void {
        global $DB;

        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->lookupexception = new provider_exception('error_ratelimit', '', 429, 120);
        $service = $this->make_service($provider);
        $scan = $service->enqueue_file_scan($this->create_file('rl-later.bin', 'rl-later'), scan_source::MANUAL);
        $scanid = (int) $scan->id;
        $this->assertTrue($service->process_scan($scanid, new recording_task()));
        $pending = (new scan_repository())->get_by_id($scanid);
        $this->assertSame(scan_status::PENDING, $pending->status);
        $this->assertSame('error_ratelimit', $pending->errorcode);
        $this->assertNotEquals(scan_status::CLEAN, $pending->status);
        $this->assertNotEquals(scan_status::MALICIOUS, $pending->status);

        $provider->lookupexception = null;
        $provider->lookupresult = new file_lookup_result(true, str_repeat('c', 64), [
            'malicious' => 0,
            'suspicious' => 0,
            'undetected' => 40,
            'harmless' => 10,
            'timeout' => 0,
        ]);
        $this->assertFalse($service->process_scan($scanid, new recording_task()));
        $done = (new scan_repository())->get_by_id($scanid);
        $this->assertSame(scan_status::CLEAN, $done->status);
        $this->assertSame(scan_phase::COMPLETED, $done->phase);
        $this->assertSame(1, $DB->count_records('antivirus_verdict_scans', ['filename' => 'rl-later.bin']));
        $this->assertSame($scanid, (int) $done->id);
    }

    /**
     * Network failures keep pending state and do not invent a verdict.
     */
    public function test_network_failure_does_not_corrupt_state(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->analysisexception = new provider_exception('error_network');
        $service = $this->make_service($provider);
        $scan = $service->queue_file_scan($this->create_file('net.bin', 'n'), scan_source::MANUAL);
        $analysisid = $scan->vtanalysisid;
        $task = new recording_task();
        $this->assertTrue($service->process_scan((int) $scan->id, $task));
        $this->assertSame(retry_policy::DELAY_NETWORK, $task->softdelay);
        $updated = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame(scan_status::PENDING, $updated->status);
        $this->assertSame($analysisid, $updated->vtanalysisid);
        $this->assertNotSame(scan_status::CLEAN, $updated->status);
    }

    /**
     * Malformed provider analysis becomes a safe error.
     */
    public function test_malformed_analysis_is_safe_error(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->analysisresult = new analysis_result('analysis-fake-1', 'exploded', null);
        $service = $this->make_service($provider);
        $scan = $service->queue_file_scan($this->create_file('bad.bin', 'b'), scan_source::MANUAL);
        $this->assertFalse($service->process_scan((int) $scan->id));
        $updated = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame(scan_status::ERROR, $updated->status);
        $this->assertSame('error_malformed', $updated->errorcode);
    }

    /**
     * Scans pending longer than the stale threshold fail rather than becoming clean.
     */
    public function test_stale_scan_fails_safely(): void {
        global $DB;

        $this->resetAfterTest();
        $provider = new fake_provider();
        $service = $this->make_service($provider);
        $scan = $service->enqueue_file_scan($this->create_file('old.bin', 'old'), scan_source::MANUAL);
        $DB->set_field(
            'antivirus_verdict_scans',
            'timecreated',
            time() - retry_policy::STALE_FAIL_AFTER - 10,
            ['id' => $scan->id]
        );
        $this->assertFalse($service->process_scan((int) $scan->id));
        $updated = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame(scan_status::ERROR, $updated->status);
        $this->assertSame('error_stale', $updated->errorcode);
        $this->assertSame(0, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
    }

    /**
     * Recovery re-queues recently stuck scans and fails very old ones.
     */
    public function test_recover_stale_scans(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $scheduler = new recording_scheduler();
        $service = new scan_service(
            $provider,
            new scan_repository(),
            new file_hasher(),
            new plugin_config(true, 1048576),
            $scheduler
        );
        $now = time();
        $fresh = $service->enqueue_file_scan($this->create_file('fresh.bin', 'f'), scan_source::MANUAL);
        $stuck = $service->enqueue_file_scan($this->create_file('stuck.bin', 's'), scan_source::MANUAL);
        $ancient = $service->enqueue_file_scan($this->create_file('ancient.bin', 'a'), scan_source::MANUAL);
        global $DB;
        $DB->set_field(
            'antivirus_verdict_scans',
            'timemodified',
            $now - retry_policy::STALE_REQUEUE_AFTER - 30,
            ['id' => $stuck->id]
        );
        $DB->set_field(
            'antivirus_verdict_scans',
            'timecreated',
            $now - retry_policy::STALE_REQUEUE_AFTER - 30,
            ['id' => $stuck->id]
        );
        $DB->set_field(
            'antivirus_verdict_scans',
            'timemodified',
            $now - retry_policy::STALE_REQUEUE_AFTER - 30,
            ['id' => $ancient->id]
        );
        $DB->set_field(
            'antivirus_verdict_scans',
            'timecreated',
            $now - retry_policy::STALE_FAIL_AFTER - 30,
            ['id' => $ancient->id]
        );

        $scheduler->queued = [];
        $handled = $service->recover_stale_scans($now);
        $this->assertGreaterThanOrEqual(2, $handled);
        $this->assertContains((int) $stuck->id, $scheduler->queued);
        $this->assertNotContains((int) $fresh->id, $scheduler->queued);
        $failed = (new scan_repository())->get_by_id((int) $ancient->id);
        $this->assertSame(scan_status::ERROR, $failed->status);
        $this->assertSame('error_stale', $failed->errorcode);
        $this->assertSame(0, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
    }

    /**
     * Create the service under test.
     *
     * @param fake_provider $provider Fake provider.
     * @return scan_service
     */
    private function make_service(fake_provider $provider): scan_service {
        return new scan_service(
            $provider,
            new scan_repository(),
            new file_hasher(),
            new plugin_config(true, 1048576),
            new recording_scheduler()
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
