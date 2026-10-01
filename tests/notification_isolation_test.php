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
 * Notification failures must not overwrite scan verdicts.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\file_hasher;
use antivirus_verdict\local\plugin_config;
use antivirus_verdict\local\retry_policy;
use antivirus_verdict\local\scan_notifications;
use antivirus_verdict\local\scan_policy;
use antivirus_verdict\local\scan_repository;
use antivirus_verdict\local\scan_service;
use antivirus_verdict\provider\analysis_result;
use antivirus_verdict\provider\file_lookup_result;
use antivirus_verdict\tests\environment_debugging_trait;
use antivirus_verdict\provider\provider_exception;
use antivirus_verdict\tests\fake_provider;
use antivirus_verdict\tests\recording_scheduler;
use antivirus_verdict\tests\throwing_notifications;


/**
 * Isolation of Moodle messaging from the scan engine.
 *
 * @covers \antivirus_verdict\local\scan_service
 * @covers \antivirus_verdict\local\scan_notifications
 */
final class notification_isolation_test extends \advanced_testcase {
    use environment_debugging_trait;

    /**
     * Clean + notification failure remains clean.
     */
    public function test_clean_survives_notification_failure(): void {
        $this->resetAfterTest();
        $this->assert_status_after_notify_failure(
            ['malicious' => 0, 'suspicious' => 0, 'undetected' => 40, 'harmless' => 10, 'timeout' => 0],
            scan_status::CLEAN
        );
    }

    /**
     * Malicious + notification failure remains malicious.
     */
    public function test_malicious_survives_notification_failure(): void {
        $this->resetAfterTest();
        $this->assert_status_after_notify_failure(
            ['malicious' => 5, 'suspicious' => 0, 'undetected' => 40, 'harmless' => 0, 'timeout' => 0],
            scan_status::MALICIOUS
        );
    }

    /**
     * Suspicious + notification failure remains suspicious.
     */
    public function test_suspicious_survives_notification_failure(): void {
        $this->resetAfterTest();
        $this->assert_status_after_notify_failure(
            ['malicious' => 0, 'suspicious' => 3, 'undetected' => 40, 'harmless' => 0, 'timeout' => 0],
            scan_status::SUSPICIOUS
        );
    }

    /**
     * Provider errors stay provider errors when notification delivery fails.
     */
    public function test_provider_error_survives_notification_failure(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->lookupexception = new provider_exception('error_auth');
        $scheduler = new recording_scheduler();
        $notifier = new throwing_notifications($this->notify_config());
        $service = $this->make_service($provider, $scheduler, $notifier);
        $scan = $service->enqueue_file_scan($this->create_file('auth.bin', 'auth-bytes'), scan_source::MANUAL);

        $this->assertFalse($service->process_scan((int) $scan->id));
        $this->assert_verdict_debugging_with_optional_environment_noise('antivirus_verdict notification hook failed');

        $updated = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame(scan_status::ERROR, $updated->status);
        $this->assertSame('error_auth', $updated->errorcode);
        $this->assertNotEquals('error_maxattempts', $updated->errorcode);
        $this->assertSame(1, $notifier->calls);
        $this->assertSame([], $scheduler->retries);
        $this->assertSame(1, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
        $this->assertSame(0, $provider->analysiscount);
    }

    /**
     * Pending analysis is not failed when a notifier is injected.
     */
    public function test_pending_does_not_notify_or_fail(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->analysisresult = new analysis_result('analysis-fake-1', 'queued', null);
        $scheduler = new recording_scheduler();
        $notifier = new throwing_notifications($this->notify_config());
        $service = $this->make_service($provider, $scheduler, $notifier);
        $scan = $service->enqueue_file_scan($this->create_file('wait.bin', 'wait-bytes'), scan_source::MANUAL);

        $this->assertTrue($service->process_scan((int) $scan->id));

        $updated = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame(scan_status::PENDING, $updated->status);
        $this->assertSame(scan_phase::POLLING, $updated->phase);
        $this->assertSame(0, $notifier->calls);
        $this->assertNotEquals(scan_status::ERROR, $updated->status);
        $this->assertSame(0, $provider->analysiscount);
    }

    /**
     * Notification throttle keys must be valid for the simple-key cache.
     */
    public function test_real_malicious_notification_uses_valid_cache_key(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $notifier = scan_notifications::from_site_config();
        $record = (object) [
            'id' => 42,
            'filename' => 'eicar.com',
            'status' => scan_status::MALICIOUS,
            'source' => scan_source::MANUAL,
        ];
        $notifier->scan_finished($record);
        $notifier->scan_finished($record);
        foreach ($this->getDebuggingMessages() as $debug) {
            $this->assertStringNotContainsString('notification hook failed', $debug->message);
            $this->assertStringNotContainsString('Invalid key', $debug->message);
        }
        $this->resetDebugging();
    }

    /**
     * Manual kickoff must not burn the poll budget on a still-queued analysis.
     */
    public function test_manual_kickoff_does_not_exhaust_pending_polls(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->analysisresult = new analysis_result('analysis-fake-1', 'queued', null);
        $scheduler = new recording_scheduler();
        $notifier = new throwing_notifications($this->notify_config());
        $service = $this->make_service($provider, $scheduler, $notifier);
        $scan = $service->enqueue_file_scan($this->create_file('kick.bin', 'kick-bytes'), scan_source::MANUAL);

        $kickoff = new \ReflectionMethod(scan_service::class, 'kickoff_manual_processing');
        $kickoff->setAccessible(true);
        $kickoff->invoke($service, (int) $scan->id);

        $updated = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame(scan_status::PENDING, $updated->status);
        $this->assertSame(scan_phase::POLLING, $updated->phase);
        $this->assertSame('analysis-fake-1', $updated->vtanalysisid);
        $this->assertLessThan(retry_policy::MAX_ATTEMPTS, (int) $updated->pollattempts);
        $this->assertNotEquals(scan_status::ERROR, $updated->status);
        $this->assertNotEquals('error_maxattempts', $updated->errorcode);
        $this->assertSame(0, $notifier->calls);
        $this->assertSame(1, $provider->uploadcount);
        $this->assertLessThan(retry_policy::MAX_ATTEMPTS, $provider->analysiscount);
        $this->assertSame([], $scheduler->retries);
    }

    /**
     * Complete a known hash and assert the verdict is unchanged after notify throw.
     *
     * @param array $stats Provider stats.
     * @param string $expected Expected status.
     */
    private function assert_status_after_notify_failure(array $stats, string $expected): void {
        $provider = new fake_provider();
        $provider->lookupresult = new file_lookup_result(true, str_repeat('a', 64), $stats);
        $scheduler = new recording_scheduler();
        $notifier = new throwing_notifications($this->notify_config());
        $service = $this->make_service($provider, $scheduler, $notifier);
        $scan = $service->enqueue_file_scan($this->create_file($expected . '.bin', $expected . '-bytes'), scan_source::MANUAL);

        $this->assertFalse($service->process_scan((int) $scan->id));
        $this->assert_verdict_debugging_with_optional_environment_noise('antivirus_verdict notification hook failed');

        $updated = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame($expected, $updated->status);
        $this->assertSame(scan_phase::COMPLETED, $updated->phase);
        $this->assertSame(1, $notifier->calls);
        $this->assertSame(1, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
        $this->assertSame(0, $provider->analysiscount);
        $this->assertSame([], $scheduler->retries);
        $this->assertNotEquals(scan_status::ERROR, $updated->status);
        $this->assertSame([(int) $scan->id], $scheduler->queued);
    }

    /**
     * Build a service with a failing notifier.
     *
     * @param fake_provider $provider Fake provider.
     * @param recording_scheduler $scheduler Fake scheduler.
     * @param throwing_notifications $notifier Failing notifier.
     * @return scan_service
     */
    private function make_service(
        fake_provider $provider,
        recording_scheduler $scheduler,
        throwing_notifications $notifier
    ): scan_service {
        return new scan_service(
            $provider,
            new scan_repository(),
            new file_hasher(),
            $this->notify_config(),
            $scheduler,
            null,
            null,
            $notifier
        );
    }

    /**
     * Config that still notifies but does not quarantine during these tests.
     *
     * @return plugin_config
     */
    private function notify_config(): plugin_config {
        return new plugin_config(
            true,
            1048576,
            false,
            scan_policy::ALLOW,
            scan_policy::ALLOW,
            scan_policy::BLOCK,
            scan_policy::REPORT
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
