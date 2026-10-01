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
 * Tests for controlled rescan of existing scan records.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\form\rescan_form;
use antivirus_verdict\local\file_hasher;
use antivirus_verdict\local\plugin_config;
use antivirus_verdict\local\rescan;
use antivirus_verdict\local\scan_access;
use antivirus_verdict\local\scan_repository;
use antivirus_verdict\local\scan_service;
use antivirus_verdict\provider\file_lookup_result;
use antivirus_verdict\tests\fake_provider;
use antivirus_verdict\tests\recording_scheduler;
use antivirus_verdict\tests\test_credentials;


/**
 * Rescan authorisation, history preservation, and asynchronous queueing.
 *
 * @covers \antivirus_verdict\local\rescan
 * @covers \antivirus_verdict\form\rescan_form
 * @covers \antivirus_verdict\local\scan_access
 */
final class rescan_test extends \advanced_testcase {
    /**
     * An authorised teacher can queue a new pending scan without calling VirusTotal.
     */
    public function test_authorized_rescan_creates_new_pending_scan(): void {
        $this->resetAfterTest();
        [$course, $teacher, $learner] = $this->prepare_course();
        $provider = new fake_provider();
        $provider->lookupresult = $this->clean_lookup();
        $scheduler = new recording_scheduler();
        $service = $this->make_service($provider, $scheduler);
        $file = $this->create_course_file($course, 'essay.pdf', 'essay-bytes');
        $original = $service->queue_file_scan($file, scan_source::ASSIGN, (int) $learner->id);
        $this->assertSame(scan_status::CLEAN, $original->status);

        $lookups = $provider->lookupcount;
        $uploads = $provider->uploadcount;
        $adapter = $this->make_rescan($service, true);
        $queued = $adapter->queue($original, (int) $teacher->id);

        $this->assertNotEquals($original->id, $queued->id);
        $this->assertSame(scan_status::PENDING, $queued->status);
        $this->assertSame(scan_phase::QUEUED, $queued->phase);
        $this->assertSame(scan_source::ASSIGN, $queued->source);
        $this->assertSame((int) $learner->id, (int) $queued->userid);
        $this->assertSame($lookups, $provider->lookupcount);
        $this->assertSame($uploads, $provider->uploadcount);
        $this->assertSame(0, $provider->analysiscount);
        $this->assertContains((int) $queued->id, $scheduler->queued);

        $reloaded = (new scan_repository())->get_by_id((int) $original->id);
        $this->assertSame(scan_status::CLEAN, $reloaded->status);
        $this->assertSame(scan_phase::COMPLETED, $reloaded->phase);
        $this->assertSame((int) $original->malicious, (int) $reloaded->malicious);
    }

    /**
     * Students and teachers in another course cannot rescan.
     */
    public function test_unauthorized_and_course_isolation(): void {
        $this->resetAfterTest();
        [$course, $teacher, $learner] = $this->prepare_course();
        $other = $this->getDataGenerator()->create_course();
        $outsider = $this->getDataGenerator()->create_and_enrol($other, 'editingteacher');
        $student = $this->getDataGenerator()->create_and_enrol($course, 'student');
        $nonediting = $this->getDataGenerator()->create_and_enrol($course, 'teacher');
        $service = $this->make_service(new fake_provider(), new recording_scheduler());
        $file = $this->create_course_file($course, 'secret.bin', 'secret');
        $scan = $service->queue_file_scan($file, scan_source::ASSIGN, (int) $learner->id);
        $this->complete_scan($scan);

        $this->assertTrue(scan_access::can_rescan($scan, (int) $teacher->id));
        $this->assertFalse(scan_access::can_rescan($scan, (int) $student->id));
        $this->assertFalse(scan_access::can_rescan($scan, (int) $outsider->id));
        $this->assertTrue(scan_access::can_rescan($scan, (int) $nonediting->id));

        $adapter = $this->make_rescan($service, true);
        $this->expectException(\required_capability_exception::class);
        $adapter->queue($scan, (int) $outsider->id);
    }

    /**
     * A missing or invalid scan id fails safely.
     */
    public function test_missing_and_invalid_scan_id(): void {
        $this->resetAfterTest();
        $adapter = $this->make_rescan($this->make_service(new fake_provider(), new recording_scheduler()), true);
        try {
            $adapter->queue_by_id(0, 2);
            $this->fail('Zero id should throw.');
        } catch (\moodle_exception $e) {
            $this->assertSame('error_invalidrequest', $e->errorcode);
        }
        try {
            $adapter->queue_by_id(99999999, 2);
            $this->fail('Unknown id should throw.');
        } catch (\moodle_exception $e) {
            $this->assertSame('error_invalidrequest', $e->errorcode);
        }
    }

    /**
     * Deleted original files cannot be rescanned from an old hash.
     */
    public function test_missing_original_file(): void {
        $this->resetAfterTest();
        [$course, $teacher, $learner] = $this->prepare_course();
        $service = $this->make_service(new fake_provider(), new recording_scheduler());
        $file = $this->create_course_file($course, 'gone.bin', 'gone');
        $scan = $service->queue_file_scan($file, scan_source::ASSIGN, (int) $learner->id);
        $this->complete_scan($scan);
        $file->delete();

        $adapter = $this->make_rescan($service, true);
        $this->assertFalse($adapter->file_available($scan));
        $this->assertFalse($adapter->is_eligible($scan));
        try {
            $adapter->queue($scan, (int) $teacher->id);
            $this->fail('Missing file should throw.');
        } catch (\moodle_exception $e) {
            $this->assertSame('error_filenotavailable', $e->errorcode);
        }
    }

    /**
     * Disabled scanner cannot queue a rescan.
     */
    public function test_scanner_disabled(): void {
        $this->resetAfterTest();
        [$course, $teacher, $learner] = $this->prepare_course();
        $service = $this->make_service(new fake_provider(), new recording_scheduler(), true);
        $file = $this->create_course_file($course, 'off.bin', 'off');
        $scan = $service->queue_file_scan($file, scan_source::ASSIGN, (int) $learner->id);
        $this->complete_scan($scan);

        $disabled = $this->make_rescan($service, false);
        $this->assertFalse($disabled->can_queue());
        $this->assertFalse($disabled->is_eligible($scan));
        try {
            $disabled->queue($scan, (int) $teacher->id);
            $this->fail('Disabled scanner should throw.');
        } catch (\moodle_exception $e) {
            $this->assertSame('scanningincomplete', $e->errorcode);
        }
    }

    /**
     * An in-flight scan of the same file is reused instead of duplicating work.
     */
    public function test_duplicate_active_scan_is_reused(): void {
        $this->resetAfterTest();
        [$course, $teacher, $learner] = $this->prepare_course();
        $provider = new fake_provider();
        $scheduler = new recording_scheduler();
        $service = $this->make_service($provider, $scheduler);
        $file = $this->create_course_file($course, 'once.bin', 'once');
        $original = $service->queue_file_scan($file, scan_source::ASSIGN, (int) $learner->id);
        $this->complete_scan($original);

        $lookups = $provider->lookupcount;
        $adapter = $this->make_rescan($service, true);
        $scheduler->queued = [];
        $first = $adapter->queue($original, (int) $teacher->id);
        $second = $adapter->queue($original, (int) $teacher->id);
        $this->assertEquals($first->id, $second->id);
        $this->assertNotEquals($original->id, $first->id);
        $this->assertSame(scan_status::PENDING, $first->status);
        $this->assertCount(1, $scheduler->queued);
        $this->assertSame($lookups, $provider->lookupcount);
    }

    /**
     * An ordinary new scan of identical content still reuses the stored verdict.
     */
    public function test_ordinary_duplicate_scan_reuses_completed_verdict(): void {
        $this->resetAfterTest();
        [$course, , $learner] = $this->prepare_course();
        $provider = new fake_provider();
        $provider->lookupresult = $this->clean_lookup();
        $service = $this->make_service($provider, new recording_scheduler());

        $first = $service->queue_file_scan(
            $this->create_course_file($course, 'a.bin', 'same-bytes'),
            scan_source::ASSIGN,
            (int) $learner->id
        );
        $this->assertSame(scan_status::CLEAN, $first->status);
        $this->assertSame(1, $provider->lookupcount);

        $second = $service->queue_file_scan(
            $this->create_course_file($course, 'b.bin', 'same-bytes'),
            scan_source::ASSIGN,
            (int) $learner->id
        );
        $this->assertNotEquals($first->id, $second->id);
        $this->assertSame(scan_status::CLEAN, $second->status);
        $this->assertSame(scan_phase::COMPLETED, $second->phase);
        $this->assertSame(1, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
    }

    /**
     * An explicit rescan skips the stored verdict and queries VirusTotal again.
     */
    public function test_explicit_rescan_bypasses_completed_verdict_reuse(): void {
        global $DB;

        $this->resetAfterTest();
        [$course, $teacher, $learner] = $this->prepare_course();
        $provider = new fake_provider();
        $provider->lookupresult = $this->clean_lookup();
        $scheduler = new recording_scheduler();
        $service = $this->make_service($provider, $scheduler);
        $file = $this->create_course_file($course, 'again.bin', 'again-bytes');
        $original = $service->queue_file_scan($file, scan_source::ASSIGN, (int) $learner->id);
        $this->assertSame(scan_status::CLEAN, $original->status);
        $this->assertSame(1, $provider->lookupcount);
        $originalcompleted = (int) (new scan_repository())->get_by_id((int) $original->id)->timecompleted;

        $queued = $this->make_rescan($service, true)->queue($original, (int) $teacher->id);
        $this->assertNotEquals($original->id, $queued->id);
        $this->assertSame(scan_status::PENDING, $queued->status);
        $this->assertContains((int) $queued->id, $scheduler->forced);
        $this->assertSame(1, $provider->lookupcount);

        $service->process_scan((int) $queued->id, null, true);

        $this->assertSame(2, $provider->lookupcount);
        $repo = new scan_repository();
        $rescanned = $repo->get_by_id((int) $queued->id);
        $this->assertSame(scan_status::CLEAN, $rescanned->status);
        $this->assertSame(scan_phase::COMPLETED, $rescanned->phase);

        $reloadedoriginal = $repo->get_by_id((int) $original->id);
        $this->assertSame(scan_status::CLEAN, $reloadedoriginal->status);
        $this->assertSame(scan_phase::COMPLETED, $reloadedoriginal->phase);
        $this->assertSame($originalcompleted, (int) $reloadedoriginal->timecompleted);

        $rows = $DB->get_records('antivirus_verdict_scans', ['pathnamehash' => $file->get_pathnamehash()]);
        $this->assertCount(2, $rows);
        $this->assertArrayHasKey($original->id, $rows);
        $this->assertArrayHasKey($queued->id, $rows);
    }

    /**
     * A forced rescan still attaches to concurrent provider work for the same content.
     */
    public function test_forced_rescan_does_not_duplicate_inflight_analysis(): void {
        $this->resetAfterTest();
        [$course, , $learner] = $this->prepare_course();
        $provider = new fake_provider();
        $service = $this->make_service($provider, new recording_scheduler());
        $inflight = $service->queue_file_scan(
            $this->create_course_file($course, 'inflight.bin', 'shared-bytes'),
            scan_source::ASSIGN,
            (int) $learner->id
        );
        $this->assertSame(1, $provider->uploadcount);
        $this->assertSame(scan_phase::POLLING, (new scan_repository())->get_by_id((int) $inflight->id)->phase);

        $forced = $service->enqueue_file_scan(
            $this->create_course_file($course, 'forced.bin', 'shared-bytes'),
            scan_source::ASSIGN,
            (int) $learner->id,
            true
        );
        $service->process_scan((int) $forced->id, null, true);

        $record = (new scan_repository())->get_by_id((int) $forced->id);
        $this->assertSame(scan_phase::POLLING, $record->phase);
        $this->assertSame('analysis-fake-1', $record->vtanalysisid);
        $this->assertSame(1, $provider->uploadcount);
    }

    /**
     * Historical completed rows remain after an intentional rescan.
     */
    public function test_historical_and_rescan_are_two_records(): void {
        global $DB;

        $this->resetAfterTest();
        [$course, $teacher, $learner] = $this->prepare_course();
        $service = $this->make_service(new fake_provider(), new recording_scheduler());
        $file = $this->create_course_file($course, 'hist.bin', 'hist');
        $original = $service->queue_file_scan($file, scan_source::ASSIGN, (int) $learner->id);
        $this->complete_scan($original);
        $adapter = $this->make_rescan($service, true);
        $queued = $adapter->queue($original, (int) $teacher->id);

        $rows = $DB->get_records('antivirus_verdict_scans', ['pathnamehash' => $file->get_pathnamehash()]);
        $this->assertCount(2, $rows);
        $this->assertArrayHasKey($original->id, $rows);
        $this->assertArrayHasKey($queued->id, $rows);
    }

    /**
     * Rescan form is POST and requires sesskey.
     */
    public function test_form_is_post_and_requires_sesskey(): void {
        $this->resetAfterTest();
        $user = $this->getDataGenerator()->create_user();
        $this->setUser($user);
        $form = new rescan_form(null, ['id' => 12]);
        $html = $form->render();
        $this->assertMatchesRegularExpression('/<form[^>]*method="post"/i', $html);
        $this->assertStringContainsString('sesskey', $html);
        $this->assertNull($form->get_data());

        $_POST['id'] = 12;
        $_POST['sesskey'] = 'not-a-sesskey';
        $_POST['submitbutton'] = get_string('rescanfile', 'antivirus_verdict');
        $submitted = new rescan_form(null, ['id' => 12]);
        $this->assertNull($submitted->get_data());
    }

    /**
     * Scan detail does not mutate state from a GET rescan parameter.
     */
    public function test_view_php_does_not_rescan_on_get(): void {
        global $CFG;
        $source = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/view.php');
        $this->assertStringNotContainsString("optional_param('rescan'", $source);
        $this->assertStringNotContainsString('$_GET[\'rescan\']', $source);
        $this->assertStringContainsString('rescan_form', $source);
        $this->assertStringContainsString('require_sesskey', $source);
        $this->assertStringNotContainsString('lookup_file_hash', $source);
        $this->assertStringNotContainsString('upload_file', $source);
    }

    /**
     * Create a course with an editing teacher and a learner.
     *
     * @return array
     */
    private function prepare_course(): array {
        $course = $this->getDataGenerator()->create_course();
        $teacher = $this->getDataGenerator()->create_and_enrol($course, 'editingteacher');
        $learner = $this->getDataGenerator()->create_and_enrol($course, 'student');
        return [$course, $teacher, $learner];
    }

    /**
     * Force a scan row to a completed clean history record.
     *
     * @param \stdClass $scan Scan row.
     */
    private function complete_scan(\stdClass $scan): void {
        $repo = new scan_repository();
        $record = $repo->get_by_id((int) $scan->id);
        $record->status = scan_status::CLEAN;
        $record->phase = scan_phase::COMPLETED;
        $record->timecompleted = time();
        $record->errorcode = null;
        $repo->update($record);
        $scan->status = $record->status;
        $scan->phase = $record->phase;
    }

    /**
     * Known clean lookup result.
     *
     * @return file_lookup_result
     */
    private function clean_lookup(): file_lookup_result {
        return new file_lookup_result(
            true,
            str_repeat('a', 64),
            ['malicious' => 0, 'suspicious' => 0, 'undetected' => 10, 'harmless' => 5]
        );
    }

    /**
     * Build the scan engine.
     *
     * @param fake_provider $provider Fake provider.
     * @param recording_scheduler $scheduler Fake scheduler.
     * @param bool $enabled Master switch.
     * @return scan_service
     */
    private function make_service(
        fake_provider $provider,
        recording_scheduler $scheduler,
        bool $enabled = true
    ): scan_service {
        return new scan_service(
            $provider,
            new scan_repository(),
            new file_hasher(),
            new plugin_config($enabled, 1048576, false),
            $scheduler
        );
    }

    /**
     * Build a rescan adapter.
     *
     * @param scan_service $service Scan engine.
     * @param bool $enabled Master switch.
     * @return rescan
     */
    private function make_rescan(scan_service $service, bool $enabled): rescan {
        return new rescan(
            $service,
            new plugin_config($enabled, 1048576, false),
            new scan_repository(),
            new test_credentials($enabled ? 'unit-test-key' : '')
        );
    }

    /**
     * Create a stored file in a course context.
     *
     * @param \stdClass $course Course.
     * @param string $filename File name.
     * @param string $content Bytes.
     * @return \stored_file
     */
    private function create_course_file(\stdClass $course, string $filename, string $content): \stored_file {
        $fs = get_file_storage();
        return $fs->create_file_from_string([
            'contextid' => \context_course::instance($course->id)->id,
            'component' => 'assignsubmission_file',
            'filearea' => 'submission_files',
            'itemid' => random_int(1, 100000000),
            'filepath' => '/',
            'filename' => $filename,
        ], $content);
    }
}
