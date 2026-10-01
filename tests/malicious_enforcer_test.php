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
 * Tests for asynchronous malicious verdict enforcement.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\file_hasher;
use antivirus_verdict\local\malicious_enforcer;
use antivirus_verdict\local\plugin_config;
use antivirus_verdict\local\plugin_file_lifecycle;
use antivirus_verdict\local\scan_policy;
use antivirus_verdict\local\scan_repository;
use antivirus_verdict\local\scan_service;
use antivirus_verdict\provider\analysis_result;
use antivirus_verdict\provider\file_lookup_result;
use antivirus_verdict\tests\fake_provider;
use antivirus_verdict\tests\recording_enforcer;
use antivirus_verdict\tests\recording_scheduler;
use core\antivirus\quarantine;


/**
 * Post-upload response when VirusTotal resolves malicious after acceptance.
 *
 * @covers \antivirus_verdict\local\malicious_enforcer
 * @covers \antivirus_verdict\enforcement_state
 */
final class malicious_enforcer_test extends \advanced_testcase {
    /** Content used as a stand-in for malware. Never real malware. */
    private const MALICIOUS_CONTENT = 'verdict-phpunit-pretend-malware';

    /**
     * Remove anything written into the shared quarantine folder.
     */
    protected function tearDown(): void {
        if (quarantine::is_quarantine_enabled()) {
            quarantine::clean_up_quarantine_folder(time() + DAYSECS);
        }
        parent::tearDown();
    }

    /**
     * A malicious verdict on a live file reaches Moodle's own quarantine,
     * infected-file event, and infected_files report, and removes the file.
     */
    public function test_live_file_is_quarantined_through_core_and_removed(): void {
        global $DB;
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('enablequarantine', 1, 'antivirus');
        $this->redirectMessages();

        $file = $this->create_submission_file('payload.bin', self::MALICIOUS_CONTENT);
        $fileid = (int) $file->get_id();
        $record = $this->malicious_record($file);

        $sink = $this->redirectEvents();
        $outcome = (new malicious_enforcer(new scan_repository(), $this->config()))->enforce($record);
        $events = $sink->get_events();
        $sink->close();

        $this->assertSame(enforcement_state::QUARANTINED, $outcome);
        $this->assertFalse(get_file_storage()->get_file_by_id($fileid), 'The malicious file must no longer exist.');

        $infected = $DB->get_records('infected_files');
        $this->assertCount(1, $infected);
        $this->assertSame('payload.bin', reset($infected)->filename);
        $this->assertNotEmpty(quarantine::get_quarantined_files());

        $detected = array_values(array_filter($events, static function ($event): bool {
            return $event instanceof \core\event\virus_infected_file_detected;
        }));
        $this->assertCount(1, $detected);
        $this->assertSame('payload.bin', $detected[0]->other['filename']);

        $this->assertSame(
            enforcement_state::QUARANTINED,
            (new scan_repository())->get_by_id((int) $record->id)->enforcement
        );
    }

    /**
     * The scan engine applies enforcement when polling resolves to malicious.
     */
    public function test_scan_service_enforces_a_late_malicious_analysis(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->analysisresult = new analysis_result('analysis-1', 'completed', [
            'malicious' => 44,
            'suspicious' => 2,
            'undetected' => 20,
            'harmless' => 0,
            'timeout' => 0,
        ]);
        $enforcer = new recording_enforcer(new scan_repository(), $this->config());
        $service = $this->make_service($provider, $enforcer);

        $file = $this->create_submission_file('late.bin', self::MALICIOUS_CONTENT);
        $fileid = (int) $file->get_id();
        $scan = $service->queue_file_scan($file, scan_source::ASSIGN, 0);
        $this->assertSame(scan_status::PENDING, $scan->status);

        $service->process_scan((int) $scan->id);

        $stored = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame(scan_status::MALICIOUS, $stored->status);
        $this->assertSame(scan_phase::COMPLETED, $stored->phase);
        $this->assertSame(enforcement_state::QUARANTINED, $stored->enforcement);
        $this->assertCount(1, $enforcer->quarantined);
        $this->assertSame(self::MALICIOUS_CONTENT, $enforcer->quarantined[0]['content']);
        $this->assertSame([$fileid], $enforcer->deleted);
        $this->assertCount(1, $enforcer->events);
        $this->assertCount(1, $enforcer->notifications);
        $this->assertFalse(get_file_storage()->get_file_by_id($fileid));
    }

    /**
     * A 429 that later resolves malicious enforces the existing scan row.
     */
    public function test_rate_limit_then_malicious_enforces_same_scan(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->lookupexception = new \antivirus_verdict\provider\provider_exception('error_ratelimit', '', 429, 60);
        $enforcer = new recording_enforcer(new scan_repository(), $this->config());
        $service = $this->make_service($provider, $enforcer);

        $file = $this->create_submission_file('late-rl.bin', self::MALICIOUS_CONTENT);
        $fileid = (int) $file->get_id();
        $scan = $service->enqueue_file_scan($file, scan_source::ASSIGN, 0);
        $scanid = (int) $scan->id;
        $this->assertTrue($service->process_scan($scanid));
        $pending = (new scan_repository())->get_by_id($scanid);
        $this->assertSame(scan_status::PENDING, $pending->status);
        $this->assertSame('error_ratelimit', $pending->errorcode);

        $provider->lookupexception = null;
        $provider->lookupresult = new file_lookup_result(true, str_repeat('e', 64), [
            'malicious' => 44,
            'suspicious' => 2,
            'undetected' => 20,
            'harmless' => 0,
            'timeout' => 0,
        ]);
        $this->assertFalse($service->process_scan($scanid));

        $stored = (new scan_repository())->get_by_id($scanid);
        $this->assertSame(scan_status::MALICIOUS, $stored->status);
        $this->assertSame(scan_phase::COMPLETED, $stored->phase);
        $this->assertSame(enforcement_state::QUARANTINED, $stored->enforcement);
        $this->assertCount(1, $enforcer->quarantined);
        $this->assertSame([$fileid], $enforcer->deleted);
        $this->assertFalse(get_file_storage()->get_file_by_id($fileid));
    }

    /**
     * A file deleted before the verdict arrives is recorded, not quarantined.
     */
    public function test_deleted_file_is_recorded_without_quarantine(): void {
        $this->resetAfterTest();
        $file = $this->create_submission_file('gone.bin', self::MALICIOUS_CONTENT);
        $record = $this->malicious_record($file);
        $file->delete();

        $enforcer = new recording_enforcer(new scan_repository(), $this->config());
        $outcome = $enforcer->enforce($record);

        $this->assertSame(enforcement_state::FILEMISSING, $outcome);
        $this->assertSame([], $enforcer->quarantined);
        $this->assertSame([], $enforcer->deleted);
        // Still auditable and still notified: the detection must not be silent.
        $this->assertCount(1, $enforcer->events);
        $this->assertCount(1, $enforcer->notifications);
        $this->assertSame(scan_status::MALICIOUS, (new scan_repository())->get_by_id((int) $record->id)->status);
    }

    /**
     * A replacement file at the same location is never touched.
     */
    public function test_replaced_file_is_left_alone(): void {
        $this->resetAfterTest();
        $file = $this->create_submission_file('essay.docx', self::MALICIOUS_CONTENT);
        $record = $this->malicious_record($file);
        $location = [
            'contextid' => $file->get_contextid(),
            'component' => $file->get_component(),
            'filearea' => $file->get_filearea(),
            'itemid' => $file->get_itemid(),
            'filepath' => '/',
            'filename' => 'essay.docx',
        ];
        $file->delete();
        $replacement = get_file_storage()->create_file_from_string($location, 'an innocent rewritten essay');
        $this->assertSame((string) $record->pathnamehash, (string) $replacement->get_pathnamehash());

        $enforcer = new recording_enforcer(new scan_repository(), $this->config());
        $outcome = $enforcer->enforce($record);

        $this->assertSame(enforcement_state::MISMATCH, $outcome);
        $this->assertSame([], $enforcer->quarantined, 'An unrelated file must never be quarantined.');
        $this->assertSame([], $enforcer->deleted);
        $this->assertInstanceOf(\stored_file::class, get_file_storage()->get_file_by_id((int) $replacement->get_id()));
    }

    /**
     * Content that no longer hashes to the scanned SHA-256 fails closed even
     * when the recorded contenthash is unavailable.
     */
    public function test_content_identity_is_verified_independently(): void {
        $this->resetAfterTest();
        $file = $this->create_submission_file('doc.pdf', self::MALICIOUS_CONTENT);
        $record = $this->malicious_record($file);
        $record->contenthash = '';
        $record->sha256 = str_repeat('b', 64);
        (new scan_repository())->update($record);

        $enforcer = new recording_enforcer(new scan_repository(), $this->config());

        $this->assertSame(enforcement_state::MISMATCH, $enforcer->enforce($record));
        $this->assertSame([], $enforcer->deleted);
        $this->assertInstanceOf(\stored_file::class, get_file_storage()->get_file_by_id((int) $file->get_id()));
    }

    /**
     * Repeated processing of the same malicious scan enforces exactly once.
     */
    public function test_enforcement_is_idempotent(): void {
        $this->resetAfterTest();
        $file = $this->create_submission_file('twice.bin', self::MALICIOUS_CONTENT);
        $record = $this->malicious_record($file);

        $enforcer = new recording_enforcer(new scan_repository(), $this->config());
        $first = $enforcer->enforce($record);
        $second = $enforcer->enforce($record);
        $third = $enforcer->enforce((new scan_repository())->get_by_id((int) $record->id));

        $this->assertSame(enforcement_state::QUARANTINED, $first);
        $this->assertSame(enforcement_state::QUARANTINED, $second);
        $this->assertSame(enforcement_state::QUARANTINED, $third);
        $this->assertCount(1, $enforcer->quarantined);
        $this->assertCount(1, $enforcer->deleted);
        $this->assertCount(1, $enforcer->events);
        $this->assertCount(1, $enforcer->notifications);
    }

    /**
     * A second worker holding a stale row does not enforce again.
     */
    public function test_second_worker_does_not_repeat_enforcement(): void {
        $this->resetAfterTest();
        $file = $this->create_submission_file('shared.bin', self::MALICIOUS_CONTENT);
        $record = $this->malicious_record($file);
        // The row each worker loaded before either of them started.
        $workerone = (new scan_repository())->get_by_id((int) $record->id);
        $workertwo = (new scan_repository())->get_by_id((int) $record->id);

        $first = new recording_enforcer(new scan_repository(), $this->config());
        $second = new recording_enforcer(new scan_repository(), $this->config());

        $this->assertSame(enforcement_state::QUARANTINED, $first->enforce($workerone));
        $this->assertSame(enforcement_state::QUARANTINED, $second->enforce($workertwo));
        $this->assertCount(1, $first->quarantined);
        $this->assertSame([], $second->quarantined);
        $this->assertSame([], $second->deleted);
        $this->assertSame([], $second->notifications);
    }

    /**
     * A quarantine error is never reported as a successful cleanup.
     */
    public function test_quarantine_failure_is_recorded_as_failed(): void {
        $this->resetAfterTest();
        $file = $this->create_submission_file('boom.bin', self::MALICIOUS_CONTENT);
        $record = $this->malicious_record($file);

        $enforcer = new recording_enforcer(new scan_repository(), $this->config());
        $enforcer->quarantinethrows = new \moodle_exception('error_generic', 'antivirus_verdict');
        $outcome = $enforcer->enforce($record);

        $this->assertSame(enforcement_state::FAILED, $outcome);
        $this->assertDebuggingCalled();
        $this->assertSame([], $enforcer->deleted, 'A file must not be deleted when it could not be captured.');
        $this->assertInstanceOf(\stored_file::class, get_file_storage()->get_file_by_id((int) $file->get_id()));

        $stored = (new scan_repository())->get_by_id((int) $record->id);
        $this->assertSame(scan_status::MALICIOUS, $stored->status);
        $this->assertSame(enforcement_state::FAILED, $stored->enforcement);
        // The administrator still hears about it.
        $this->assertCount(1, $enforcer->notifications);
    }

    /**
     * A notification error does not undo a completed security action.
     */
    public function test_notification_failure_keeps_the_quarantine_outcome(): void {
        $this->resetAfterTest();
        $file = $this->create_submission_file('quiet.bin', self::MALICIOUS_CONTENT);
        $fileid = (int) $file->get_id();
        $record = $this->malicious_record($file);

        $enforcer = new recording_enforcer(new scan_repository(), $this->config());
        $enforcer->notifythrows = new \moodle_exception('error_generic', 'antivirus_verdict');
        $enforcer->eventthrows = new \moodle_exception('error_generic', 'antivirus_verdict');
        $outcome = $enforcer->enforce($record);

        $this->assertSame(enforcement_state::QUARANTINED, $outcome);
        $this->assertSame([$fileid], $enforcer->deleted);
        $this->assertFalse(get_file_storage()->get_file_by_id($fileid));
        $this->assertSame(
            enforcement_state::QUARANTINED,
            (new scan_repository())->get_by_id((int) $record->id)->enforcement
        );
        $this->assertDebuggingCalledCount(2);
    }

    /**
     * Report-only policy notifies and audits without removing the file.
     */
    public function test_report_policy_leaves_the_file_in_place(): void {
        $this->resetAfterTest();
        $file = $this->create_submission_file('keep.bin', self::MALICIOUS_CONTENT);
        $record = $this->malicious_record($file);

        $enforcer = new recording_enforcer(new scan_repository(), $this->config(scan_policy::REPORT));
        $outcome = $enforcer->enforce($record);

        $this->assertSame(enforcement_state::REPORTED, $outcome);
        $this->assertSame([], $enforcer->quarantined);
        $this->assertSame([], $enforcer->deleted);
        $this->assertCount(1, $enforcer->events);
        $this->assertCount(1, $enforcer->notifications);
        $this->assertInstanceOf(\stored_file::class, get_file_storage()->get_file_by_id((int) $file->get_id()));
    }

    /**
     * Without Moodle quarantine there is no recoverable copy, so nothing is deleted.
     */
    public function test_disabled_core_quarantine_never_deletes(): void {
        $this->resetAfterTest();
        $file = $this->create_submission_file('norecovery.bin', self::MALICIOUS_CONTENT);
        $record = $this->malicious_record($file);

        $enforcer = new recording_enforcer(new scan_repository(), $this->config());
        $enforcer->quarantineenabled = false;
        $outcome = $enforcer->enforce($record);

        $this->assertSame(enforcement_state::QUARANTINEOFF, $outcome);
        $this->assertSame([], $enforcer->deleted);
        $this->assertInstanceOf(\stored_file::class, get_file_storage()->get_file_by_id((int) $file->get_id()));
        $this->assertCount(1, $enforcer->notifications);
    }

    /**
     * A plugin-owned copy is captured, but no Moodle file is claimed or deleted.
     */
    public function test_plugin_copy_is_quarantined_without_claiming_a_moodle_file(): void {
        $this->resetAfterTest();
        $copy = get_file_storage()->create_file_from_string([
            'contextid' => \context_system::instance()->id,
            'component' => plugin_file_lifecycle::COMPONENT,
            'filearea' => plugin_file_lifecycle::GATE_FILEAREA,
            'itemid' => 7,
            'filepath' => '/',
            'filename' => 'upload.bin',
        ], self::MALICIOUS_CONTENT);
        $record = $this->malicious_record($copy);

        $enforcer = new recording_enforcer(new scan_repository(), $this->config());
        $outcome = $enforcer->enforce($record);

        $this->assertSame(enforcement_state::QUARANTINEDCOPY, $outcome);
        $this->assertCount(1, $enforcer->quarantined);
        $this->assertSame(self::MALICIOUS_CONTENT, $enforcer->quarantined[0]['content']);
        $this->assertSame([], $enforcer->deleted);
        $this->assertCount(1, $enforcer->notifications);
    }

    /**
     * A native-gate copy can still reach the Moodle file that landed after the scan.
     */
    public function test_gate_copy_removes_matching_permanent_file(): void {
        $this->resetAfterTest();
        $copy = get_file_storage()->create_file_from_string([
            'contextid' => \context_system::instance()->id,
            'component' => plugin_file_lifecycle::COMPONENT,
            'filearea' => plugin_file_lifecycle::GATE_FILEAREA,
            'itemid' => 11,
            'filepath' => '/',
            'filename' => 'upload.bin',
        ], self::MALICIOUS_CONTENT);
        $live = $this->create_submission_file('upload.bin', self::MALICIOUS_CONTENT);
        $liveid = (int) $live->get_id();
        $unrelated = $this->create_submission_file('innocent.bin', 'a perfectly ordinary document');
        $unrelatedid = (int) $unrelated->get_id();
        $record = $this->malicious_record($copy);

        $enforcer = new recording_enforcer(new scan_repository(), $this->config());
        $outcome = $enforcer->enforce($record);

        $this->assertSame(enforcement_state::QUARANTINED, $outcome);
        $this->assertSame(self::MALICIOUS_CONTENT, $enforcer->quarantined[0]['content']);
        $this->assertSame([$liveid], $enforcer->deleted);
        $this->assertFalse(get_file_storage()->get_file_by_id($liveid));
        $this->assertInstanceOf(\stored_file::class, get_file_storage()->get_file_by_id((int) $copy->get_id()));
        $this->assertInstanceOf(\stored_file::class, get_file_storage()->get_file_by_id($unrelatedid));
    }

    /**
     * Only a malicious verdict triggers enforcement.
     *
     * @param string $status Stored scan status.
     * @param string $phase Stored scan phase.
     * @dataProvider non_malicious_provider
     */
    public function test_non_malicious_verdicts_never_enforce(string $status, string $phase): void {
        $this->resetAfterTest();
        $file = $this->create_submission_file('ordinary.bin', 'ordinary content');
        $record = $this->malicious_record($file);
        $record->status = $status;
        $record->phase = $phase;
        (new scan_repository())->update($record);

        $enforcer = new recording_enforcer(new scan_repository(), $this->config());
        $outcome = $enforcer->enforce($record);

        $this->assertSame(enforcement_state::NONE, $outcome);
        $this->assertSame([], $enforcer->quarantined);
        $this->assertSame([], $enforcer->deleted);
        $this->assertSame([], $enforcer->events);
        $this->assertSame([], $enforcer->notifications);
        $this->assertInstanceOf(\stored_file::class, get_file_storage()->get_file_by_id((int) $file->get_id()));
        $this->assertSame(
            enforcement_state::NONE,
            (new scan_repository())->get_by_id((int) $record->id)->enforcement
        );
    }

    /**
     * Statuses that must never reach the malicious enforcement path.
     *
     * @return array<string,array{0:string,1:string}>
     */
    public static function non_malicious_provider(): array {
        return [
            'clean' => [scan_status::CLEAN, scan_phase::COMPLETED],
            'suspicious' => [scan_status::SUSPICIOUS, scan_phase::COMPLETED],
            'error' => [scan_status::ERROR, scan_phase::FAILED],
            'notscanned' => [scan_status::NOTSCANNED, scan_phase::SKIPPED],
            'pending' => [scan_status::PENDING, scan_phase::POLLING],
        ];
    }

    /**
     * A clean verdict through the full engine leaves the file untouched.
     */
    public function test_clean_verdict_through_the_engine_does_not_enforce(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->lookupresult = new file_lookup_result(
            true,
            str_repeat('c', 64),
            ['malicious' => 0, 'suspicious' => 0, 'undetected' => 60, 'harmless' => 10]
        );
        $enforcer = new recording_enforcer(new scan_repository(), $this->config());
        $service = $this->make_service($provider, $enforcer);

        $file = $this->create_submission_file('safe.pdf', 'a perfectly ordinary document');
        $scan = $service->queue_file_scan($file, scan_source::ASSIGN, 0);

        $this->assertSame(scan_status::CLEAN, $scan->status);
        $this->assertSame([], $enforcer->quarantined);
        $this->assertSame([], $enforcer->deleted);
        $this->assertInstanceOf(\stored_file::class, get_file_storage()->get_file_by_id((int) $file->get_id()));
    }

    /**
     * A suspicious analysis is not treated as a malicious cleanup.
     */
    public function test_suspicious_verdict_through_the_engine_does_not_enforce(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $provider->analysisresult = new analysis_result('analysis-s', 'completed', [
            'malicious' => 0,
            'suspicious' => 6,
            'undetected' => 50,
            'harmless' => 4,
            'timeout' => 0,
        ]);
        $enforcer = new recording_enforcer(new scan_repository(), $this->config());
        $service = $this->make_service($provider, $enforcer);

        $file = $this->create_submission_file('maybe.bin', 'not confirmed malware');
        $scan = $service->queue_file_scan($file, scan_source::ASSIGN, 0);
        $service->process_scan((int) $scan->id);

        $stored = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame(scan_status::SUSPICIOUS, $stored->status);
        $this->assertSame(enforcement_state::NONE, $stored->enforcement);
        $this->assertSame([], $enforcer->quarantined);
        $this->assertSame([], $enforcer->deleted);
        $this->assertInstanceOf(\stored_file::class, get_file_storage()->get_file_by_id((int) $file->get_id()));
    }

    /**
     * Build a completed malicious scan row for an existing Moodle file.
     *
     * @param \stored_file $file Scanned file.
     * @return \stdClass Persisted scan record.
     */
    private function malicious_record(\stored_file $file): \stdClass {
        $now = time();
        $record = (object) [
            'fileid' => $file->get_id(),
            'contenthash' => $file->get_contenthash(),
            'pathnamehash' => $file->get_pathnamehash(),
            'contextid' => $file->get_contextid(),
            'courseid' => 0,
            'component' => $file->get_component(),
            'filearea' => $file->get_filearea(),
            'itemid' => $file->get_itemid(),
            'filepath' => $file->get_filepath(),
            'filename' => $file->get_filename(),
            'userid' => 0,
            'source' => scan_source::ASSIGN,
            'sha256' => (new file_hasher())->hash_stored_file($file),
            'filesize' => $file->get_filesize(),
            'mimetype' => $file->get_mimetype(),
            'status' => scan_status::MALICIOUS,
            'phase' => scan_phase::COMPLETED,
            'vtanalysisid' => 'analysis-phpunit',
            'vtfileid' => null,
            'malicious' => 44,
            'suspicious' => 2,
            'undetected' => 20,
            'harmless' => 0,
            'timeout' => 0,
            'totalengines' => 66,
            'errorcode' => null,
            'enforcement' => enforcement_state::NONE,
            'pollattempts' => 1,
            'timelastpoll' => $now,
            'timesubmitted' => $now,
            'timecreated' => $now,
            'timemodified' => $now,
            'timecompleted' => $now,
        ];
        $record->id = (new scan_repository())->insert($record);
        return $record;
    }

    /**
     * Operational settings with a chosen enforcement policy.
     *
     * @param string $policy Enforcement policy.
     * @return plugin_config
     */
    private function config(string $policy = scan_policy::QUARANTINE): plugin_config {
        return new plugin_config(
            true,
            1048576,
            false,
            scan_policy::ALLOW,
            scan_policy::ALLOW,
            scan_policy::BLOCK,
            $policy
        );
    }

    /**
     * Scan engine wired to a recording enforcer.
     *
     * @param fake_provider $provider Fake provider.
     * @param recording_enforcer $enforcer Recording enforcer.
     * @return scan_service
     */
    private function make_service(fake_provider $provider, recording_enforcer $enforcer): scan_service {
        return new scan_service(
            $provider,
            new scan_repository(),
            new file_hasher(),
            $this->config(),
            new recording_scheduler(),
            null,
            $enforcer
        );
    }

    /**
     * A learner submission file in a real course context.
     *
     * @param string $filename Filename.
     * @param string $content File content.
     * @return \stored_file
     */
    private function create_submission_file(string $filename, string $content): \stored_file {
        $course = $this->getDataGenerator()->create_course();
        return get_file_storage()->create_file_from_string([
            'contextid' => \context_course::instance($course->id)->id,
            'component' => 'assignsubmission_file',
            'filearea' => 'submission_files',
            'itemid' => random_int(1, 100000000),
            'filepath' => '/',
            'filename' => $filename,
        ], $content);
    }
}
