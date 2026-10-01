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
 * Tests for assignment submission automatic scanning.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\assignment_scanner;
use antivirus_verdict\local\file_hasher;
use antivirus_verdict\local\plugin_config;
use antivirus_verdict\local\scan_context_resolver;
use antivirus_verdict\local\scan_repository;
use antivirus_verdict\local\scan_service;
use antivirus_verdict\provider\file_lookup_result;
use antivirus_verdict\tests\environment_debugging_trait;
use antivirus_verdict\tests\fake_provider;
use antivirus_verdict\tests\recording_scheduler;
use antivirus_verdict\tests\throwing_scan_service;


defined('MOODLE_INTERNAL') || die();

global $CFG;
require_once($CFG->dirroot . '/mod/assign/locallib.php');
require_once($CFG->dirroot . '/mod/assign/submission/file/locallib.php');

/**
 * Assignment event consumer against the existing scan engine.
 *
 * @covers \antivirus_verdict\local\assignment_scanner
 * @covers \antivirus_verdict\observer
 */
final class assignment_scanner_test extends \advanced_testcase {
    use environment_debugging_trait;

    /**
     * Observer registration targets the Moodle 5.2 assessable_submitted event.
     */
    public function test_events_php_observes_assessable_submitted(): void {
        global $CFG;
        $observers = [];
        include($CFG->dirroot . '/lib/antivirus/verdict/db/events.php');
        $assign = null;
        foreach ($observers as $observer) {
            if ($observer['eventname'] === '\mod_assign\event\assessable_submitted') {
                $assign = $observer;
                break;
            }
        }
        $this->assertNotNull($assign);
        $this->assertSame('\antivirus_verdict\observer::assessable_submitted', $assign['callback']);
    }

    /**
     * Activity title on scan detail resolution matches Moodle cm name exactly.
     */
    public function test_activity_name_resolves_from_moodle_modinfo(): void {
        $this->resetAfterTest();
        $activityname = 'Task 2 — API Authentication Testing';
        $course = $this->getDataGenerator()->create_course();
        $student = $this->getDataGenerator()->create_and_enrol($course, 'student');
        $generator = $this->getDataGenerator()->get_plugin_generator('mod_assign');
        $instance = $generator->create_instance([
            'course' => $course->id,
            'name' => $activityname,
            'assignsubmission_file_enabled' => 1,
            'assignsubmission_file_maxfiles' => 12,
            'assignsubmission_file_maxsizebytes' => 1024 * 1024,
            'assignsubmission_onlinetext_enabled' => 0,
        ]);
        $cm = get_coursemodule_from_instance('assign', $instance->id);
        $context = \context_module::instance($cm->id);
        $this->setUser($student);
        $submission = (new \assign($context, $cm, $course))->get_user_submission($student->id, true);
        $fs = get_file_storage();
        $fs->create_file_from_string([
            'contextid' => $context->id,
            'component' => assignment_scanner::FILE_COMPONENT,
            'filearea' => assignment_scanner::FILE_AREA,
            'itemid' => $submission->id,
            'filepath' => '/',
            'filename' => 'report.pdf',
        ], 'pdf-bytes');
        $this->mark_submitted($submission);

        $provider = new fake_provider();
        $scanner = $this->make_scanner($provider, new recording_scheduler());
        $assign = new \assign($context, $cm, $course);
        $event = \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false);
        $scans = $scanner->scan_from_event($event);
        $scan = reset($scans);

        $this->setAdminUser();
        $resolved = (new scan_context_resolver())->resolve($scan);
        $this->assertSame($activityname, $resolved->activity);
    }

    /**
     * File area constants match Moodle Assignment file submission.
     */
    public function test_file_area_matches_moodle_assign(): void {
        $this->assertSame(ASSIGNSUBMISSION_FILE_FILEAREA, assignment_scanner::FILE_AREA);
        $this->assertSame(ASSIGN_SUBMISSION_STATUS_SUBMITTED, assignment_scanner::SUBMISSION_STATUS_SUBMITTED);
    }

    /**
     * A submitted assignment file is queued with source assign and the learner id.
     */
    public function test_submitted_file_is_queued_asynchronously(): void {
        global $DB, $USER;

        $this->resetAfterTest();
        [$assign, $student, $submission] = $this->prepare_submission(['report.pdf' => 'report-bytes']);
        $provider = new fake_provider();
        $scheduler = new recording_scheduler();
        $scanner = $this->make_scanner($provider, $scheduler);

        $this->setAdminUser();
        $adminid = (int) $USER->id;
        $event = \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false);
        $scans = $scanner->scan_from_event($event);

        $this->assertCount(1, $scans);
        $scan = reset($scans);
        $this->assertSame(scan_source::ASSIGN, $scan->source);
        $this->assertSame((int) $student->id, (int) $scan->userid);
        $this->assertNotEquals($adminid, (int) $scan->userid);
        $this->assertSame(assignment_scanner::FILE_COMPONENT, $scan->component);
        $this->assertSame(assignment_scanner::FILE_AREA, $scan->filearea);
        $this->assertSame((int) $submission->id, (int) $scan->itemid);
        $this->assertSame((int) $submission->id, (int) $scan->submissionid);
        $this->assertSame(scan_phase::QUEUED, $scan->phase);
        $this->assertSame(scan_status::PENDING, $scan->status);
        $this->assertSame(0, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
        $this->assertSame(0, $provider->analysiscount);
        $this->assertSame([(int) $scan->id], $scheduler->queued);
        $this->assertSame(
            ASSIGN_SUBMISSION_STATUS_SUBMITTED,
            $DB->get_field('assign_submission', 'status', ['id' => $submission->id])
        );
        $this->assertFalse($assign->get_user_grade($student->id, false));
    }

    /**
     * Assignment automatic scanning stays queued and attributed after HTTP 429.
     */
    public function test_rate_limit_keeps_assignment_scan_pending(): void {
        $this->resetAfterTest();
        [$assign, $student, $submission] = $this->prepare_submission(['rl-assign.bin' => 'assign-rl']);
        $provider = new fake_provider();
        $provider->lookupexception = new \antivirus_verdict\provider\provider_exception(
            'error_ratelimit',
            '',
            429,
            45
        );
        $scheduler = new recording_scheduler();
        $scanner = $this->make_scanner($provider, $scheduler);
        $this->setAdminUser();
        $event = \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false);
        $scans = $scanner->scan_from_event($event);
        $this->assertCount(1, $scans);
        $scan = reset($scans);
        $scanid = (int) $scan->id;
        $this->assertSame(scan_source::ASSIGN, $scan->source);
        $this->assertSame((int) $student->id, (int) $scan->userid);
        $this->assertSame((int) $assign->get_course()->id, (int) $scan->courseid);
        $this->assertSame((int) $submission->id, (int) $scan->submissionid);
        $this->assertSame(scan_status::PENDING, $scan->status);

        $service = $this->make_service($provider, $scheduler);
        $this->assertTrue($service->process_scan($scanid));
        $updated = (new scan_repository())->get_by_id($scanid);
        $this->assertSame(scan_status::PENDING, $updated->status);
        $this->assertSame('error_ratelimit', $updated->errorcode);
        $this->assertSame((int) $student->id, (int) $updated->userid);
        $this->assertSame((int) $submission->id, (int) $updated->submissionid);
        $this->assertSame($scanid, (int) $updated->id);
        $this->assertNotEquals(scan_status::CLEAN, $updated->status);
        $this->assertNotEquals(scan_status::MALICIOUS, $updated->status);
        $this->assertSame(0, $provider->uploadcount);
    }

    /**
     * Moodle event dispatch queues scans when both settings are enabled.
     */
    public function test_event_trigger_queues_scan_without_virustotal(): void {
        global $CFG, $DB;

        $this->resetAfterTest();
        $CFG->antiviruses = 'verdict';
        set_config('apikey', 'phpunit-assign-event-key', 'antivirus_verdict');
        set_config('assignscan', 1, 'antivirus_verdict');
        [$assign, $student, $submission] = $this->prepare_submission(['event.bin' => 'event-bytes']);
        $this->setUser($student);
        $this->assertEquals(0, $DB->count_records('antivirus_verdict_scans'));

        \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false)->trigger();

        $records = $DB->get_records('antivirus_verdict_scans');
        $this->assertCount(1, $records);
        $scan = reset($records);
        $this->assertSame(scan_source::ASSIGN, $scan->source);
        $this->assertSame((int) $student->id, (int) $scan->userid);
        $this->assertSame(scan_phase::QUEUED, $scan->phase);
        $this->assertSame('', $scan->sha256);
    }

    /**
     * Assignment backfill still queues when native antivirus is not enabled.
     */
    public function test_assignment_backfill_runs_without_antivirus_enablement(): void {
        global $DB;

        $this->resetAfterTest();
        [$assign, $student, $submission] = $this->prepare_submission(['off.pdf' => 'x']);
        $provider = new fake_provider();
        $scanner = $this->make_scanner($provider, new recording_scheduler(), false, true);
        $this->setUser($student);
        $event = \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false);

        $scans = $scanner->scan_from_event($event);
        $this->assertCount(1, $scans);
        $this->assertEquals(1, $DB->count_records('antivirus_verdict_scans'));
        $this->assertSame(0, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
    }

    /**
     * Selected-areas scope does not replace the assignment checkbox.
     */
    public function test_selected_scope_still_respects_assignscan(): void {
        global $DB;

        $this->resetAfterTest();
        [$assign, $student, $submission] = $this->prepare_submission(['scope.pdf' => 'scope-bytes']);
        $provider = new fake_provider();
        $scheduler = new recording_scheduler();
        $off = new assignment_scanner(
            $this->make_service($provider, $scheduler),
            new plugin_config(
                enabled: true,
                maxbytes: 1048576,
                assignscan: false,
                scanscope: \antivirus_verdict\local\scan_scope::SELECTED_AREAS
            )
        );
        $this->setUser($student);
        $event = \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false);
        $this->assertSame([], $off->scan_from_event($event));
        $this->assertEquals(0, $DB->count_records('antivirus_verdict_scans'));

        $on = new assignment_scanner(
            $this->make_service($provider, $scheduler),
            new plugin_config(
                enabled: true,
                maxbytes: 1048576,
                assignscan: true,
                scanscope: \antivirus_verdict\local\scan_scope::SELECTED_AREAS
            )
        );
        $scans = $on->scan_from_event($event);
        $this->assertCount(1, $scans);
        $this->assertSame(scan_source::ASSIGN, reset($scans)->source);
        $this->assertSame(0, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
    }

    /**
     * Assignment auto-scan off does not create records even if scanning is enabled.
     */
    public function test_disabled_assignscan_does_not_scan(): void {
        global $DB;

        $this->resetAfterTest();
        [$assign, $student, $submission] = $this->prepare_submission(['skip.pdf' => 'x']);
        $provider = new fake_provider();
        $scanner = $this->make_scanner($provider, new recording_scheduler(), true, false);
        $this->setUser($student);
        $event = \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false);

        $this->assertSame([], $scanner->scan_from_event($event));
        $this->assertEquals(0, $DB->count_records('antivirus_verdict_scans'));
        $this->assertSame(0, $provider->lookupcount);
    }

    /**
     * Default site configuration does not auto-scan assignments.
     */
    public function test_defaults_do_not_auto_scan(): void {
        global $DB;

        $this->resetAfterTest();
        [$assign, $student, $submission] = $this->prepare_submission(['default.pdf' => 'x']);
        $this->setUser($student);
        $event = \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false);

        observer::assessable_submitted($event);
        $this->assertEquals(0, $DB->count_records('antivirus_verdict_scans'));
        $this->assertEquals(0, (int) get_config('antivirus_verdict', 'assignscan'));
    }

    /**
     * Multiple submission files become independent queued scans.
     */
    public function test_multiple_files_are_queued_independently(): void {
        $this->resetAfterTest();
        [$assign, $student, $submission] = $this->prepare_submission([
            'report.pdf' => 'pdf-bytes',
            'diagram.png' => "\x89PNG",
            'archive.zip' => "PK\x03\x04",
        ]);
        $provider = new fake_provider();
        $scheduler = new recording_scheduler();
        $scanner = $this->make_scanner($provider, $scheduler);
        $this->setUser($student);
        $event = \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false);

        $scans = $scanner->scan_from_event($event);
        $names = array_map(static fn($scan) => $scan->filename, $scans);
        sort($names);

        $this->assertCount(3, $scans);
        $this->assertSame(['archive.zip', 'diagram.png', 'report.pdf'], $names);
        $this->assertCount(3, array_unique(array_map(static fn($scan) => (int) $scan->id, $scans)));
        $this->assertCount(3, $scheduler->queued);
        $this->assertSame(0, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
    }

    /**
     * Directories in the file area are not queued.
     */
    public function test_directories_are_ignored(): void {
        $this->resetAfterTest();
        [$assign, $student, $submission] = $this->prepare_submission(['keep.txt' => 'keep']);
        $fs = get_file_storage();
        $fs->create_directory(
            $assign->get_context()->id,
            assignment_scanner::FILE_COMPONENT,
            assignment_scanner::FILE_AREA,
            $submission->id,
            '/nested/'
        );
        $provider = new fake_provider();
        $scanner = $this->make_scanner($provider, new recording_scheduler());
        $this->setUser($student);
        $event = \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false);

        $scans = $scanner->scan_from_event($event);
        $this->assertCount(1, $scans);
        $this->assertSame('keep.txt', $scans[0]->filename);
    }

    /**
     * Empty and binary submission files are still passed to the scan engine.
     */
    public function test_empty_and_binary_files_are_queued(): void {
        $this->resetAfterTest();
        [$assign, $student, $submission] = $this->prepare_submission([
            'empty.dat' => '',
            'binary.bin' => "\x00\x01\xff\xfe",
        ]);
        $scanner = $this->make_scanner(new fake_provider(), new recording_scheduler());
        $this->setUser($student);
        $event = \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false);

        $scans = $scanner->scan_from_event($event);
        $names = array_map(static fn($scan) => $scan->filename, $scans);
        sort($names);
        $this->assertSame(['binary.bin', 'empty.dat'], $names);
        foreach ($scans as $scan) {
            $this->assertSame(scan_phase::QUEUED, $scan->phase);
        }
    }

    /**
     * Assignment description files are not scanned.
     */
    public function test_intro_attachments_are_not_scanned(): void {
        $this->resetAfterTest();
        [$assign, $student, $submission] = $this->prepare_submission(['real.pdf' => 'real']);
        $fs = get_file_storage();
        $fs->create_file_from_string([
            'contextid' => $assign->get_context()->id,
            'component' => 'mod_assign',
            'filearea' => ASSIGN_INTROATTACHMENT_FILEAREA,
            'itemid' => 0,
            'filepath' => '/',
            'filename' => 'intro.pdf',
        ], 'intro-bytes');
        $scanner = $this->make_scanner(new fake_provider(), new recording_scheduler());
        $this->setUser($student);
        $event = \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false);

        $scans = $scanner->scan_from_event($event);
        $this->assertCount(1, $scans);
        $this->assertSame('real.pdf', $scans[0]->filename);
    }

    /**
     * Draft submissions are not scanned.
     */
    public function test_draft_submission_is_not_scanned(): void {
        global $DB;

        $this->resetAfterTest();
        $course = $this->getDataGenerator()->create_course();
        $student = $this->getDataGenerator()->create_and_enrol($course, 'student');
        $assign = $this->create_assign($course);
        $this->setUser($student);
        $submission = $assign->get_user_submission($student->id, true);
        $this->add_submission_file($assign, $submission, 'draft.pdf', 'draft');
        $this->assertNotEquals(ASSIGN_SUBMISSION_STATUS_SUBMITTED, $submission->status);
        $event = \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false);

        $scans = $this->make_scanner(new fake_provider(), new recording_scheduler())->scan_from_event($event);
        $this->assertSame([], $scans);
        $this->assertEquals(0, $DB->count_records('antivirus_verdict_scans'));
    }

    /**
     * Missing submissions do not fatal.
     */
    public function test_missing_submission_is_safe(): void {
        global $DB;

        $this->resetAfterTest();
        [$assign, $student, $submission] = $this->prepare_submission(['gone.pdf' => 'x']);
        $this->setUser($student);
        $event = \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false);
        $DB->delete_records('assign_submission', ['id' => $submission->id]);

        $scans = $this->make_scanner(new fake_provider(), new recording_scheduler())->scan_from_event($event);
        $this->assertSame([], $scans);
    }

    /**
     * Deleted files after queueing do not fatal in background processing.
     */
    public function test_deleted_file_after_queue_fails_safely(): void {
        $this->resetAfterTest();
        [$assign, $student, $submission] = $this->prepare_submission(['later.pdf' => 'later']);
        $provider = new fake_provider();
        $service = $this->make_service($provider, new recording_scheduler());
        $scanner = new assignment_scanner($service, new plugin_config(true, 1048576, true));
        $this->setUser($student);
        $event = \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false);
        $scans = $scanner->scan_from_event($event);
        $this->assertCount(1, $scans);

        $fs = get_file_storage();
        $file = $fs->get_file_by_id((int) $scans[0]->fileid);
        $this->assertNotFalse($file);
        $file->delete();

        $this->assertFalse($service->process_scan((int) $scans[0]->id));
        $updated = (new scan_repository())->get_by_id((int) $scans[0]->id);
        $this->assertSame(scan_status::ERROR, $updated->status);
        $this->assertSame('error_invalidfile', $updated->errorcode);
        $this->assertSame(0, $provider->lookupcount);
    }

    /**
     * Provider failure while queueing a file does not throw out of the scanner.
     */
    public function test_enqueue_failure_does_not_break_assignment(): void {
        $this->resetAfterTest();
        [$assign, $student, $submission] = $this->prepare_submission(['fail.pdf' => 'x']);
        $provider = new fake_provider();
        $broken = new throwing_scan_service(
            $provider,
            new scan_repository(),
            new file_hasher(),
            new plugin_config(true, 1048576, true),
            new recording_scheduler()
        );
        $scanner = new assignment_scanner($broken, new plugin_config(true, 1048576, true));
        $this->setUser($student);
        $event = \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false);

        $this->resetDebugging();
        $this->assertSame([], $scanner->scan_from_event($event));
        $this->assertDebuggingCalled(
            'antivirus_verdict assignment file scan failed: The VirusTotal API could not be reached. Try again later.',
            DEBUG_DEVELOPER
        );
        $this->assertSame(0, $provider->lookupcount);
        observer::assessable_submitted($event);
        $this->assertDebuggingNotCalled();
        $this->assertSame(ASSIGN_SUBMISSION_STATUS_SUBMITTED, $submission->status);
    }

    /**
     * Duplicate events reuse the in-flight scan rather than creating another active row.
     */
    public function test_duplicate_event_reuses_active_scan(): void {
        global $DB;

        $this->resetAfterTest();
        [$assign, $student, $submission] = $this->prepare_submission(['once.pdf' => 'once']);
        $scheduler = new recording_scheduler();
        $scanner = $this->make_scanner(new fake_provider(), $scheduler);
        $this->setUser($student);
        $event = \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false);

        $first = $scanner->scan_from_event($event);
        $second = $scanner->scan_from_event($event);

        $this->assertCount(1, $first);
        $this->assertCount(1, $second);
        $this->assertEquals($first[0]->id, $second[0]->id);
        $this->assertEquals(1, $DB->count_records('antivirus_verdict_scans'));
        $this->assertCount(1, $scheduler->queued);
    }

    /**
     * Updated submissions queue new files and reuse unchanged in-flight scans.
     */
    public function test_updated_submission_scans_new_files_and_reuses_unchanged(): void {
        $this->resetAfterTest();
        [$assign, $student, $submission] = $this->prepare_submission(['keep.pdf' => 'keep-bytes']);
        $scheduler = new recording_scheduler();
        $scanner = $this->make_scanner(new fake_provider(), $scheduler);
        $this->setUser($student);
        $event = \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false);
        $first = $scanner->scan_from_event($event);
        $this->assertCount(1, $first);

        $this->add_submission_file($assign, $submission, 'extra.png', 'extra-bytes');
        $second = $scanner->scan_from_event($event);

        $this->assertCount(2, $second);
        $ids = array_map(static fn($scan) => (int) $scan->id, $second);
        $this->assertContains((int) $first[0]->id, $ids);
        $names = array_map(static fn($scan) => $scan->filename, $second);
        sort($names);
        $this->assertSame(['extra.png', 'keep.pdf'], $names);
        $this->assertCount(2, $scheduler->queued);
    }

    /**
     * Completed historical scans remain; a later event can create a new row for the same file.
     */
    public function test_completed_scan_is_not_deleted_on_resubmit(): void {
        global $DB;

        $this->resetAfterTest();
        [$assign, $student, $submission] = $this->prepare_submission(['keep.pdf' => 'keep-bytes']);
        $provider = new fake_provider();
        $provider->lookupresult = new file_lookup_result(
            true,
            str_repeat('a', 64),
            ['malicious' => 0, 'suspicious' => 0, 'undetected' => 40, 'harmless' => 10, 'timeout' => 0]
        );
        $service = $this->make_service($provider, new recording_scheduler());
        $scanner = new assignment_scanner($service, new plugin_config(true, 1048576, true));
        $this->setUser($student);
        $event = \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false);
        $first = $scanner->scan_from_event($event);
        $this->assertFalse($service->process_scan((int) $first[0]->id));
        $completed = (new scan_repository())->get_by_id((int) $first[0]->id);
        $this->assertSame(scan_phase::COMPLETED, $completed->phase);

        $second = $scanner->scan_from_event($event);
        $this->assertCount(1, $second);
        $this->assertNotEquals($first[0]->id, $second[0]->id);
        $this->assertEquals(2, $DB->count_records('antivirus_verdict_scans'));
        $this->assertSame(
            scan_phase::COMPLETED,
            (new scan_repository())->get_by_id((int) $first[0]->id)->phase
        );
        $this->assertSame(scan_phase::QUEUED, $second[0]->phase);
        $this->assertSame(1, $provider->lookupcount);
    }

    /**
     * Size limits are applied by the scan engine, not the assignment adapter.
     */
    public function test_oversized_file_is_queued_then_skipped_by_engine(): void {
        $this->resetAfterTest();
        [$assign, $student, $submission] = $this->prepare_submission(['big.bin' => '12345']);
        $provider = new fake_provider();
        $service = $this->make_service($provider, new recording_scheduler(), 4);
        $scanner = new assignment_scanner($service, new plugin_config(true, 4, true));
        $this->setUser($student);
        $event = \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false);
        $scans = $scanner->scan_from_event($event);
        $this->assertCount(1, $scans);
        $this->assertSame(scan_phase::QUEUED, $scans[0]->phase);
        $this->assertSame(0, $provider->lookupcount);

        $this->assertFalse($service->process_scan((int) $scans[0]->id));
        $updated = (new scan_repository())->get_by_id((int) $scans[0]->id);
        $this->assertSame(scan_status::NOTSCANNED, $updated->status);
        $this->assertSame('error_filetoolarge', $updated->errorcode);
        $this->assertSame(0, $provider->uploadcount);
    }

    /**
     * Assignment classes do not contain VirusTotal client or request handling.
     */
    public function test_assignment_integration_does_not_call_virustotal_directly(): void {
        global $CFG;

        $scanner = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/classes/local/assignment_scanner.php');
        $observer = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/classes/observer.php');
        $events = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/db/events.php');
        foreach ([$scanner, $observer, $events] as $source) {
            $this->assertStringNotContainsString('virustotal\\client', $source);
            $this->assertStringNotContainsString('curl_', $source);
            $this->assertStringNotContainsString('$_GET', $source);
            $this->assertStringNotContainsString('$_POST', $source);
            $this->assertStringNotContainsString('$_REQUEST', $source);
            $this->assertStringNotContainsString('lookup_file_hash', $source);
            $this->assertStringNotContainsString('upload_file', $source);
            $this->assertStringNotContainsString('get_analysis', $source);
        }
    }

    /**
     * Build an assignment scanner with injected doubles.
     *
     * @param fake_provider $provider Fake provider.
     * @param recording_scheduler $scheduler Fake scheduler.
     * @param bool $enabled Master scanning switch.
     * @param bool $assignscan Assignment auto-scan switch.
     * @return assignment_scanner
     */
    private function make_scanner(
        fake_provider $provider,
        recording_scheduler $scheduler,
        bool $enabled = true,
        bool $assignscan = true
    ): assignment_scanner {
        return new assignment_scanner(
            $this->make_service($provider, $scheduler),
            new plugin_config($enabled, 1048576, $assignscan)
        );
    }

    /**
     * Build a scan service with injected doubles.
     *
     * @param fake_provider $provider Fake provider.
     * @param recording_scheduler $scheduler Fake scheduler.
     * @param int $maxbytes Size limit.
     * @return scan_service
     */
    private function make_service(
        fake_provider $provider,
        recording_scheduler $scheduler,
        int $maxbytes = 1048576
    ): scan_service {
        return new scan_service(
            $provider,
            new scan_repository(),
            new file_hasher(),
            new plugin_config(true, $maxbytes, true),
            $scheduler
        );
    }

    /**
     * Create an assignment, student, submitted files, and submitted status.
     *
     * @param array $files Filename => content.
     * @return array Assignment, student, submission.
     */
    private function prepare_submission(array $files): array {
        $course = $this->getDataGenerator()->create_course();
        $student = $this->getDataGenerator()->create_and_enrol($course, 'student');
        $assign = $this->create_assign($course);
        $this->setUser($student);
        $submission = $assign->get_user_submission($student->id, true);
        foreach ($files as $filename => $content) {
            $this->add_submission_file($assign, $submission, $filename, $content);
        }
        $this->mark_submitted($submission);
        return [$assign, $student, $submission];
    }

    /**
     * Create an assignment with file submissions enabled.
     *
     * @param \stdClass $course Course.
     * @return \assign
     */
    private function create_assign(\stdClass $course): \assign {
        $generator = $this->getDataGenerator()->get_plugin_generator('mod_assign');
        $instance = $generator->create_instance([
            'course' => $course->id,
            'assignsubmission_file_enabled' => 1,
            'assignsubmission_file_maxfiles' => 12,
            'assignsubmission_file_maxsizebytes' => 1024 * 1024,
            'assignsubmission_onlinetext_enabled' => 0,
            'submissiondrafts' => 0,
        ]);
        $cm = get_coursemodule_from_instance('assign', $instance->id);
        $context = \context_module::instance($cm->id);
        return new \assign($context, $cm, $course);
    }

    /**
     * Store a learner file in the assignment submission file area.
     *
     * @param \assign $assign Assignment.
     * @param \stdClass $submission Submission record.
     * @param string $filename File name.
     * @param string $content Bytes.
     * @return \stored_file
     */
    private function add_submission_file(
        \assign $assign,
        \stdClass $submission,
        string $filename,
        string $content
    ): \stored_file {
        $fs = get_file_storage();
        return $fs->create_file_from_string([
            'contextid' => $assign->get_context()->id,
            'component' => assignment_scanner::FILE_COMPONENT,
            'filearea' => assignment_scanner::FILE_AREA,
            'itemid' => $submission->id,
            'filepath' => '/',
            'filename' => $filename,
        ], $content);
    }

    /**
     * Persist submitted status on the assignment submission row.
     *
     * @param \stdClass $submission Submission record.
     */
    private function mark_submitted(\stdClass $submission): void {
        global $DB;
        $submission->status = ASSIGN_SUBMISSION_STATUS_SUBMITTED;
        $DB->set_field('assign_submission', 'status', ASSIGN_SUBMISSION_STATUS_SUBMITTED, ['id' => $submission->id]);
    }
}
