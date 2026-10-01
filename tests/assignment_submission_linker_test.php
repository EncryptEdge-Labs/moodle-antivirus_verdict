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
 * Gate scan ↔ assignment submission correlation tests.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\assignment_scanner;
use antivirus_verdict\local\assignment_submission_linker;
use antivirus_verdict\local\plugin_file_lifecycle;
use antivirus_verdict\local\scan_context_resolver;
use antivirus_verdict\local\scan_correlation;
use antivirus_verdict\local\scan_repository;
use antivirus_verdict\tests\environment_debugging_trait;


defined('MOODLE_INTERNAL') || die();

global $CFG;
require_once($CFG->dirroot . '/mod/assign/locallib.php');

/**
 * Gate scan to assignment submission correlation tests.
 *
 * @covers \antivirus_verdict\local\assignment_submission_linker
 * @covers \antivirus_verdict\local\scan_correlation
 */
final class assignment_submission_linker_test extends \advanced_testcase {
    use environment_debugging_trait;

    /**
     * Observer links gate scans even when assignscan backfill is disabled (staging default).
     */
    public function test_observer_links_gate_when_assignscan_off(): void {
        global $DB;

        $this->resetAfterTest();
        [$assign, $student, $submission, $file] = $this->prepare_with_gate('letter.pdf', 'pdf-bytes', false);
        $this->assertEquals(0, (int) get_config('antivirus_verdict', 'assignscan'));

        \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false)->trigger();

        $this->assertEquals(1, $DB->count_records('antivirus_verdict_scans'));
        $gate = $DB->get_record('antivirus_verdict_scans', [], '*', MUST_EXIST);
        $this->assertSame(scan_source::ANTIVIRUS, $gate->source);
        $this->assertSame((int) $submission->id, (int) $gate->submissionid);
        $this->assertSame($file->get_contenthash(), $gate->contenthash);
        $this->assertSame((int) $assign->get_course()->id, (int) $gate->courseid);
    }

    /**
     * Linked gate scan resolves course, activity, submission, and both file locations.
     */
    public function test_linked_gate_resolves_assignment_context(): void {
        $this->resetAfterTest();
        $activityname = '3. Letter task';
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
        $assign = new \assign(\context_module::instance($cm->id), $cm, $course);
        $this->setUser($student);
        $submission = $assign->get_user_submission($student->id, true);
        $file = get_file_storage()->create_file_from_string([
            'contextid' => $assign->get_context()->id,
            'component' => assignment_scanner::FILE_COMPONENT,
            'filearea' => assignment_scanner::FILE_AREA,
            'itemid' => $submission->id,
            'filepath' => '/',
            'filename' => '3. Letter of Recommendation.pdf',
        ], 'pdf-bytes');
        $this->mark_submitted($submission);
        $this->insert_gate_scan($file, (int) $student->id, time() - 60);

        $event = \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false);
        assignment_submission_linker::from_site_config()->link_from_event($event);

        $recent = (new scan_repository())->get_recent_scans(1);
        $gate = reset($recent);

        $this->setAdminUser();
        $ctx = (new scan_context_resolver())->resolve($gate);
        $this->assertSame($activityname, $ctx->activity);
        $this->assertTrue($ctx->showsubmission);
        $this->assertTrue($ctx->showsubmissionfilelocation);
        $this->assertStringContainsString('assignsubmission_file', $ctx->submissionfilelocation);
    }

    /**
     * Same contenthash in another student's submission must not link.
     */
    public function test_cross_user_gate_not_linked(): void {
        global $DB;

        $this->resetAfterTest();
        $course = $this->getDataGenerator()->create_course();
        $studenta = $this->getDataGenerator()->create_and_enrol($course, 'student');
        $studentb = $this->getDataGenerator()->create_and_enrol($course, 'student');
        $assignb = $this->create_assign($course);
        $this->setUser($studentb);
        $subb = $assignb->get_user_submission($studentb->id, true);
        $fileb = $this->add_file($assignb, $subb, 'shared.pdf', 'same-bytes');
        $this->mark_submitted($subb);

        $gateid = $this->insert_gate_scan($fileb, (int) $studenta->id, time() - 30);

        $event = \mod_assign\event\assessable_submitted::create_from_submission($assignb, $subb, false);
        assignment_submission_linker::from_site_config()->link_from_event($event);

        $gate = $DB->get_record('antivirus_verdict_scans', ['id' => $gateid], '*', MUST_EXIST);
        $this->assertSame(0, (int) $gate->submissionid);
    }

    /**
     * Replaced submission file after gate scan must not link (contenthash mismatch).
     */
    public function test_replaced_file_not_linked(): void {
        global $DB;

        $this->resetAfterTest();
        [$assign, $student, $submission] = $this->prepare_assign_only(['old.pdf' => 'old-bytes']);
        $fs = get_file_storage();
        $oldfile = $this->add_file($assign, $submission, 'old.pdf', 'old-bytes');
        $gateid = $this->insert_gate_scan($oldfile, (int) $student->id, time() - 20);

        $oldfile->delete();
        $this->add_file($assign, $submission, 'old.pdf', 'new-bytes');
        $this->mark_submitted($submission);

        $event = \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false);
        assignment_submission_linker::from_site_config()->link_from_event($event);

        $gate = $DB->get_record('antivirus_verdict_scans', ['id' => $gateid], '*', MUST_EXIST);
        $this->assertSame(0, (int) $gate->submissionid);
    }

    /**
     * Same user, same filename/content on two assignments links each gate to its own submission.
     */
    public function test_same_user_two_assignments_do_not_cross_link(): void {
        global $DB;

        $this->resetAfterTest();
        set_config('assignscan', 0, 'antivirus_verdict');
        $course = $this->getDataGenerator()->create_course();
        $student = $this->getDataGenerator()->create_and_enrol($course, 'student');
        $assignx = $this->create_assign($course, 'Assignment X');
        $assigny = $this->create_assign($course, 'Assignment Y');
        $this->setUser($student);

        $subx = $assignx->get_user_submission($student->id, true);
        $filex = $this->add_file($assignx, $subx, 'report.pdf', 'content-a');
        $gatex = $this->insert_gate_scan($filex, (int) $student->id, (int) $filex->get_timecreated() - 3);
        $this->mark_submitted($subx);
        assignment_submission_linker::from_site_config()->link_from_event(
            \mod_assign\event\assessable_submitted::create_from_submission($assignx, $subx, false)
        );

        sleep(1);
        $suby = $assigny->get_user_submission($student->id, true);
        $filey = $this->add_file($assigny, $suby, 'report.pdf', 'content-a');
        $gatey = $this->insert_gate_scan($filey, (int) $student->id, (int) $filey->get_timecreated() - 3);
        $this->mark_submitted($suby);
        assignment_submission_linker::from_site_config()->link_from_event(
            \mod_assign\event\assessable_submitted::create_from_submission($assigny, $suby, false)
        );

        $gatexrow = $DB->get_record('antivirus_verdict_scans', ['id' => $gatex], '*', MUST_EXIST);
        $gateyrow = $DB->get_record('antivirus_verdict_scans', ['id' => $gatey], '*', MUST_EXIST);
        $this->assertSame((int) $subx->id, (int) $gatexrow->submissionid);
        $this->assertSame((int) $suby->id, (int) $gateyrow->submissionid);
        $this->assertSame((int) $assignx->get_context()->id, (int) $gatexrow->contextid);
        $this->assertSame((int) $assigny->get_context()->id, (int) $gateyrow->contextid);
    }

    /**
     * Multiple files in one submission each link to their own gate scan.
     */
    public function test_multiple_files_link_independently(): void {
        global $DB;

        $this->resetAfterTest();
        set_config('assignscan', 0, 'antivirus_verdict');
        $course = $this->getDataGenerator()->create_course();
        $student = $this->getDataGenerator()->create_and_enrol($course, 'student');
        $assign = $this->create_assign($course);
        $this->setUser($student);
        $submission = $assign->get_user_submission($student->id, true);
        $filea = $this->add_file($assign, $submission, 'report.pdf', 'aaa');
        $fileb = $this->add_file($assign, $submission, 'evidence.zip', 'bbb');
        $gatea = $this->insert_gate_scan($filea, (int) $student->id, (int) $filea->get_timecreated() - 2);
        $gateb = $this->insert_gate_scan($fileb, (int) $student->id, (int) $fileb->get_timecreated() - 2);
        $this->mark_submitted($submission);

        assignment_submission_linker::from_site_config()->link_from_event(
            \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false)
        );

        $rowa = $DB->get_record('antivirus_verdict_scans', ['id' => $gatea], '*', MUST_EXIST);
        $rowb = $DB->get_record('antivirus_verdict_scans', ['id' => $gateb], '*', MUST_EXIST);
        $this->assertSame((int) $submission->id, (int) $rowa->submissionid);
        $this->assertSame((int) $submission->id, (int) $rowb->submissionid);
        $this->assertSame('report.pdf', $rowa->filename);
        $this->assertSame('evidence.zip', $rowb->filename);
    }

    /**
     * Linked gate detail shows both upload session and submitter labels.
     */
    public function test_linked_gate_shows_upload_and_submitted_by(): void {
        $this->resetAfterTest();
        [$assign, $student, $submission, $file] = $this->prepare_with_gate('doc.pdf', 'bytes', false);
        observer::assessable_submitted(
            \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false)
        );
        $recent = (new scan_repository())->get_recent_scans(1);
        $gate = reset($recent);
        $this->setAdminUser();
        $ctx = (new scan_context_resolver())->resolve($gate);
        $this->assertTrue($ctx->showuploadsession);
        $this->assertTrue($ctx->showfileowner);
        $this->assertStringContainsString('Submitted', $ctx->fileownerlabel);
    }

    /**
     * A gate far older than the submission file must not link (stale correlation).
     */
    public function test_stale_gate_outside_file_age_window_not_linked(): void {
        global $DB;

        $this->resetAfterTest();
        [$assign, $student, $submission] = $this->prepare_assign_only([]);
        $file = $this->add_file($assign, $submission, 'stale.pdf', 'stale-bytes');
        $filetime = (int) $file->get_timecreated();
        $gateid = $this->insert_gate_scan(
            $file,
            (int) $student->id,
            $filetime - assignment_submission_linker::GATE_MAX_AGE_BEFORE_FILE_SECONDS - 3600
        );
        $this->mark_submitted($submission);

        assignment_submission_linker::from_site_config()->link_from_event(
            \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false)
        );

        $gate = $DB->get_record('antivirus_verdict_scans', ['id' => $gateid], '*', MUST_EXIST);
        $this->assertSame(0, (int) $gate->submissionid);
    }

    /**
     * Resubmission with a new upload links a second gate; the first gate stays on the first link only.
     */
    public function test_resubmission_links_new_gate_without_reusing_old(): void {
        global $DB;

        $this->resetAfterTest();
        set_config('assignscan', 0, 'antivirus_verdict');
        $course = $this->getDataGenerator()->create_course();
        $student = $this->getDataGenerator()->create_and_enrol($course, 'student');
        $assign = $this->create_assign($course, 'Assignment X');
        $this->setUser($student);
        $submission = $assign->get_user_submission($student->id, true);

        $file1 = $this->add_file($assign, $submission, 'report.pdf', 'content-a');
        $gate1 = $this->insert_gate_scan($file1, (int) $student->id, (int) $file1->get_timecreated() - 2);
        $this->mark_submitted($submission);
        $event1 = \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false);
        assignment_submission_linker::from_site_config()->link_from_event($event1);

        $file1->delete();
        $file2 = $this->add_file($assign, $submission, 'report.pdf', 'content-a');
        $gate2 = $this->insert_gate_scan($file2, (int) $student->id, (int) $file2->get_timecreated() - 2);
        $event2 = \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false);
        assignment_submission_linker::from_site_config()->link_from_event($event2);

        $row1 = $DB->get_record('antivirus_verdict_scans', ['id' => $gate1], '*', MUST_EXIST);
        $row2 = $DB->get_record('antivirus_verdict_scans', ['id' => $gate2], '*', MUST_EXIST);
        $this->assertSame((int) $submission->id, (int) $row1->submissionid);
        $this->assertSame((int) $submission->id, (int) $row2->submissionid);
        $this->assertNotEquals((int) $row1->id, (int) $row2->id);
    }

    /**
     * Linking assignment context must not replace gate File API identity used for enforcement.
     */
    public function test_link_preserves_gate_file_identity(): void {
        global $DB;

        $this->resetAfterTest();
        [$assign, $student, $submission, $file] = $this->prepare_with_gate('enforce.pdf', 'enforce-bytes', false);
        observer::assessable_submitted(
            \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false)
        );
        $gate = $DB->get_record('antivirus_verdict_scans', [], '*', MUST_EXIST);
        $this->assertSame(plugin_file_lifecycle::GATE_FILEAREA, $gate->filearea);
        $this->assertSame(plugin_file_lifecycle::COMPONENT, $gate->component);
        $this->assertSame((int) $assign->get_context()->id, (int) $gate->contextid);
        $this->assertSame((int) $submission->id, (int) $gate->submissionid);
    }

    /**
     * Staging shape: reopened submission with no assign file still links via draft evidence.
     */
    public function test_links_without_submission_file_using_draft_and_event(): void {
        global $DB;

        $this->resetAfterTest();
        set_config('assignscan', 0, 'antivirus_verdict');
        $activityname = 'Task 01 - Network Security Basics';
        $course = $this->getDataGenerator()->create_course();
        $student = $this->getDataGenerator()->create_and_enrol($course, 'student');
        $assign = $this->create_assign($course, $activityname);
        $this->setUser($student);
        $submission = $assign->get_user_submission($student->id, true);

        $usercontext = \context_user::instance($student->id);
        $draft = get_file_storage()->create_file_from_string([
            'contextid' => $usercontext->id,
            'component' => 'user',
            'filearea' => 'draft',
            'itemid' => 42,
            'filepath' => '/',
            'filename' => 'Task Report.pdf',
            'userid' => $student->id,
        ], 'task-report-bytes');
        $gateid = $this->insert_gate_scan($draft, (int) $student->id, (int) $draft->get_timecreated());
        $this->mark_submitted($submission);
        $DB->set_field('assign_submission', 'status', ASSIGN_SUBMISSION_STATUS_REOPENED, ['id' => $submission->id]);
        $submission->status = ASSIGN_SUBMISSION_STATUS_REOPENED;

        $event = \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false);
        assignment_submission_linker::from_site_config()->link_from_event($event);

        $gate = $DB->get_record('antivirus_verdict_scans', ['id' => $gateid], '*', MUST_EXIST);
        $this->assertSame(scan_source::ANTIVIRUS, $gate->source);
        $this->assertSame((int) $submission->id, (int) $gate->submissionid);
        $this->assertSame((int) $course->id, (int) $gate->courseid);
        $this->assertSame((int) $assign->get_context()->id, (int) $gate->contextid);
        $this->assertSame(plugin_file_lifecycle::GATE_FILEAREA, $gate->filearea);

        $this->setAdminUser();
        $ctx = (new scan_context_resolver())->resolve($gate);
        $this->assertSame($activityname, $ctx->activity);
        $this->assertTrue($ctx->showsubmission);
    }

    /**
     * Unique recent gate without File API evidence is not attributed (userid+time is not enough).
     */
    public function test_unique_gate_without_file_evidence_is_not_linked(): void {
        global $DB;

        $this->resetAfterTest();
        [$assign, $student, $submission] = $this->prepare_assign_only([]);
        $usercontext = \context_user::instance($student->id);
        $ghost = get_file_storage()->create_file_from_string([
            'contextid' => $usercontext->id,
            'component' => 'user',
            'filearea' => 'draft',
            'itemid' => 7,
            'filepath' => '/',
            'filename' => 'gone.pdf',
            'userid' => $student->id,
        ], 'gone-bytes');
        $gateid = $this->insert_gate_scan($ghost, (int) $student->id, time() - 10);
        $ghost->delete();
        $this->mark_submitted($submission);

        assignment_submission_linker::from_site_config()->link_from_event(
            \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false)
        );

        $gate = $DB->get_record('antivirus_verdict_scans', ['id' => $gateid], '*', MUST_EXIST);
        $this->assertSame(0, (int) $gate->submissionid);
    }

    /**
     * A leftover unique draft from earlier in a broad window is not attributed.
     */
    public function test_stale_unique_draft_outside_event_window_is_not_linked(): void {
        global $DB;

        $this->resetAfterTest();
        [$assign, $student, $submission] = $this->prepare_assign_only([]);
        $usercontext = \context_user::instance($student->id);
        $draft = get_file_storage()->create_file_from_string([
            'contextid' => $usercontext->id,
            'component' => 'user',
            'filearea' => 'draft',
            'itemid' => 11,
            'filepath' => '/',
            'filename' => 'old.pdf',
            'userid' => $student->id,
        ], 'old-bytes');
        $stale = time() - assignment_submission_linker::EVENT_ONLY_MAX_AGE_SECONDS - 60;
        $DB->set_field('files', 'timecreated', $stale, ['id' => $draft->get_id()]);
        $gateid = $this->insert_gate_scan($draft, (int) $student->id, $stale);
        $this->mark_submitted($submission);

        assignment_submission_linker::from_site_config()->link_from_event(
            \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false)
        );

        $gate = $DB->get_record('antivirus_verdict_scans', ['id' => $gateid], '*', MUST_EXIST);
        $this->assertSame(0, (int) $gate->submissionid);
    }

    /**
     * Two leftover drafts must not both be attributed to one submission.
     */
    public function test_two_drafts_do_not_attribute_both_gates_to_one_submission(): void {
        global $DB;

        $this->resetAfterTest();
        [$assign, $student, $submission] = $this->prepare_assign_only([]);
        $usercontext = \context_user::instance($student->id);
        $a = get_file_storage()->create_file_from_string([
            'contextid' => $usercontext->id,
            'component' => 'user',
            'filearea' => 'draft',
            'itemid' => 8,
            'filepath' => '/',
            'filename' => 'a.pdf',
            'userid' => $student->id,
        ], 'aaa');
        $b = get_file_storage()->create_file_from_string([
            'contextid' => $usercontext->id,
            'component' => 'user',
            'filearea' => 'draft',
            'itemid' => 9,
            'filepath' => '/',
            'filename' => 'b.pdf',
            'userid' => $student->id,
        ], 'bbb');
        $gatea = $this->insert_gate_scan($a, (int) $student->id, (int) $a->get_timecreated());
        $gateb = $this->insert_gate_scan($b, (int) $student->id, (int) $b->get_timecreated());
        $this->mark_submitted($submission);

        $this->resetDebugging();
        assignment_submission_linker::from_site_config()->link_from_event(
            \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false)
        );
        $this->assertDebuggingCalled(
            'antivirus_verdict assignment gate link skipped: multiple user drafts near event for user '
                . (int) $student->id,
            DEBUG_DEVELOPER
        );

        $this->assertSame(0, (int) $DB->get_field('antivirus_verdict_scans', 'submissionid', ['id' => $gatea]));
        $this->assertSame(0, (int) $DB->get_field('antivirus_verdict_scans', 'submissionid', ['id' => $gateb]));
    }

    /**
     * Two unlinked gates for the same user without file evidence stay unlinked.
     */
    public function test_ambiguous_gates_without_file_evidence_are_not_linked(): void {
        global $DB;

        $this->resetAfterTest();
        [$assign, $student, $submission] = $this->prepare_assign_only([]);
        $usercontext = \context_user::instance($student->id);
        $a = get_file_storage()->create_file_from_string([
            'contextid' => $usercontext->id,
            'component' => 'user',
            'filearea' => 'draft',
            'itemid' => 8,
            'filepath' => '/',
            'filename' => 'a.pdf',
        ], 'aaa');
        $b = get_file_storage()->create_file_from_string([
            'contextid' => $usercontext->id,
            'component' => 'user',
            'filearea' => 'draft',
            'itemid' => 9,
            'filepath' => '/',
            'filename' => 'b.pdf',
        ], 'bbb');
        $gatea = $this->insert_gate_scan($a, (int) $student->id, time() - 20);
        $gateb = $this->insert_gate_scan($b, (int) $student->id, time() - 10);
        $a->delete();
        $b->delete();
        $this->mark_submitted($submission);

        assignment_submission_linker::from_site_config()->link_from_event(
            \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false)
        );

        $this->assertSame(0, (int) $DB->get_field('antivirus_verdict_scans', 'submissionid', ['id' => $gatea]));
        $this->assertSame(0, (int) $DB->get_field('antivirus_verdict_scans', 'submissionid', ['id' => $gateb]));
    }

    /**
     * Assignment scanner enqueue failure does not prevent gate attribution.
     */
    public function test_linker_runs_after_assignment_scanner_enqueue_failure(): void {
        global $CFG, $DB;

        $this->resetAfterTest();
        $observer = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/classes/observer.php');
        $this->assertStringContainsString('assignment_scanner::from_site_config()->scan_from_event', $observer);
        $this->assertStringContainsString('assignment_submission_linker::from_site_config()->link_from_event', $observer);
        $scannerpos = strpos($observer, 'assignment_scanner::from_site_config()');
        $linkerpos = strpos($observer, 'assignment_submission_linker::from_site_config()');
        $this->assertNotFalse($scannerpos);
        $this->assertNotFalse($linkerpos);
        $this->assertGreaterThan($scannerpos, $linkerpos);
        $linkertry = strrpos(substr($observer, 0, $linkerpos), 'try {');
        $scannertry = strrpos(substr($observer, 0, $scannerpos), 'try {');
        $this->assertNotFalse($linkertry);
        $this->assertNotFalse($scannertry);
        $this->assertNotEquals($scannertry, $linkertry);

        [$assign, $student, $submission, $file] = $this->prepare_with_gate('obs.pdf', 'obs-bytes', true);
        $scanner = new assignment_scanner(
            new \antivirus_verdict\tests\throwing_scan_service(
                new \antivirus_verdict\tests\fake_provider(),
                new scan_repository(),
                new \antivirus_verdict\local\file_hasher(),
                new \antivirus_verdict\local\plugin_config(true, 1048576, true),
                new \antivirus_verdict\tests\recording_scheduler()
            ),
            new \antivirus_verdict\local\plugin_config(true, 1048576, true)
        );
        $event = \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false);
        $this->resetDebugging();
        $this->assertSame([], $scanner->scan_from_event($event));
        $this->assertDebuggingCalled(
            'antivirus_verdict assignment file scan failed: The VirusTotal API could not be reached. Try again later.',
            DEBUG_DEVELOPER
        );
        assignment_submission_linker::from_site_config()->link_from_event($event);

        $gate = $DB->get_record('antivirus_verdict_scans', ['source' => scan_source::ANTIVIRUS], '*', MUST_EXIST);
        $this->assertSame((int) $submission->id, (int) $gate->submissionid);
        $this->assertEquals(0, $DB->count_records('antivirus_verdict_scans', ['source' => scan_source::ASSIGN]));
    }

    /**
     * When assignscan is on, correlation exposes cross-links between gate and assign rows.
     */
    public function test_correlation_finds_assign_scan_when_both_exist(): void {
        global $DB;

        $this->resetAfterTest();
        set_config('assignscan', 1, 'antivirus_verdict');
        [$assign, $student, $submission, $file] = $this->prepare_with_gate('both.pdf', 'both-bytes', true);

        $event = \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false);
        observer::assessable_submitted($event);

        $this->assertEquals(2, $DB->count_records('antivirus_verdict_scans'));
        $gate = $DB->get_record('antivirus_verdict_scans', ['source' => scan_source::ANTIVIRUS], '*', MUST_EXIST);
        $assignscan = $DB->get_record('antivirus_verdict_scans', ['source' => scan_source::ASSIGN], '*', MUST_EXIST);
        $this->assertSame((int) $submission->id, (int) $gate->submissionid);

        $this->setAdminUser();
        $link = (new scan_correlation())->related_scan_link($gate);
        $this->assertNotNull($link);
        $this->assertSame((int) $assignscan->id, $link['id']);
        $this->assertStringContainsString('/lib/antivirus/verdict/view.php', $link['url']);
        $this->assertTrue($link['isassign']);
        $assignlink = (new scan_correlation())->related_scan_link($assignscan);
        $this->assertNotNull($assignlink);
        $this->assertSame((int) $gate->id, $assignlink['id']);
        $this->assertStringContainsString('/lib/antivirus/verdict/view.php', $assignlink['url']);
        $this->assertTrue($assignlink['isgate']);
        $html = $this->detail_renderer()->render(new \antivirus_verdict\output\scan_detail($assignscan));
        $this->assertStringNotContainsString('[[relatedgatescan]]', $html);
        $this->assertStringContainsString(get_string('relatedgatescan', 'antivirus_verdict'), $html);
    }

    /**
     * Plugin renderer for related-scan Mustache output.
     *
     * @return \renderer_base
     */
    private function detail_renderer(): \renderer_base {
        global $PAGE;
        $PAGE->set_url(new \moodle_url('/lib/antivirus/verdict/view.php'));
        $PAGE->set_context(\context_system::instance());
        return $PAGE->get_renderer('antivirus_verdict');
    }

    /**
     * Create a submitted assignment with a matching gate scan row.
     *
     * @param string $filename Filename.
     * @param string $content File bytes.
     * @param bool $assignscan Whether assignscan is enabled.
     * @return array{\assign,\stdClass,\stdClass,\stored_file}
     */
    private function prepare_with_gate(string $filename, string $content, bool $assignscan): array {
        global $DB;

        set_config('assignscan', $assignscan ? 1 : 0, 'antivirus_verdict');
        $course = $this->getDataGenerator()->create_course();
        $student = $this->getDataGenerator()->create_and_enrol($course, 'student');
        $assign = $this->create_assign($course);
        $this->setUser($student);
        $submission = $assign->get_user_submission($student->id, true);
        $file = $this->add_file($assign, $submission, $filename, $content);
        $this->mark_submitted($submission);
        $this->insert_gate_scan($file, (int) $student->id, (int) $file->get_timecreated() - 3);
        return [$assign, $student, $submission, $file];
    }

    /**
     * Create assignment and submission without files.
     *
     * @param array $files Filename => content (unused placeholder for symmetry).
     * @return array{\assign,\stdClass,\stdClass}
     */
    private function prepare_assign_only(array $files): array {
        $course = $this->getDataGenerator()->create_course();
        $student = $this->getDataGenerator()->create_and_enrol($course, 'student');
        $assign = $this->create_assign($course);
        $this->setUser($student);
        $submission = $assign->get_user_submission($student->id, true);
        return [$assign, $student, $submission];
    }

    /**
     * Create a file-submission assignment instance.
     *
     * @param \stdClass $course Course.
     * @param string $name Activity name.
     * @return \assign
     */
    private function create_assign(\stdClass $course, string $name = 'Test assign'): \assign {
        $generator = $this->getDataGenerator()->get_plugin_generator('mod_assign');
        $instance = $generator->create_instance([
            'course' => $course->id,
            'name' => $name,
            'assignsubmission_file_enabled' => 1,
            'assignsubmission_file_maxfiles' => 12,
            'assignsubmission_file_maxsizebytes' => 1024 * 1024,
            'assignsubmission_onlinetext_enabled' => 0,
        ]);
        $cm = get_coursemodule_from_instance('assign', $instance->id);
        return new \assign(\context_module::instance($cm->id), $cm, $course);
    }

    /**
     * Store one learner file in the submission file area.
     *
     * @param \assign $assign Assignment.
     * @param \stdClass $submission Submission.
     * @param string $filename Filename.
     * @param string $content Bytes.
     * @return \stored_file
     */
    private function add_file(\assign $assign, \stdClass $submission, string $filename, string $content): \stored_file {
        return get_file_storage()->create_file_from_string([
            'contextid' => $assign->get_context()->id,
            'component' => assignment_scanner::FILE_COMPONENT,
            'filearea' => assignment_scanner::FILE_AREA,
            'itemid' => $submission->id,
            'filepath' => '/',
            'filename' => $filename,
        ], $content);
    }

    /**
     * Insert a synthetic antivirus gate scan for tests.
     *
     * @param \stored_file $file Submission file used for contenthash.
     * @param int $userid Upload user.
     * @param int $timecreated Gate scan time.
     * @return int Gate scan id.
     */
    private function insert_gate_scan(\stored_file $file, int $userid, int $timecreated): int {
        $repo = new scan_repository();
        $sha256 = hash('sha256', $file->get_content());
        return $repo->insert((object) [
            'fileid' => 0,
            'contenthash' => $file->get_contenthash(),
            'pathnamehash' => '',
            'contextid' => (int) \context_system::instance()->id,
            'courseid' => 0,
            'component' => plugin_file_lifecycle::COMPONENT,
            'filearea' => plugin_file_lifecycle::GATE_FILEAREA,
            'itemid' => 0,
            'filepath' => '/',
            'filename' => $file->get_filename(),
            'userid' => $userid,
            'initiatedby' => 0,
            'submissionid' => 0,
            'source' => scan_source::ANTIVIRUS,
            'sha256' => $sha256,
            'filesize' => $file->get_filesize(),
            'status' => scan_status::CLEAN,
            'phase' => scan_phase::COMPLETED,
            'enforcement' => enforcement_state::NONE,
            'pollattempts' => 0,
            'timelastpoll' => 0,
            'timesubmitted' => $timecreated,
            'timecreated' => $timecreated,
            'timemodified' => $timecreated,
            'timecompleted' => $timecreated + 60,
            'parentscanid' => 0,
        ]);
    }

    /**
     * Mark assign_submission status as submitted.
     *
     * @param \stdClass $submission Submission row.
     */
    private function mark_submitted(\stdClass $submission): void {
        global $DB;
        $DB->set_field('assign_submission', 'status', ASSIGN_SUBMISSION_STATUS_SUBMITTED, ['id' => $submission->id]);
        $submission->status = ASSIGN_SUBMISSION_STATUS_SUBMITTED;
    }
}
