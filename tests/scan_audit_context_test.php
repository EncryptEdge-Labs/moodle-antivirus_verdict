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
 * Audit identities and Moodle-native scan context.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\antivirus_gate;
use antivirus_verdict\local\archive_extract_result;
use antivirus_verdict\local\archive_member_scanner;
use antivirus_verdict\local\assignment_scanner;
use antivirus_verdict\local\bulk_scan_service;
use antivirus_verdict\local\file_hasher;
use antivirus_verdict\local\manual_scan;
use antivirus_verdict\local\operation_reservation;
use antivirus_verdict\local\plugin_config;
use antivirus_verdict\local\rescan;
use antivirus_verdict\local\scan_context_resolver;
use antivirus_verdict\local\scan_repository;
use antivirus_verdict\local\scan_scope;
use antivirus_verdict\local\scan_service;
use antivirus_verdict\tests\fake_provider;
use antivirus_verdict\tests\recording_scheduler;
use antivirus_verdict\tests\test_credentials;

defined('MOODLE_INTERNAL') || die();

global $CFG;
require_once($CFG->dirroot . '/mod/assign/locallib.php');
require_once($CFG->dirroot . '/course/lib.php');

/**
 * Phase 6: initiator and content owner stay distinct, and display uses Moodle context.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @covers \antivirus_verdict\local\manual_scan
 * @covers \antivirus_verdict\local\assignment_scanner
 * @covers \antivirus_verdict\local\rescan
 * @covers \antivirus_verdict\local\scan_context_resolver
 * @covers \antivirus_verdict\local\archive_member_scanner
 */
final class scan_audit_context_test extends \advanced_testcase {
    /**
     * A manual scan records the user who requested it.
     */
    public function test_manual_scan_records_initiator(): void {
        $this->resetAfterTest();
        $admin = $this->getDataGenerator()->create_user(['firstname' => 'Ada', 'lastname' => 'Admin']);
        $context = \context_system::instance();
        $file = $this->stored_file('own.txt', 'own-bytes', (int) $admin->id);
        $scan = $this->manual()->queue_stored_file($file, $context, (int) $admin->id);

        $this->assertSame((int) $admin->id, (int) $scan->initiatedby);
        $this->setAdminUser();
        $ctx = (new scan_context_resolver())->resolve($scan);
        $this->assertTrue($ctx->showscannedby);
        $this->assertStringContainsString('Ada', $ctx->scannedby);
    }

    /**
     * The person who starts a manual scan is not written over the file owner.
     */
    public function test_manual_initiator_stays_distinct_from_file_owner(): void {
        $this->resetAfterTest();
        $admin = $this->getDataGenerator()->create_user(['firstname' => 'Ada', 'lastname' => 'Admin']);
        $student = $this->getDataGenerator()->create_user(['firstname' => 'Sam', 'lastname' => 'Student']);
        $file = $this->stored_file('owned.txt', 'student-bytes', (int) $student->id);
        $scan = $this->manual()->queue_stored_file($file, \context_system::instance(), (int) $admin->id);

        $this->assertSame((int) $admin->id, (int) $scan->initiatedby);
        $this->assertSame((int) $student->id, (int) $scan->userid);
        $this->assertNotSame((int) $scan->initiatedby, (int) $scan->userid);

        $this->setAdminUser();
        $ctx = (new scan_context_resolver())->resolve($scan);
        $this->assertStringContainsString('Ada', $ctx->scannedby);
        $this->assertTrue($ctx->showfileowner);
        $this->assertSame(get_string('contextuploadedby', 'antivirus_verdict'), $ctx->fileownerlabel);
        $this->assertStringContainsString('Sam', $ctx->fileowner);
        $this->assertFalse($ctx->showsubmission);
    }

    /**
     * Assignment scanning stores the Moodle submission user.
     */
    public function test_assignment_records_submission_user(): void {
        $this->resetAfterTest();
        [$course, $student, $submission, $scan] = $this->assignment_scan(false);

        $this->assertSame((int) $student->id, (int) $scan->userid);
        $this->assertSame((int) $submission->id, (int) $scan->submissionid);
        $this->assertSame((int) $course->id, (int) $scan->courseid);

        $this->setAdminUser();
        $ctx = (new scan_context_resolver())->resolve($scan);
        $this->assertSame(get_string('contextsubmittedby', 'antivirus_verdict'), $ctx->fileownerlabel);
        $this->assertStringContainsString('Sam', $ctx->fileowner);
    }

    /**
     * The assignment event actor is not stored as the submitter.
     */
    public function test_assignment_initiator_is_not_the_submitter(): void {
        $this->resetAfterTest();
        $admin = $this->getDataGenerator()->create_user(['firstname' => 'Ada', 'lastname' => 'Admin']);
        [, $student, , $scan] = $this->assignment_scan(true, $admin);

        $this->assertSame((int) $student->id, (int) $scan->userid);
        $this->assertSame((int) $admin->id, (int) $scan->initiatedby);
        $this->assertNotSame((int) $scan->userid, (int) $scan->initiatedby);

        $this->setAdminUser();
        $ctx = (new scan_context_resolver())->resolve($scan);
        $this->assertStringContainsString('Sam', $ctx->fileowner);
        $this->assertStringContainsString('Ada', $ctx->scannedby);
    }

    /**
     * Course name comes from the Moodle course id.
     */
    public function test_course_name_comes_from_moodle_course(): void {
        $this->resetAfterTest();
        [$course, , , $scan] = $this->assignment_scan(false);
        $this->setAdminUser();
        $ctx = (new scan_context_resolver())->resolve($scan);
        $this->assertTrue($ctx->showcourse);
        $this->assertSame($course->shortname, $ctx->course);
    }

    /**
     * Activity name comes from the course module, not the filename.
     */
    public function test_activity_name_comes_from_course_module(): void {
        $this->resetAfterTest();
        [, , , $scan] = $this->assignment_scan(false);
        $this->setAdminUser();
        $ctx = (new scan_context_resolver())->resolve($scan);
        $this->assertSame('Week 3 essay', $ctx->activity);
        $this->assertStringNotContainsString($scan->filename, $ctx->activity);
    }

    /**
     * Activity type comes from the Moodle module, not the scan source string.
     */
    public function test_activity_type_comes_from_moodle_module(): void {
        $this->resetAfterTest();
        [, , , $scan] = $this->assignment_scan(false);
        $this->setAdminUser();
        $ctx = (new scan_context_resolver())->resolve($scan);
        $this->assertSame(get_string('modulename', 'assign'), $ctx->activitytype);
        $this->assertNotSame((string) $scan->source, $ctx->activitytype);
    }

    /**
     * The stored submission id is the assign_submission id.
     */
    public function test_submission_id_is_the_assign_submission(): void {
        $this->resetAfterTest();
        [, , $submission, $scan] = $this->assignment_scan(false);
        $this->setAdminUser();
        $ctx = (new scan_context_resolver())->resolve($scan);
        $this->assertTrue($ctx->showsubmission);
        $this->assertSame(
            get_string('contextsubmissionid', 'antivirus_verdict', (int) $submission->id),
            $ctx->submission
        );
        $this->assertSame((int) $submission->id, (int) $scan->submissionid);
    }

    /**
     * A manual file scan does not present a submission id.
     */
    public function test_manual_scan_has_no_submission_id(): void {
        $this->resetAfterTest();
        $admin = $this->getDataGenerator()->create_user();
        $file = $this->stored_file('loose.txt', 'loose', (int) $admin->id);
        $scan = $this->manual()->queue_stored_file($file, \context_system::instance(), (int) $admin->id);
        $this->assertSame(0, (int) $scan->submissionid);
        $this->setAdminUser();
        $ctx = (new scan_context_resolver())->resolve($scan);
        $this->assertFalse($ctx->showsubmission);
    }

    /**
     * A rescan records the acting user and keeps the original content owner.
     */
    public function test_rescan_initiator_is_separate_from_content_owner(): void {
        $this->resetAfterTest();
        $student = $this->getDataGenerator()->create_user(['firstname' => 'Sam', 'lastname' => 'Student']);
        $file = $this->stored_file('again.txt', 'again-bytes', (int) $student->id);
        $repo = new scan_repository();
        $originalid = $repo->insert($this->completed_row($file, (int) $student->id, 0));
        $original = $repo->get_by_id($originalid);

        $this->setAdminUser();
        global $USER;
        $adminid = (int) $USER->id;
        $rescanned = (new rescan(
            $this->service(),
            new plugin_config(true, 1048576),
            $repo,
            new test_credentials('test-key')
        ))->queue($original, $adminid);

        $this->assertNotSame($originalid, (int) $rescanned->id);
        $this->assertSame((int) $student->id, (int) $rescanned->userid);
        $this->assertSame($adminid, (int) $rescanned->initiatedby);
        $this->assertSame((int) $student->id, (int) $repo->get_by_id($originalid)->userid);
        $this->assertSame(scan_status::CLEAN, $repo->get_by_id($originalid)->status);
    }

    /**
     * A bulk sweep keeps the file owner and the requesting administrator apart.
     */
    public function test_bulk_operator_is_not_the_file_owner(): void {
        $this->resetAfterTest();
        $course = $this->getDataGenerator()->create_course();
        $admin = $this->getDataGenerator()->create_user(['firstname' => 'Ada', 'lastname' => 'Admin']);
        $student = $this->getDataGenerator()->create_user(['firstname' => 'Sam', 'lastname' => 'Student']);
        $this->stored_file('notes.txt', 'notes', (int) $student->id, \context_course::instance($course->id)->id);

        $this->setUser($admin);
        (new bulk_scan_service(
            $this->service(),
            new scan_repository(),
            new plugin_config(true, 1048576)
        ))->process_batch((int) $course->id, (int) $admin->id, 0, false, scan_source::BULK);

        $rows = (new scan_repository())->get_recent_scans(20);
        $match = null;
        foreach ($rows as $row) {
            if ($row->filename === 'notes.txt') {
                $match = $row;
                break;
            }
        }
        $this->assertNotNull($match);
        $this->assertSame((int) $student->id, (int) $match->userid);
        $this->assertSame((int) $admin->id, (int) $match->initiatedby);
        $this->assertNotSame((int) $match->userid, (int) $match->initiatedby);
    }

    /**
     * History resolution still returns when the referenced user record is gone.
     */
    public function test_missing_user_does_not_break_history(): void {
        $this->resetAfterTest();
        $scan = (object) [
            'source' => scan_source::ASSIGN,
            'userid' => 987654321,
            'initiatedby' => 0,
            'submissionid' => 0,
            'courseid' => 0,
            'contextid' => \context_system::instance()->id,
            'component' => 'assignsubmission_file',
            'filearea' => 'submission_files',
            'itemid' => 0,
            'filename' => 'gone.pdf',
            'status' => scan_status::CLEAN,
        ];
        $this->setAdminUser();
        $ctx = (new scan_context_resolver())->resolve($scan);
        $this->assertSame(get_string('contextnotavailable', 'antivirus_verdict'), $ctx->fileowner);
        $this->assertSame(scan_status::CLEAN, $scan->status);
    }

    /**
     * History resolution still returns after the course and activity are deleted.
     */
    public function test_deleted_course_and_activity_do_not_break_history(): void {
        $this->resetAfterTest();
        [$course, , , $scan] = $this->assignment_scan(false);
        $cm = get_coursemodule_from_instance('assign', $this->assignid, $course->id);
        $this->setAdminUser();
        $before = (new scan_context_resolver())->resolve($scan);
        $this->assertSame('Week 3 essay', $before->activity);

        $this->delete_course_module_for_test($course, $cm);
        $afteractivity = (new scan_context_resolver())->resolve($scan);
        $unavailable = get_string('contextnotavailable', 'antivirus_verdict');
        $this->assertSame($unavailable, $afteractivity->activity);
        $this->assertSame($course->shortname, $afteractivity->course);

        ob_start();
        delete_course($course->id, false);
        ob_end_clean();
        $aftercourse = (new scan_context_resolver())->resolve($scan);
        $this->assertSame(get_string('contextnotavailable', 'antivirus_verdict'), $aftercourse->course);
        $this->assertSame(scan_status::PENDING, $scan->status);
    }

    /**
     * An archive member reuses the parent context and does not invent a user.
     */
    public function test_archive_child_reuses_parent_context(): void {
        $this->resetAfterTest();
        $course = $this->getDataGenerator()->create_course();
        $student = $this->getDataGenerator()->create_user();
        $admin = $this->getDataGenerator()->create_user();
        $modulecontext = \context_course::instance($course->id);
        $repo = new scan_repository();
        $parent = (object) $this->completed_row(
            $this->stored_file('bundle.zip', 'not-a-zip', (int) $student->id, $modulecontext->id),
            (int) $student->id,
            (int) $admin->id
        );
        $parent->source = scan_source::ASSIGN;
        $parent->courseid = (int) $course->id;
        $parent->contextid = $modulecontext->id;
        $parent->submissionid = 440;
        $parent->status = scan_status::PENDING;
        $parent->phase = scan_phase::QUEUED;
        $parent->id = $repo->insert($parent);

        $path = make_request_directory() . '/member.txt';
        file_put_contents($path, 'member-bytes');
        $extraction = new archive_extract_result(true, false, false, '', [[
            'abspath' => $path,
            'relpath' => 'member.txt',
            'size' => 12,
            'depth' => 1,
        ]]);
        $queued = (new archive_member_scanner($this->service()))->queue_members($repo->get_by_id($parent->id), $extraction);
        $this->assertSame(1, $queued);

        $children = $repo->find_children_by_parent($parent->id);
        $child = reset($children);
        $this->assertSame(scan_source::ARCHIVE, $child->source);
        $this->assertSame($parent->id, (int) $child->parentscanid);
        $this->assertSame((int) $student->id, (int) $child->userid);
        $this->assertSame((int) $admin->id, (int) $child->initiatedby);
        $this->assertSame(440, (int) $child->submissionid);
        $this->assertSame((int) $course->id, (int) $child->courseid);
        $this->assertSame($modulecontext->id, (int) $child->contextid);
        $this->assertNotSame((int) $child->userid, (int) $child->initiatedby);
        $this->assertSame(scan_status::PENDING, $repo->get_by_id($parent->id)->status);
    }

    /**
     * Selected-area unknown uploads still skip the provider and create no row.
     */
    public function test_selected_area_unknown_stays_outside_provider_path(): void {
        global $DB;

        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $gate = new antivirus_gate(
            $provider,
            new scan_repository(),
            new file_hasher(),
            new plugin_config(
                enabled: true,
                maxbytes: 1048576,
                scanscope: scan_scope::SELECTED_AREAS
            ),
            new recording_scheduler()
        );
        $scanner = new scanner();
        $scanner->set_gate($gate);
        $path = make_request_directory() . '/draft.bin';
        file_put_contents($path, 'draft-bytes');

        $this->assertSame(scanner::SCAN_RESULT_OK, $scanner->scan_file($path, 'draft.bin'));
        $this->assertSame(0, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
        $this->assertSame(0, $provider->analysiscount);
        $this->assertSame(0, $DB->count_records('antivirus_verdict_scans'));
    }

    /**
     * Provider calls still go through scan_service, and an unlimited ceiling reserves nothing.
     */
    public function test_provider_path_and_reservation_remain_central(): void {
        global $CFG;

        $this->resetAfterTest();
        $this->setAdminUser();
        $gate = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/classes/local/antivirus_gate.php');
        $servicefile = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/classes/local/scan_service.php');
        $this->assertStringNotContainsString('lookup_file_hash(', $gate);
        $this->assertStringContainsString('lookup_file_hash(', $servicefile);
        $this->assertStringContainsString('reserve_lookup(', $servicefile);

        $provider = new fake_provider();
        $before = (new operation_reservation())->totals();
        $file = $this->stored_file('fresh.bin', 'fresh-bytes', 0);
        $scan = $this->service($provider)->enqueue_file_scan($file, scan_source::MANUAL, 2);
        $this->service($provider)->process_scan((int) $scan->id);

        $this->assertSame(1, $provider->lookupcount);
        $this->assertSame($before->lookups, (new operation_reservation())->totals()->lookups);
    }

    /** @var int Assignment instance id from the latest helper call. */
    private int $assignid = 0;

    /**
     * Queue one assignment submission file.
     *
     * @param bool $asotheruser True when the event actor is not the student.
     * @param \stdClass|null $actor Event actor. Defaults to the site admin user.
     * @return array{0:\stdClass,1:\stdClass,2:\stdClass,3:\stdClass}
     */
    private function assignment_scan(bool $asotheruser, ?\stdClass $actor = null): array {
        $course = $this->getDataGenerator()->create_course(['shortname' => 'SEC440']);
        $student = $this->getDataGenerator()->create_user(['firstname' => 'Sam', 'lastname' => 'Student']);
        $this->getDataGenerator()->enrol_user($student->id, $course->id, 'student');
        $generator = $this->getDataGenerator()->get_plugin_generator('mod_assign');
        $instance = $generator->create_instance([
            'course' => $course->id,
            'name' => 'Week 3 essay',
            'assignsubmission_file_enabled' => 1,
            'assignsubmission_file_maxfiles' => 2,
            'assignsubmission_file_maxsizebytes' => 1024 * 1024,
            'assignsubmission_onlinetext_enabled' => 0,
        ]);
        $this->assignid = (int) $instance->id;
        $cm = get_coursemodule_from_instance('assign', $instance->id);
        $context = \context_module::instance($cm->id);
        $this->setUser($student);
        $assign = new \assign($context, $cm, $course);
        $submission = $assign->get_user_submission($student->id, true);
        get_file_storage()->create_file_from_string([
            'contextid' => $context->id,
            'component' => assignment_scanner::FILE_COMPONENT,
            'filearea' => assignment_scanner::FILE_AREA,
            'itemid' => $submission->id,
            'filepath' => '/',
            'filename' => 'essay.pdf',
            'userid' => $student->id,
        ], 'essay-bytes');
        $submission->status = ASSIGN_SUBMISSION_STATUS_SUBMITTED;
        global $DB;
        $DB->set_field('assign_submission', 'status', ASSIGN_SUBMISSION_STATUS_SUBMITTED, ['id' => $submission->id]);

        if ($asotheruser) {
            $this->setUser($actor ?? get_admin());
        }
        $event = \mod_assign\event\assessable_submitted::create_from_submission($assign, $submission, false);
        $scans = (new assignment_scanner(
            $this->service(),
            new plugin_config(true, 1048576, true)
        ))->scan_from_event($event);
        $scan = reset($scans);
        $this->assertNotFalse($scan);
        return [$course, $student, $submission, $scan];
    }

    /**
     * Build a manual scan adapter.
     *
     * @return manual_scan
     */
    private function manual(): manual_scan {
        return new manual_scan(
            $this->service(),
            new plugin_config(true, 1048576),
            new test_credentials('test-key')
        );
    }

    /**
     * Build a scan service around the fake provider.
     *
     * @param fake_provider|null $provider Provider.
     * @return scan_service
     */
    private function service(?fake_provider $provider = null): scan_service {
        return new scan_service(
            $provider ?? new fake_provider(),
            new scan_repository(),
            new file_hasher(),
            new plugin_config(true, 1048576),
            new recording_scheduler()
        );
    }

    /**
     * Store a user private file.
     *
     * @param string $filename Filename.
     * @param string $contents Bytes.
     * @param int $userid File user.
     * @param int $contextid Context id.
     * @return \stored_file
     */
    private function stored_file(
        string $filename,
        string $contents,
        int $userid,
        int $contextid = 0
    ): \stored_file {
        if ($contextid <= 0) {
            $contextid = \context_system::instance()->id;
        }
        return get_file_storage()->create_file_from_string([
            'contextid' => $contextid,
            'component' => 'user',
            'filearea' => 'private',
            'itemid' => 0,
            'filepath' => '/',
            'filename' => $filename,
            'userid' => $userid,
        ], $contents);
    }

    /**
     * Delete a course module using the API available on this Moodle branch.
     *
     * Moodle 5.2 exposes {@see \core_courseformat\local\cmactions::delete()}; older branches use
     * {@see course_delete_module()}.
     *
     * @param \stdClass $course Course record.
     * @param \stdClass $cm Course-module row (must include id).
     */
    private function delete_course_module_for_test(\stdClass $course, \stdClass $cm): void {
        $cmid = (int) $cm->id;
        if (method_exists(\core_courseformat\local\cmactions::class, 'delete')) {
            (new \core_courseformat\local\cmactions($course))->delete($cmid);
            return;
        }
        course_delete_module($cmid);
    }

    /**
     * Build a completed scan row for a stored file.
     *
     * @param \stored_file $file Moodle file.
     * @param int $userid Content user.
     * @param int $initiatedby Initiator.
     * @return \stdClass
     */
    private function completed_row(\stored_file $file, int $userid, int $initiatedby): \stdClass {
        $now = time();
        return (object) [
            'fileid' => $file->get_id(),
            'contenthash' => $file->get_contenthash(),
            'pathnamehash' => $file->get_pathnamehash(),
            'contextid' => $file->get_contextid(),
            'courseid' => 0,
            'component' => $file->get_component(),
            'filearea' => $file->get_filearea(),
            'itemid' => $file->get_itemid(),
            'filepath' => '/',
            'filename' => $file->get_filename(),
            'userid' => $userid,
            'initiatedby' => $initiatedby,
            'submissionid' => 0,
            'source' => scan_source::MANUAL,
            'sha256' => hash('sha256', 'again-bytes'),
            'filesize' => $file->get_filesize(),
            'mimetype' => 'text/plain',
            'status' => scan_status::CLEAN,
            'phase' => scan_phase::COMPLETED,
            'vtanalysisid' => 'analysis-done',
            'vtfileid' => hash('sha256', 'again-bytes'),
            'malicious' => 0,
            'suspicious' => 0,
            'undetected' => 1,
            'harmless' => 1,
            'timeout' => 0,
            'totalengines' => 2,
            'errorcode' => null,
            'enforcement' => enforcement_state::NONE,
            'pollattempts' => 0,
            'timelastpoll' => 0,
            'timesubmitted' => $now,
            'timecreated' => $now,
            'timemodified' => $now,
            'timecompleted' => $now,
            'parentscanid' => 0,
            'archiveoutcome' => '',
        ];
    }
}
