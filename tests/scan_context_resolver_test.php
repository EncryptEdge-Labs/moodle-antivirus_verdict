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
 * Tests for Moodle-native scan context resolution.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\assignment_scanner;
use antivirus_verdict\local\manual_scan;
use antivirus_verdict\local\plugin_file_lifecycle;
use antivirus_verdict\local\scan_access;
use antivirus_verdict\local\scan_context_resolver;

/**
 * Tests for scan context resolution.
 *
 * @covers \antivirus_verdict\local\scan_context_resolver
 * @covers \antivirus_verdict\local\scan_access
 */
final class scan_context_resolver_test extends \advanced_testcase {
    /**
     * Manual scan shows Scanned by initiator, not Uploaded by.
     */
    public function test_manual_scan_scanned_by_initiator(): void {
        $this->resetAfterTest();
        $admin = $this->getDataGenerator()->create_user(['firstname' => 'Ada', 'lastname' => 'Admin']);
        $student = $this->getDataGenerator()->create_user(['firstname' => 'Sam', 'lastname' => 'Student']);
        $scan = $this->base_scan(scan_source::MANUAL, (int) $admin->id);
        $scan->component = 'antivirus_verdict';
        $scan->filearea = manual_scan::FILEAREA;

        $this->setUser($admin);
        $ctx = (new scan_context_resolver((int) $admin->id))->resolve($scan);

        $this->assertTrue($ctx->showscannedby);
        $this->assertStringContainsString('Ada', $ctx->scannedby);
        $this->assertFalse($ctx->showfileowner);
    }

    /**
     * Bulk scan distinguishes operator from file owner.
     */
    public function test_bulk_operator_and_file_owner(): void {
        $this->resetAfterTest();
        $course = $this->getDataGenerator()->create_course(['shortname' => 'SEC101']);
        $operator = $this->getDataGenerator()->create_user(['firstname' => 'Op', 'lastname' => 'Erator']);
        $owner = $this->getDataGenerator()->create_and_enrol($course, 'student', ['firstname' => 'File', 'lastname' => 'Owner']);
        $scan = $this->base_scan(scan_source::BULK, (int) $owner->id);
        $scan->initiatedby = (int) $operator->id;
        $scan->courseid = (int) $course->id;
        $scan->contextid = (int) \context_course::instance($course->id)->id;

        $this->setAdminUser();
        $ctx = (new scan_context_resolver())->resolve($scan);

        $this->assertTrue($ctx->showscannedby);
        $this->assertStringContainsString('Op', $ctx->scannedby);
        $this->assertTrue($ctx->showfileowner);
        $this->assertStringContainsString('File', $ctx->fileowner);
    }

    /**
     * Gate scan does not fabricate course or activity.
     */
    public function test_antivirus_gate_honest_limits(): void {
        $this->resetAfterTest();
        $uploader = $this->getDataGenerator()->create_user(['firstname' => 'Up', 'lastname' => 'Loader']);
        $scan = $this->base_scan(scan_source::ANTIVIRUS, (int) $uploader->id);
        $scan->courseid = 0;
        $scan->contextid = (int) \context_system::instance()->id;
        $scan->component = 'antivirus_verdict';
        $scan->filearea = plugin_file_lifecycle::GATE_FILEAREA;

        $this->setAdminUser();
        $ctx = (new scan_context_resolver())->resolve($scan);

        $this->assertFalse($ctx->showcourse);
        $this->assertFalse($ctx->showactivity);
        $this->assertTrue($ctx->showfileowner);
        $this->assertStringContainsString('Up', $ctx->fileowner);
    }

    /**
     * Teachers cannot resolve unrelated course user names.
     */
    public function test_teacher_cannot_view_unrelated_user_identity(): void {
        $this->resetAfterTest();
        $course1 = $this->getDataGenerator()->create_course();
        $course2 = $this->getDataGenerator()->create_course();
        $teacher = $this->getDataGenerator()->create_and_enrol($course1, 'editingteacher');
        $student = $this->getDataGenerator()->create_and_enrol($course2, 'student');
        $scan = $this->base_scan(scan_source::ASSIGN, (int) $student->id);
        $scan->courseid = (int) $course2->id;
        $scan->contextid = (int) \context_course::instance($course2->id)->id;

        $context = scan_access::context_for_scan($scan);
        $this->assertFalse(scan_access::can_view_user_identity((int) $teacher->id, (int) $student->id, $context));
    }

    /**
     * Assignment activity name comes from Moodle modinfo verbatim.
     */
    public function test_assignment_activity_name_from_modinfo(): void {
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
        $scan = $this->base_scan(scan_source::ASSIGN, (int) $student->id);
        $scan->courseid = (int) $course->id;
        $scan->contextid = (int) $context->id;
        $scan->component = assignment_scanner::FILE_COMPONENT;
        $scan->filearea = assignment_scanner::FILE_AREA;
        $scan->submissionid = 42;
        $scan->itemid = 42;

        $this->setAdminUser();
        $ctx = (new scan_context_resolver())->resolve($scan);

        $this->assertTrue($ctx->showactivity);
        $this->assertSame($activityname, $ctx->activity);
        $this->assertTrue($ctx->showactivitytype);
        $this->assertSame(get_string('modulename', 'assign'), $ctx->activitytype);
    }

    /**
     * Internal helper.
     *
     * @param string $source Scan source.
     * @param int $userid User id.
     * @return \stdClass
     */
    private function base_scan(string $source, int $userid): \stdClass {
        $scan = (object) [
            'id' => 1,
            'fileid' => 0,
            'contenthash' => '',
            'pathnamehash' => '',
            'contextid' => (int) \context_system::instance()->id,
            'courseid' => 0,
            'component' => 'user',
            'filearea' => 'draft',
            'itemid' => 0,
            'filepath' => '/',
            'filename' => 'test.bin',
            'userid' => $userid,
            'initiatedby' => 0,
            'submissionid' => 0,
            'source' => $source,
            'sha256' => str_repeat('a', 64),
            'filesize' => 4,
            'mimetype' => 'application/octet-stream',
            'status' => scan_status::CLEAN,
            'phase' => 'complete',
            'enforcement' => 'none',
            'timecreated' => time(),
            'timecompleted' => time(),
        ];
        return $scan;
    }
}
