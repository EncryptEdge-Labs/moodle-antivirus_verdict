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
 * Tests for scan history authorisation.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\scan_access;
use antivirus_verdict\local\scan_repository;


/**
 * Visibility rules for history and detail.
 *
 * @covers \antivirus_verdict\local\scan_access
 * @covers \antivirus_verdict\local\scan_repository
 */
final class scan_access_test extends \advanced_testcase {
    /**
     * Site managers can see scans from every course.
     */
    public function test_manager_sees_all_courses(): void {

        $this->resetAfterTest();
        [$course1, $course2, $teacher1] = $this->prepare_courses();
        $manager = $this->create_manager();
        $this->insert_scan($course1, $teacher1->id, scan_source::ASSIGN, 'a.pdf');
        $this->insert_scan($course2, $teacher1->id, scan_source::MANUAL, 'b.pdf');

        $this->assertTrue(scan_access::can_manage_site($manager->id));
        $repo = new scan_repository();
        $this->assertSame(2, $repo->count_visible_history($manager->id));
        $this->assertSame(1, $repo->count_visible_history($manager->id, ['courseid' => $course1->id]));
    }

    /**
     * Teachers see assignment scans only in courses they can access.
     */
    public function test_teacher_cannot_see_other_course_assignment_scan(): void {
        $this->resetAfterTest();
        [$course1, $course2, $teacher1] = $this->prepare_courses();
        $teacher2 = $this->getDataGenerator()->create_and_enrol($course2, 'editingteacher');
        $scan1 = $this->insert_scan($course1, 5, scan_source::ASSIGN, 'secret.pdf');
        $scan2 = $this->insert_scan($course2, 6, scan_source::ASSIGN, 'local.pdf');

        $this->assertFalse(scan_access::can_view_scan($scan1, $teacher2->id));
        $this->assertTrue(scan_access::can_view_scan($scan2, $teacher2->id));

        $repo = new scan_repository();
        $rows = $repo->get_visible_history($teacher2->id);
        $names = array_map(static fn($row) => $row->filename, $rows);
        $this->assertContains('local.pdf', $names);
        $this->assertNotContains('secret.pdf', $names);
    }

    /**
     * Students have no scan history access by default.
     */
    public function test_student_cannot_access_history_or_detail(): void {
        $this->resetAfterTest();
        [$course1] = $this->prepare_courses();
        $student = $this->getDataGenerator()->create_and_enrol($course1, 'student');
        $scan = $this->insert_scan($course1, $student->id, scan_source::ASSIGN, 'essay.pdf');
        $context = \context_course::instance($course1->id);

        $this->assertFalse(scan_access::can_view_history_page($context, $student->id));
        $this->assertFalse(scan_access::can_view_scan($scan, $student->id));
        $this->assertFalse(scan_access::can_scan($context, $student->id));
        $this->assertFalse(scan_access::can_rescan($scan, $student->id));
        $this->assertSame(0, (new scan_repository())->count_visible_history($student->id));
    }

    /**
     * A teacher cannot view or rescan scans from another course by id.
     */
    public function test_teacher_cannot_rescan_other_course(): void {
        $this->resetAfterTest();
        [$course1, $course2, $teacher1] = $this->prepare_courses();
        $teacher2 = $this->getDataGenerator()->create_and_enrol($course2, 'editingteacher');
        $scan = $this->insert_scan($course1, $teacher1->id, scan_source::ASSIGN, 'secret.pdf');

        $this->assertTrue(scan_access::can_view_scan($scan, $teacher1->id));
        $this->assertTrue(scan_access::can_rescan($scan, $teacher1->id));
        $this->assertFalse(scan_access::can_view_scan($scan, $teacher2->id));
        $this->assertFalse(scan_access::can_rescan($scan, $teacher2->id));
    }

    /**
     * A teacher can see their own manual scans.
     */
    public function test_owner_can_view_own_manual_scan(): void {
        $this->resetAfterTest();
        [$course1] = $this->prepare_courses();
        $teacher = $this->getDataGenerator()->create_and_enrol($course1, 'editingteacher');
        $scan = $this->insert_scan($course1, $teacher->id, scan_source::MANUAL, 'mine.bin');
        $this->assertTrue(scan_access::can_view_scan($scan, $teacher->id));
    }

    /**
     * Site-level manual scans use system context; teachers still see their own row.
     */
    public function test_owner_can_view_site_level_manual_scan(): void {
        $this->resetAfterTest();
        [$course1] = $this->prepare_courses();
        $teacher = $this->getDataGenerator()->create_and_enrol($course1, 'editingteacher');
        $system = \context_system::instance();
        $repo = new scan_repository();
        $now = time();
        $scan = (object) [
            'fileid' => 0,
            'contenthash' => sha1('site.bin'),
            'pathnamehash' => sha1('site-level'),
            'contextid' => $system->id,
            'courseid' => 0,
            'component' => 'antivirus_verdict',
            'filearea' => 'manual',
            'itemid' => 1,
            'filepath' => '/',
            'filename' => 'site.bin',
            'userid' => $teacher->id,
            'initiatedby' => $teacher->id,
            'source' => scan_source::MANUAL,
            'sha256' => '',
            'filesize' => 10,
            'mimetype' => 'application/octet-stream',
            'status' => scan_status::PENDING,
            'phase' => scan_phase::QUEUED,
            'vtanalysisid' => null,
            'vtfileid' => null,
            'malicious' => null,
            'suspicious' => null,
            'undetected' => null,
            'harmless' => null,
            'timeout' => null,
            'totalengines' => null,
            'errorcode' => null,
            'pollattempts' => 0,
            'timelastpoll' => 0,
            'timesubmitted' => 0,
            'timecreated' => $now,
            'timemodified' => $now,
            'timecompleted' => 0,
        ];
        $scan->id = $repo->insert($scan);
        $this->assertFalse(has_capability('antivirus/verdict:scan', $system, $teacher->id));
        $this->assertTrue(scan_access::can_view_own_manual_scan($scan, $teacher->id));
        $this->assertTrue(scan_access::can_view_scan($scan, $teacher->id));
    }

    /**
     * Course scans stay visible when the row context id is system-level.
     */
    public function test_course_scan_visible_via_courseid_not_contextid(): void {
        $this->resetAfterTest();
        [$course1] = $this->prepare_courses();
        $teacher = $this->getDataGenerator()->create_and_enrol($course1, 'editingteacher');
        $system = \context_system::instance();
        $repo = new scan_repository();
        $now = time();
        $scan = (object) [
            'fileid' => 0,
            'contenthash' => sha1('course-context.bin'),
            'pathnamehash' => sha1('course-context'),
            'contextid' => $system->id,
            'courseid' => $course1->id,
            'component' => 'assignsubmission_file',
            'filearea' => 'submission_files',
            'itemid' => 1,
            'filepath' => '/',
            'filename' => 'course-context.bin',
            'userid' => $teacher->id,
            'initiatedby' => 0,
            'source' => scan_source::ASSIGN,
            'sha256' => '',
            'filesize' => 10,
            'mimetype' => 'application/octet-stream',
            'status' => scan_status::CLEAN,
            'phase' => scan_phase::COMPLETED,
            'vtanalysisid' => null,
            'vtfileid' => null,
            'malicious' => 0,
            'suspicious' => null,
            'undetected' => null,
            'harmless' => null,
            'timeout' => null,
            'totalengines' => 10,
            'errorcode' => null,
            'pollattempts' => 0,
            'timelastpoll' => 0,
            'timesubmitted' => 0,
            'timecreated' => $now,
            'timemodified' => $now,
            'timecompleted' => $now,
        ];
        $scan->id = $repo->insert($scan);
        $this->assertFalse(has_capability('antivirus/verdict:viewhistory', $system, $teacher->id));
        $this->assertTrue(scan_access::can_view_scan($scan, $teacher->id));
    }

    /**
     * Teachers may rescan their own site-level manual scans when they hold rescan in a course.
     */
    public function test_teacher_can_rescan_own_site_manual_scan(): void {
        $this->resetAfterTest();
        [$course1] = $this->prepare_courses();
        $teacher = $this->getDataGenerator()->create_and_enrol($course1, 'editingteacher');
        $system = \context_system::instance();
        $repo = new scan_repository();
        $now = time();
        $scan = (object) [
            'fileid' => 0,
            'contenthash' => sha1('rescan-site.bin'),
            'pathnamehash' => sha1('rescan-site'),
            'contextid' => $system->id,
            'courseid' => 0,
            'component' => 'antivirus_verdict',
            'filearea' => 'manual',
            'itemid' => 1,
            'filepath' => '/',
            'filename' => 'rescan-site.bin',
            'userid' => $teacher->id,
            'initiatedby' => $teacher->id,
            'source' => scan_source::MANUAL,
            'sha256' => '',
            'filesize' => 10,
            'mimetype' => 'application/octet-stream',
            'status' => scan_status::CLEAN,
            'phase' => scan_phase::COMPLETED,
            'vtanalysisid' => null,
            'vtfileid' => null,
            'malicious' => 0,
            'suspicious' => null,
            'undetected' => null,
            'harmless' => null,
            'timeout' => null,
            'totalengines' => 10,
            'errorcode' => null,
            'pollattempts' => 0,
            'timelastpoll' => 0,
            'timesubmitted' => 0,
            'timecreated' => $now,
            'timemodified' => $now,
            'timecompleted' => $now,
        ];
        $scan->id = $repo->insert($scan);
        $this->assertTrue(scan_access::can_rescan($scan, $teacher->id));
    }

    /**
     * Guessed scan ids do not become visible without capability.
     */
    public function test_guessed_id_is_not_visible(): void {
        $this->resetAfterTest();
        [$course1, $course2] = $this->prepare_courses();
        $outsider = $this->getDataGenerator()->create_and_enrol($course2, 'editingteacher');
        $scan = $this->insert_scan($course1, 9, scan_source::MANUAL, 'hidden.bin');
        $this->assertFalse(scan_access::can_view_scan($scan, $outsider->id));
        $this->assertNull((new scan_repository())->get_by_id(0));
        $this->assertNull((new scan_repository())->get_by_id(-1));
    }

    /**
     * Pagination returns a slice, not the full table.
     */
    public function test_history_pagination_and_filters(): void {
        $this->resetAfterTest();
        [$course1] = $this->prepare_courses();
        $teacher = $this->getDataGenerator()->create_and_enrol($course1, 'editingteacher');
        $this->insert_scan($course1, $teacher->id, scan_source::MANUAL, 'one.pdf', scan_status::PENDING);
        $this->insert_scan($course1, $teacher->id, scan_source::MANUAL, 'two.pdf', scan_status::CLEAN);
        $this->insert_scan($course1, $teacher->id, scan_source::ASSIGN, 'three.pdf', scan_status::MALICIOUS);

        $repo = new scan_repository();
        $this->assertSame(3, $repo->count_visible_history($teacher->id, ['courseid' => $course1->id]));
        $page = $repo->get_visible_history($teacher->id, ['courseid' => $course1->id], 2, 0);
        $this->assertCount(2, $page);
        $rest = $repo->get_visible_history($teacher->id, ['courseid' => $course1->id], 2, 2);
        $this->assertCount(1, $rest);

        $clean = $repo->get_visible_history($teacher->id, ['courseid' => $course1->id, 'status' => scan_status::CLEAN]);
        $this->assertCount(1, $clean);
        $this->assertSame('two.pdf', reset($clean)->filename);

        $assign = $repo->get_visible_history($teacher->id, ['courseid' => $course1->id, 'source' => scan_source::ASSIGN]);
        $this->assertCount(1, $assign);

        $search = $repo->get_visible_history($teacher->id, ['courseid' => $course1->id, 'filename' => 'three']);
        $this->assertCount(1, $search);
        $none = $repo->get_visible_history($teacher->id, ['courseid' => $course1->id, 'filename' => 'missing-name']);
        $this->assertCount(0, $none);
    }

    /**
     * Empty history is an empty list.
     */
    public function test_empty_history(): void {
        $this->resetAfterTest();
        $user = $this->getDataGenerator()->create_user();
        $this->assertSame([], (new scan_repository())->get_visible_history($user->id));
    }

    /**
     * Create two courses and a teacher in the first.
     *
     * @return array
     */
    private function prepare_courses(): array {
        $course1 = $this->getDataGenerator()->create_course();
        $course2 = $this->getDataGenerator()->create_course();
        $teacher1 = $this->getDataGenerator()->create_and_enrol($course1, 'editingteacher');
        return [$course1, $course2, $teacher1];
    }

    /**
     * Assign the manager role at system context.
     *
     * @return \stdClass
     */
    private function create_manager(): \stdClass {
        global $DB;
        $user = $this->getDataGenerator()->create_user();
        $roleid = $DB->get_field('role', 'id', ['shortname' => 'manager'], \MUST_EXIST);
        role_assign($roleid, $user->id, \context_system::instance()->id);
        return $user;
    }

    /**
     * Insert a scan row.
     *
     * @param \stdClass $course Course.
     * @param int $userid Associated user.
     * @param string $source Source.
     * @param string $filename File name.
     * @param string $status Status.
     * @return \stdClass
     */
    private function insert_scan(
        \stdClass $course,
        int $userid,
        string $source,
        string $filename,
        string $status = scan_status::PENDING
    ): \stdClass {
        $repo = new scan_repository();
        $context = \context_course::instance($course->id);
        $now = time();
        $record = (object) [
            'fileid' => 0,
            'contenthash' => sha1($filename),
            'pathnamehash' => sha1($filename . $course->id . $userid),
            'contextid' => $context->id,
            'courseid' => $course->id,
            'component' => 'antivirus_verdict',
            'filearea' => 'unittest',
            'itemid' => random_int(1, 1000000),
            'filepath' => '/',
            'filename' => $filename,
            'userid' => $userid,
            'source' => $source,
            'sha256' => '',
            'filesize' => 10,
            'mimetype' => 'application/octet-stream',
            'status' => $status,
            'phase' => $status === scan_status::PENDING ? scan_phase::QUEUED : scan_phase::COMPLETED,
            'vtanalysisid' => null,
            'vtfileid' => null,
            'malicious' => $status === scan_status::MALICIOUS ? 3 : null,
            'suspicious' => null,
            'undetected' => null,
            'harmless' => null,
            'timeout' => null,
            'totalengines' => $status === scan_status::MALICIOUS ? 10 : null,
            'errorcode' => null,
            'pollattempts' => 0,
            'timelastpoll' => 0,
            'timesubmitted' => 0,
            'timecreated' => $now,
            'timemodified' => $now,
            'timecompleted' => $status === scan_status::PENDING ? 0 : $now,
        ];
        $record->id = $repo->insert($record);
        return $record;
    }
}
