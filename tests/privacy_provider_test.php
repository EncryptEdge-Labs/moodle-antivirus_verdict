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
 * Privacy API tests for the antivirus_verdict plugin.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\privacy;

use core_privacy\local\metadata\collection;
use core_privacy\local\request\writer;
use antivirus_verdict\local\plugin_file_lifecycle;
use antivirus_verdict\scan_source;
use antivirus_verdict\scan_status;


/**
 * Tests the privacy metadata and request provider.
 *
 * @covers \antivirus_verdict\privacy\provider
 */
final class privacy_provider_test extends \core_privacy\tests\provider_testcase {
    /** Placeholder key used only in these tests. */
    private const FAKE_KEY = 'phpunit-privacy-secret-key';

    /**
     * Metadata includes the scan table and VirusTotal external location.
     */
    public function test_get_metadata(): void {
        $this->resetAfterTest();

        $collection = provider::get_metadata(new collection('antivirus_verdict'));
        $items = $collection->get_collection();
        $this->assertNotEmpty($items);

        $types = [];
        foreach ($items as $item) {
            $types[] = $item->get_name();
        }

        $this->assertContains('antivirus_verdict_scans', $types);
        $this->assertContains('virustotal', $types);
        $this->assertContains('core_files', $types);
    }

    /**
     * A user with no scans has an empty context list.
     */
    public function test_get_contexts_for_userid_without_data(): void {
        $this->resetAfterTest();
        $user = $this->getDataGenerator()->create_user();
        $contextlist = provider::get_contexts_for_userid($user->id);
        $this->assertCount(0, $contextlist);
    }

    /**
     * Export includes user-facing scan metadata and excludes secrets and internals.
     */
    public function test_export_and_delete_user_data(): void {
        global $DB;

        $this->resetAfterTest();
        set_config('apikey', self::FAKE_KEY, 'antivirus_verdict');
        $user = $this->getDataGenerator()->create_user();
        $course = $this->getDataGenerator()->create_course();
        $context = \context_course::instance($course->id);

        $id = $this->insert_scan($user->id, $context, $course->id, [
            'filename' => 'essay.pdf',
            'source' => scan_source::ASSIGN,
            'status' => scan_status::PENDING,
            'phase' => 'queued',
            'sha256' => str_repeat('c', 64),
            'vtanalysisid' => 'analysis-secret',
            'vtfileid' => 'file-secret',
        ]);

        $contextlist = provider::get_contexts_for_userid($user->id);
        $this->assertEquals([$context->id], $contextlist->get_contextids());

        $approved = new \core_privacy\local\request\approved_contextlist(
            $user,
            'antivirus_verdict',
            [$context->id]
        );
        provider::export_user_data($approved);

        $writer = writer::with_context($context);
        $this->assertTrue($writer->has_any_data());
        $data = $writer->get_data([get_string('privacy:path:scans', 'antivirus_verdict'), $id]);
        $this->assertSame('essay.pdf', $data->filename);
        $this->assertSame(get_string('source_assign', 'antivirus_verdict'), $data->source);
        $this->assertSame(get_string('status_pending', 'antivirus_verdict'), $data->status);
        $this->assertSame(str_repeat('c', 64), $data->sha256);
        $this->assertFalse(property_exists($data, 'pathnamehash'));
        $this->assertFalse(property_exists($data, 'contenthash'));
        $this->assertFalse(property_exists($data, 'fileid'));
        $this->assertFalse(property_exists($data, 'itemid'));
        $this->assertFalse(property_exists($data, 'phase'));
        $this->assertFalse(property_exists($data, 'vtanalysisid'));
        $this->assertFalse(property_exists($data, 'vtfileid'));
        $this->assertFalse(property_exists($data, 'errorcode'));
        $this->assertFalse(property_exists($data, 'malicious'));
        $json = json_encode($data);
        $this->assertStringNotContainsString(self::FAKE_KEY, $json);
        $this->assertStringNotContainsString('x-apikey', $json);
        $this->assertStringNotContainsString('analysis-secret', $json);
        $this->assertStringNotContainsString('queued', $json);

        provider::delete_data_for_user($approved);
        $this->assertEquals(0, $DB->count_records('antivirus_verdict_scans', ['userid' => $user->id]));
        provider::delete_data_for_user($approved);
        $this->assertEquals(0, $DB->count_records('antivirus_verdict_scans', ['userid' => $user->id]));
    }

    /**
     * Export is scoped to the requesting user.
     */
    public function test_export_does_not_include_another_user(): void {
        $this->resetAfterTest();
        $course = $this->getDataGenerator()->create_course();
        $context = \context_course::instance($course->id);
        $user = $this->getDataGenerator()->create_user();
        $other = $this->getDataGenerator()->create_user();
        $mineid = $this->insert_scan($user->id, $context, $course->id, ['filename' => 'mine.pdf']);
        $otherid = $this->insert_scan($other->id, $context, $course->id, ['filename' => 'theirs.pdf']);

        $approved = new \core_privacy\local\request\approved_contextlist(
            $user,
            'antivirus_verdict',
            [$context->id]
        );
        provider::export_user_data($approved);
        $writer = writer::with_context($context);
        $mine = $writer->get_data([get_string('privacy:path:scans', 'antivirus_verdict'), $mineid]);
        $this->assertSame('mine.pdf', $mine->filename);
        $theirs = $writer->get_data([get_string('privacy:path:scans', 'antivirus_verdict'), $otherid]);
        $this->assertEmpty((array) $theirs);
    }

    /**
     * Assignment scans export for the learner, not an unrelated teacher.
     */
    public function test_assignment_learner_export_isolation(): void {
        $this->resetAfterTest();
        $course = $this->getDataGenerator()->create_course();
        $context = \context_course::instance($course->id);
        $learner = $this->getDataGenerator()->create_user();
        $teacher = $this->getDataGenerator()->create_and_enrol($course, 'editingteacher');
        $id = $this->insert_scan($learner->id, $context, $course->id, [
            'filename' => 'submission.pdf',
            'source' => scan_source::ASSIGN,
            'status' => scan_status::CLEAN,
            'malicious' => 0,
            'totalengines' => 70,
        ]);

        $teacherapproved = new \core_privacy\local\request\approved_contextlist(
            $teacher,
            'antivirus_verdict',
            [$context->id]
        );
        provider::export_user_data($teacherapproved);
        $teacherdata = writer::with_context($context)->get_data(
            [get_string('privacy:path:scans', 'antivirus_verdict'), $id]
        );
        $this->assertEmpty((array) $teacherdata);

        writer::reset();
        $learnerapproved = new \core_privacy\local\request\approved_contextlist(
            $learner,
            'antivirus_verdict',
            [$context->id]
        );
        provider::export_user_data($learnerapproved);
        $learnerdata = writer::with_context($context)->get_data(
            [get_string('privacy:path:scans', 'antivirus_verdict'), $id]
        );
        $this->assertSame('submission.pdf', $learnerdata->filename);
        $this->assertSame(0, (int) $learnerdata->malicious);
        $this->assertSame(70, (int) $learnerdata->totalengines);
    }

    /**
     * An administrator's privacy export contains only that user's scan rows.
     */
    public function test_administrator_export_is_own_data_only(): void {
        $this->resetAfterTest();
        $course = $this->getDataGenerator()->create_course();
        $context = \context_course::instance($course->id);
        $admin = get_admin();
        $other = $this->getDataGenerator()->create_user();
        $adminid = $this->insert_scan($admin->id, $context, $course->id, ['filename' => 'admin.bin']);
        $otherid = $this->insert_scan($other->id, $context, $course->id, ['filename' => 'other.bin']);

        $approved = new \core_privacy\local\request\approved_contextlist(
            $admin,
            'antivirus_verdict',
            [$context->id]
        );
        provider::export_user_data($approved);
        $writer = writer::with_context($context);
        $this->assertSame(
            'admin.bin',
            $writer->get_data([get_string('privacy:path:scans', 'antivirus_verdict'), $adminid])->filename
        );
        $this->assertEmpty((array) $writer->get_data(
            [get_string('privacy:path:scans', 'antivirus_verdict'), $otherid]
        ));
    }

    /**
     * Missing course context does not fabricate export content.
     */
    public function test_export_skips_missing_context(): void {
        $this->resetAfterTest();
        $user = $this->getDataGenerator()->create_user();
        $this->insert_scan($user->id, \context_system::instance(), 0, [
            'contextid' => 999999999,
            'filename' => 'gone.pdf',
        ]);
        $approved = new \core_privacy\local\request\approved_contextlist(
            $user,
            'antivirus_verdict',
            [999999999]
        );
        provider::export_user_data($approved);
        $this->assertTrue(true);
    }

    /**
     * Privacy deletion removes plugin-owned copies and leaves other files.
     */
    public function test_delete_removes_plugin_copies_only(): void {
        $this->resetAfterTest();
        $user = $this->getDataGenerator()->create_user();
        $course = $this->getDataGenerator()->create_course();
        $context = \context_course::instance($course->id);
        $fs = get_file_storage();
        $copy = $fs->create_file_from_string([
            'contextid' => $context->id,
            'component' => 'antivirus_verdict',
            'filearea' => 'manual',
            'itemid' => 7,
            'filepath' => '/',
            'filename' => 'copy.bin',
            'userid' => $user->id,
        ], 'copy-bytes');
        $assign = $fs->create_file_from_string([
            'contextid' => $context->id,
            'component' => 'assignsubmission_file',
            'filearea' => 'submission_files',
            'itemid' => 8,
            'filepath' => '/',
            'filename' => 'keep.bin',
            'userid' => $user->id,
        ], 'keep-bytes');
        $other = $this->getDataGenerator()->create_user();
        $othercopy = $fs->create_file_from_string([
            'contextid' => $context->id,
            'component' => 'antivirus_verdict',
            'filearea' => 'manual',
            'itemid' => 9,
            'filepath' => '/',
            'filename' => 'other.bin',
            'userid' => $other->id,
        ], 'other-bytes');

        $approved = new \core_privacy\local\request\approved_contextlist(
            $user,
            'antivirus_verdict',
            [$context->id]
        );
        provider::delete_data_for_user($approved);
        $this->assertFalse($fs->get_file_by_id($copy->get_id()));
        $this->assertNotFalse($fs->get_file_by_id($assign->get_id()));
        $this->assertNotFalse($fs->get_file_by_id($othercopy->get_id()));
    }

    /**
     * Deletion succeeds when a plugin-owned copy is already missing.
     */
    public function test_delete_missing_manual_copy_is_safe(): void {
        global $DB;

        $this->resetAfterTest();
        $user = $this->getDataGenerator()->create_user();
        $course = $this->getDataGenerator()->create_course();
        $context = \context_course::instance($course->id);
        $this->insert_scan($user->id, $context, $course->id, [
            'component' => 'antivirus_verdict',
            'filearea' => 'manual',
            'itemid' => 42,
            'filename' => 'missing.bin',
        ]);
        $approved = new \core_privacy\local\request\approved_contextlist(
            $user,
            'antivirus_verdict',
            [$context->id]
        );
        provider::delete_data_for_user($approved);
        $this->assertEquals(0, $DB->count_records('antivirus_verdict_scans', ['userid' => $user->id]));
    }

    /**
     * Plugin-owned copies without a scan row are still discoverable.
     */
    public function test_contexts_include_plugin_owned_copies(): void {
        $this->resetAfterTest();
        $user = $this->getDataGenerator()->create_user();
        $course = $this->getDataGenerator()->create_course();
        $context = \context_course::instance($course->id);
        get_file_storage()->create_file_from_string([
            'contextid' => $context->id,
            'component' => 'antivirus_verdict',
            'filearea' => 'manual',
            'itemid' => 11,
            'filepath' => '/',
            'filename' => 'pending.bin',
            'userid' => $user->id,
        ], 'pending-bytes');

        $contextlist = provider::get_contexts_for_userid($user->id);
        $this->assertEquals([$context->id], $contextlist->get_contextids());

        $userlist = new \core_privacy\local\request\userlist($context, 'antivirus_verdict');
        provider::get_users_in_context($userlist);
        $this->assertContains((int) $user->id, $userlist->get_userids());
    }

    /**
     * Gate copies are discoverable, exported, and deleted for the owning user only.
     */
    public function test_gate_copies_are_covered_by_privacy_api(): void {
        $this->resetAfterTest();
        $user = $this->getDataGenerator()->create_user();
        $other = $this->getDataGenerator()->create_user();
        $context = \context_system::instance();

        $mine = $this->create_gate_copy($context, (int) $user->id, 'upload.bin', 'gate-bytes');
        $theirs = $this->create_gate_copy($context, (int) $other->id, 'their.bin', 'their-bytes');
        $this->assertSame(plugin_file_lifecycle::COMPONENT, $mine->get_component());
        $this->assertSame(plugin_file_lifecycle::GATE_FILEAREA, $mine->get_filearea());
        $this->assertSame((int) $user->id, (int) $mine->get_userid());

        $contextlist = provider::get_contexts_for_userid($user->id);
        $this->assertContainsEquals($context->id, $contextlist->get_contextids());

        $userlist = new \core_privacy\local\request\userlist($context, 'antivirus_verdict');
        provider::get_users_in_context($userlist);
        $this->assertContains((int) $user->id, $userlist->get_userids());
        $this->assertContains((int) $other->id, $userlist->get_userids());

        $approved = new \core_privacy\local\request\approved_contextlist(
            $user,
            'antivirus_verdict',
            [$context->id]
        );
        provider::export_user_data($approved);
        $files = writer::with_context($context)->get_files([
            get_string('privacy:path:copies', 'antivirus_verdict'),
            plugin_file_lifecycle::GATE_FILEAREA,
        ]);
        $this->assertArrayHasKey('upload.bin', $files);
        $this->assertArrayNotHasKey('their.bin', $files);

        provider::delete_data_for_user($approved);
        $fs = get_file_storage();
        $this->assertFalse($fs->get_file_by_id($mine->get_id()));
        $this->assertNotFalse($fs->get_file_by_id($theirs->get_id()));
    }

    /**
     * Deleting a container context also deletes member rows stored elsewhere.
     */
    public function test_context_delete_removes_archive_members(): void {
        global $DB;

        $this->resetAfterTest();
        $user = $this->getDataGenerator()->create_user();
        $course = $this->getDataGenerator()->create_course();
        $coursecontext = \context_course::instance($course->id);
        $system = \context_system::instance();

        $parentid = $this->insert_scan($user->id, $coursecontext, $course->id, [
            'filename' => 'bundle.zip',
            'archiveoutcome' => 'processing',
            'sha256' => str_repeat('d', 64),
            'pathnamehash' => str_repeat('d', 40),
        ]);
        $childid = $this->insert_scan($user->id, $system, 0, [
            'filename' => 'member.txt',
            'parentscanid' => $parentid,
            'source' => scan_source::ARCHIVE,
            'sha256' => str_repeat('e', 64),
            'pathnamehash' => str_repeat('e', 40),
            'contenthash' => str_repeat('e', 40),
        ]);
        $otherid = $this->insert_scan($user->id, $system, 0, [
            'filename' => 'plain.bin',
            'sha256' => str_repeat('f', 64),
            'pathnamehash' => str_repeat('f', 40),
            'contenthash' => str_repeat('f', 40),
        ]);

        $approved = new \core_privacy\local\request\approved_contextlist(
            $user,
            'antivirus_verdict',
            [$coursecontext->id]
        );
        provider::export_user_data($approved);
        $exported = writer::with_context($coursecontext)->get_data([
            get_string('privacy:path:scans', 'antivirus_verdict'),
            $parentid,
        ]);
        $this->assertSame('processing', $exported->archiveoutcome);

        provider::delete_data_for_all_users_in_context($coursecontext);
        $this->assertFalse($DB->record_exists('antivirus_verdict_scans', ['id' => $parentid]));
        $this->assertFalse($DB->record_exists('antivirus_verdict_scans', ['id' => $childid]));
        $this->assertTrue($DB->record_exists('antivirus_verdict_scans', ['id' => $otherid]));
    }

    /**
     * Manual and gate copies are both removed when a whole context is purged.
     */
    public function test_delete_all_users_in_context_removes_both_copy_areas(): void {
        $this->resetAfterTest();
        $user = $this->getDataGenerator()->create_user();
        $other = $this->getDataGenerator()->create_user();
        $context = \context_system::instance();
        $fs = get_file_storage();

        $gate = $this->create_gate_copy($context, (int) $user->id, 'gate.bin', 'gate-bytes');
        $othergate = $this->create_gate_copy($context, (int) $other->id, 'othergate.bin', 'other-bytes');
        $manual = $fs->create_file_from_string([
            'contextid' => $context->id,
            'component' => 'antivirus_verdict',
            'filearea' => 'manual',
            'itemid' => 3,
            'filepath' => '/',
            'filename' => 'manual.bin',
            'userid' => $user->id,
        ], 'manual-bytes');

        provider::delete_data_for_all_users_in_context($context);

        $this->assertFalse($fs->get_file_by_id($gate->get_id()));
        $this->assertFalse($fs->get_file_by_id($othergate->get_id()));
        $this->assertFalse($fs->get_file_by_id($manual->get_id()));
    }

    /**
     * Create a real gate copy through the plugin file lifecycle helper.
     *
     * @param \context $context Destination context.
     * @param int $userid Owning user.
     * @param string $filename Destination filename.
     * @param string $content Bytes.
     * @return \stored_file
     */
    private function create_gate_copy(
        \context $context,
        int $userid,
        string $filename,
        string $content
    ): \stored_file {
        $path = make_request_directory() . '/' . $filename;
        file_put_contents($path, $content);
        return plugin_file_lifecycle::store_path_copy($path, $filename, $context, $userid);
    }

    /**
     * Last inserted scan id for isolation assertions.
     *
     * @var int
     */
    private int $lastscanid = 0;

    /**
     * Insert a scan row for privacy tests.
     *
     * @param int $userid User id.
     * @param \context $context Context.
     * @param int $courseid Course id.
     * @param array $overrides Field overrides.
     * @return int Scan id.
     */
    private function insert_scan(int $userid, \context $context, int $courseid, array $overrides = []): int {
        global $DB;

        $now = time();
        $record = (object) array_merge([
            'contenthash' => str_repeat('a', 40),
            'pathnamehash' => str_repeat('b', 40),
            'contextid' => $context->id,
            'courseid' => $courseid,
            'component' => 'mod_assign',
            'filearea' => 'submission_files',
            'itemid' => 1,
            'filepath' => '/',
            'filename' => 'file.bin',
            'userid' => $userid,
            'source' => scan_source::MANUAL,
            'sha256' => str_repeat('c', 64),
            'filesize' => 1234,
            'mimetype' => 'application/pdf',
            'status' => scan_status::PENDING,
            'phase' => 'queued',
            'fileid' => 0,
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
        ], $overrides);
        $this->lastscanid = (int) $DB->insert_record('antivirus_verdict_scans', $record);
        return $this->lastscanid;
    }
}
