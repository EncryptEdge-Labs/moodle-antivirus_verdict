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
 * Tests for plugin-owned manual file copy cleanup.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\file_hasher;
use antivirus_verdict\local\manual_scan;
use antivirus_verdict\local\plugin_config;
use antivirus_verdict\local\plugin_file_lifecycle;
use antivirus_verdict\local\rescan;
use antivirus_verdict\local\scan_repository;
use antivirus_verdict\local\scan_service;
use antivirus_verdict\provider\file_lookup_result;
use antivirus_verdict\tests\fake_provider;
use antivirus_verdict\tests\recording_scheduler;
use antivirus_verdict\tests\test_credentials;


/**
 * Manual copy lifecycle.
 *
 * @covers \antivirus_verdict\local\plugin_file_lifecycle
 * @covers \antivirus_verdict\local\manual_scan
 */
final class plugin_file_lifecycle_test extends \advanced_testcase {
    /**
     * Plugin copies remain while the scan is pending and are removed after completion.
     */
    public function test_copy_removed_after_terminal_scan(): void {
        $this->resetAfterTest();
        $course = $this->getDataGenerator()->create_course();
        $teacher = $this->getDataGenerator()->create_and_enrol($course, 'editingteacher');
        $context = \context_course::instance($course->id);
        $provider = new fake_provider();
        $provider->lookupresult = new file_lookup_result(
            true,
            str_repeat('b', 64),
            ['malicious' => 0, 'suspicious' => 0, 'undetected' => 8]
        );
        $service = $this->make_service($provider);
        $manual = new manual_scan(
            $service,
            new plugin_config(true, 1048576, false),
            new test_credentials('unit-test-key')
        );

        $pendingprovider = new fake_provider();
        $pendingservice = $this->make_service($pendingprovider);
        $pendingmanual = new manual_scan(
            $pendingservice,
            new plugin_config(true, 1048576, false),
            new test_credentials('unit-test-key')
        );
        $pendingscan = $pendingmanual->queue_stored_file(
            $this->create_file('pending.bin', 'pending'),
            $context,
            (int) $teacher->id
        );
        $pendingfile = get_file_storage()->get_file_by_id((int) $pendingscan->fileid);
        $this->assertNotFalse($pendingfile);
        $this->assertTrue(plugin_file_lifecycle::is_plugin_copy($pendingfile));

        $scan = $manual->queue_stored_file($this->create_file('done.bin', 'done'), $context, (int) $teacher->id);
        $copyid = (int) $scan->fileid;
        $this->assertNotFalse(get_file_storage()->get_file_by_id($copyid));
        $service->process_scan((int) $scan->id);
        $this->assertFalse(get_file_storage()->get_file_by_id($copyid));
        $this->assertNotFalse(get_file_storage()->get_file_by_id((int) $pendingscan->fileid));
    }

    /**
     * Assignment files are never deleted by plugin copy cleanup.
     */
    public function test_unrelated_files_are_not_deleted(): void {
        $this->resetAfterTest();
        $fs = get_file_storage();
        $assignfile = $fs->create_file_from_string([
            'contextid' => \context_system::instance()->id,
            'component' => 'assignsubmission_file',
            'filearea' => 'submission_files',
            'itemid' => random_int(1, 1000000),
            'filepath' => '/',
            'filename' => 'keep.bin',
        ], 'keep');
        $provider = new fake_provider();
        $provider->lookupresult = new file_lookup_result(
            true,
            str_repeat('c', 64),
            ['malicious' => 0, 'suspicious' => 0, 'undetected' => 4]
        );
        $service = $this->make_service($provider);
        $scan = $service->queue_file_scan($assignfile, scan_source::ASSIGN, 4);
        $this->assertSame(scan_status::CLEAN, $scan->status);
        $this->assertNotFalse($fs->get_file_by_id($assignfile->get_id()));
    }

    /**
     * Cleanup is idempotent and missing copies are not fatal.
     */
    public function test_cleanup_is_idempotent(): void {
        $this->resetAfterTest();
        $record = (object) [
            'fileid' => 0,
            'pathnamehash' => str_repeat('0', 40),
            'component' => 'antivirus_verdict',
            'filearea' => manual_scan::FILEAREA,
        ];
        plugin_file_lifecycle::delete_copy_for_scan($record);
        plugin_file_lifecycle::delete_copy_for_scan($record);
        $this->assertNull(plugin_file_lifecycle::resolve_plugin_copy($record));
    }

    /**
     * A completed manual scan cannot be rescanned after its copy is deleted.
     */
    public function test_rescan_disabled_after_manual_copy_cleanup(): void {
        $this->resetAfterTest();
        $course = $this->getDataGenerator()->create_course();
        $teacher = $this->getDataGenerator()->create_and_enrol($course, 'editingteacher');
        $context = \context_course::instance($course->id);
        $provider = new fake_provider();
        $provider->lookupresult = new file_lookup_result(
            true,
            str_repeat('d', 64),
            ['malicious' => 0, 'suspicious' => 0, 'undetected' => 3]
        );
        $service = $this->make_service($provider);
        $manual = new manual_scan(
            $service,
            new plugin_config(true, 1048576, false),
            new test_credentials('unit-test-key')
        );
        $scan = $manual->queue_stored_file($this->create_file('manual.bin', 'manual'), $context, (int) $teacher->id);
        $service->process_scan((int) $scan->id);
        $completed = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame(scan_status::CLEAN, $completed->status);

        $adapter = new rescan(
            $service,
            new plugin_config(true, 1048576, false),
            new scan_repository(),
            new test_credentials('unit-test-key')
        );
        $this->assertFalse($adapter->file_available($completed));
        $this->assertFalse($adapter->is_eligible($completed));
    }

    /**
     * ZIP plugin copies stay until archive inspection publishes a final verdict.
     */
    public function test_archive_copy_kept_until_member_extraction(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        set_config('archivescan', 1, 'antivirus_verdict');
        $course = $this->getDataGenerator()->create_course();
        $teacher = $this->getDataGenerator()->create_and_enrol($course, 'editingteacher');
        $context = \context_course::instance($course->id);
        $provider = new fake_provider();
        $provider->lookupresult = new file_lookup_result(
            true,
            str_repeat('e', 64),
            ['malicious' => 0, 'suspicious' => 0, 'undetected' => 64]
        );
        $service = $this->make_service($provider);
        $manual = new manual_scan(
            $service,
            plugin_config::from_site_config(),
            new test_credentials('unit-test-key')
        );
        $zippath = \antivirus_verdict\tests\archive_test_helper::fixtures_dir() . '/lifecycle.zip';
        $this->assertTrue(\antivirus_verdict\tests\archive_test_helper::write_zip($zippath, [
            'test-clean.jpg' => 'clean-jpg-bytes',
        ]));
        $src = get_file_storage()->create_file_from_pathname([
            'contextid' => \context_system::instance()->id,
            'component' => 'user',
            'filearea' => 'draft',
            'itemid' => file_get_unused_draft_itemid(),
            'filepath' => '/',
            'filename' => 'lifecycle.zip',
        ], $zippath);
        $scan = $manual->queue_stored_file($src, $context, (int) $teacher->id);
        $copyid = (int) $scan->fileid;
        $service->process_scan((int) $scan->id);
        $completed = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame(scan_status::PENDING, $completed->status);
        $this->assertSame(scan_phase::COMPLETED, $completed->phase);
        $this->assertSame(0, (int) $completed->timecompleted);
        $this->assertNotFalse(get_file_storage()->get_file_by_id($copyid));
        $this->assertSame(\antivirus_verdict\archive_outcome::PROCESSING, $completed->archiveoutcome);

        $scanner = new \antivirus_verdict\local\archive_scanner($service, plugin_config::from_site_config());
        $scanner->process_container((int) $scan->id);
        $this->assertNotFalse(get_file_storage()->get_file_by_id($copyid));
        $children = (new scan_repository())->find_children_by_parent((int) $scan->id);
        $this->assertNotEmpty($children);
        $this->assertSame('test-clean.jpg', reset($children)->filename);
        $this->assertFalse($service->process_scan((int) reset($children)->id));
        $finished = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame(scan_status::CLEAN, $finished->status);
        $this->assertSame(\antivirus_verdict\archive_outcome::COMPLETE, $finished->archiveoutcome);
        $this->assertFalse(get_file_storage()->get_file_by_id($copyid));
    }

    /**
     * Uninstall deletes plugin-owned copies and leaves assignment files.
     */
    public function test_uninstall_removes_plugin_copies_only(): void {
        global $CFG, $DB;

        $this->resetAfterTest();
        $user = $this->getDataGenerator()->create_user();
        $course = $this->getDataGenerator()->create_course();
        $context = \context_course::instance($course->id);
        $fs = get_file_storage();
        $copy = $fs->create_file_from_string([
            'contextid' => $context->id,
            'component' => 'antivirus_verdict',
            'filearea' => 'manual',
            'itemid' => 21,
            'filepath' => '/',
            'filename' => 'copy.bin',
            'userid' => $user->id,
        ], 'copy-bytes');
        $assign = $fs->create_file_from_string([
            'contextid' => $context->id,
            'component' => 'assignsubmission_file',
            'filearea' => 'submission_files',
            'itemid' => 22,
            'filepath' => '/',
            'filename' => 'keep.bin',
            'userid' => $user->id,
        ], 'keep-bytes');

        require_once($CFG->dirroot . '/lib/antivirus/verdict/db/uninstall.php');
        $this->assertTrue(xmldb_antivirus_verdict_uninstall());
        $this->assertFalse($fs->get_file_by_id($copy->get_id()));
        $this->assertNotFalse($fs->get_file_by_id($assign->get_id()));
        $this->assertTrue($DB->get_manager()->table_exists('antivirus_verdict_scans'));
        $this->assertTrue(xmldb_antivirus_verdict_uninstall());
    }

    /**
     * Build the scan engine.
     *
     * @param fake_provider $provider Fake provider.
     * @return scan_service
     */
    private function make_service(fake_provider $provider): scan_service {
        return new scan_service(
            $provider,
            new scan_repository(),
            new file_hasher(),
            new plugin_config(true, 1048576, false),
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
            'component' => 'user',
            'filearea' => 'draft',
            'itemid' => random_int(1, 100000000),
            'filepath' => '/',
            'filename' => $filename,
        ], $content);
    }
}
