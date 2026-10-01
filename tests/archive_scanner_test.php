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

namespace antivirus_verdict;

use antivirus_verdict\archive_outcome;
use antivirus_verdict\local\archive_orchestrator;
use antivirus_verdict\local\archive_scanner;
use antivirus_verdict\local\file_hasher;
use antivirus_verdict\local\plugin_config;
use antivirus_verdict\local\plugin_file_lifecycle;
use antivirus_verdict\local\scan_repository;
use antivirus_verdict\local\scan_service;
use antivirus_verdict\provider\file_lookup_result;
use antivirus_verdict\tests\archive_test_helper;
use antivirus_verdict\tests\fake_provider;
use antivirus_verdict\tests\recording_scheduler;

/**
 * Tests for archive scanning.
 *
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @covers \antivirus_verdict\local\archive_scanner
 */
final class archive_scanner_test extends \advanced_testcase {
    /**
     * ZIP filenames are treated as containers.
     */
    public function test_is_zip_container_by_extension(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        $fs = get_file_storage();
        $context = \context_system::instance();
        $file = $fs->create_file_from_string([
            'contextid' => $context->id,
            'component' => 'user',
            'filearea' => 'draft',
            'itemid' => file_get_unused_draft_itemid(),
            'filepath' => '/',
            'filename' => 'bundle.zip',
        ], 'PK');
        $scanner = archive_scanner::from_site_config();
        $this->assertTrue($scanner->is_zip_container($file));
    }

    /**
     * Archive scanning respects the archivescan setting.
     */
    public function test_maybe_scan_respects_disabled_setting(): void {
        $this->resetAfterTest();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        set_config('archivescan', 0, 'antivirus_verdict');
        $scanner = archive_scanner::from_site_config();
        $record = (object) ['id' => 1, 'userid' => 2, 'source' => scan_source::MANUAL, 'parentscanid' => 0];
        $scanner->maybe_scan_container($record, null);
        $this->assertTrue(true);
    }

    /**
     * A normal HTML file must not be marked as an unsupported archive after VT completes.
     */
    public function test_html_does_not_trigger_archive_unsupported_error(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        $fs = get_file_storage();
        $file = $fs->create_file_from_string([
            'contextid' => \context_system::instance()->id,
            'component' => 'user',
            'filearea' => 'draft',
            'itemid' => file_get_unused_draft_itemid(),
            'filepath' => '/',
            'filename' => 'portfolio-track-notice.html',
        ], '<!DOCTYPE html><html><body>notice</body></html>');
        $repo = new scan_repository();
        $parentid = $repo->insert($this->minimal_row($file, scan_status::CLEAN));
        $parent = $repo->get_by_id($parentid);
        archive_scanner::from_site_config()->maybe_scan_container($parent, $file);
        $updated = $repo->get_by_id((int) $parent->id);
        $this->assertSame(scan_status::CLEAN, $updated->status);
        $this->assertNull($updated->errorcode);
        $this->assertSame(archive_outcome::NONE, $updated->archiveoutcome);
    }

    /**
     * Unsupported 7z containers are marked uninspectable, not silently skipped.
     */
    public function test_unsupported_7z_marks_parent(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        $fs = get_file_storage();
        $file = $fs->create_file_from_string([
            'contextid' => \context_system::instance()->id,
            'component' => 'user',
            'filearea' => 'draft',
            'itemid' => file_get_unused_draft_itemid(),
            'filepath' => '/',
            'filename' => 'data.7z',
        ], '7z-bytes');
        $repo = new scan_repository();
        $parentid = $repo->insert($this->minimal_row($file, scan_status::CLEAN));
        $parent = $repo->get_by_id($parentid);
        archive_scanner::from_site_config()->maybe_scan_container($parent, $file);
        $updated = $repo->get_by_id((int) $parent->id);
        $this->assertSame(archive_outcome::UNSUPPORTED, $updated->archiveoutcome);
        $this->assertNotSame(scan_status::CLEAN, $updated->status);
    }

    /**
     * process_container queues member scans for a valid zip.
     */
    public function test_process_container_queues_members(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        $zippath = archive_test_helper::fixtures_dir() . '/queue.zip';
        archive_test_helper::write_zip($zippath, ['member.txt' => 'hello-member']);
        $fs = get_file_storage();
        $file = $fs->create_file_from_pathname([
            'contextid' => \context_system::instance()->id,
            'component' => 'user',
            'filearea' => 'draft',
            'itemid' => file_get_unused_draft_itemid(),
            'filepath' => '/',
            'filename' => 'queue.zip',
        ], $zippath);

        $provider = new fake_provider();
        $scheduler = new recording_scheduler();
        $service = new scan_service(
            $provider,
            new scan_repository(),
            new file_hasher(),
            new plugin_config(true, 1024 * 1024),
            $scheduler
        );
        $repo = new scan_repository();
        $parentid = $repo->insert($this->minimal_row($file, scan_status::CLEAN));
        $parent = $repo->get_by_id($parentid);
        $parent->archiveoutcome = archive_outcome::PROCESSING;
        $repo->update($parent);

        $scanner = new archive_scanner($service, plugin_config::from_site_config());
        $scanner->process_container($parentid);

        $children = $repo->find_children_by_parent($parentid);
        $this->assertNotEmpty($children);
        $this->assertSame(scan_source::ARCHIVE, reset($children)->source);
    }

    /**
     * Deleting the plugin ZIP before process_container is the live Error 0/N failure mode.
     */
    public function test_missing_plugin_copy_marks_invalidfile(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        set_config('archivescan', 1, 'antivirus_verdict');
        $file = $this->create_plugin_zip(['test-clean.jpg' => 'clean-jpg-bytes']);
        $repo = new scan_repository();
        $parentid = $repo->insert($this->minimal_row($file, scan_status::CLEAN));
        $parent = $repo->get_by_id($parentid);
        $parent->archiveoutcome = archive_outcome::PROCESSING;
        $parent->malicious = 0;
        $parent->totalengines = 64;
        $repo->update($parent);
        $file->delete();

        $scanner = new archive_scanner($this->make_service(new fake_provider()), plugin_config::from_site_config());
        $scanner->process_container($parentid);

        $updated = $repo->get_by_id($parentid);
        $this->assertSame(scan_status::ERROR, $updated->status);
        $this->assertSame('error_invalidfile', $updated->errorcode);
        $this->assertSame(64, (int) $updated->totalengines);
        $this->assertEmpty($repo->find_children_by_parent($parentid));
    }

    /**
     * Outer ZIP VT clean must not skip member extraction when the plugin copy is kept.
     */
    public function test_clean_zip_member_is_queued_and_aggregated_clean(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        set_config('archivescan', 1, 'antivirus_verdict');

        $memberbytes = 'clean-jpg-bytes';
        $file = $this->create_plugin_zip(['test-clean.jpg' => $memberbytes]);
        $copyid = $file->get_id();
        $provider = new fake_provider();
        $cleanstats = ['malicious' => 0, 'suspicious' => 0, 'undetected' => 40, 'harmless' => 10, 'timeout' => 0];
        $provider->lookupresult = new file_lookup_result(true, str_repeat('a', 64), $cleanstats);
        $service = $this->make_service($provider);
        $repo = new scan_repository();
        $parentid = $repo->insert($this->minimal_row($file, scan_status::CLEAN));
        $parent = $repo->get_by_id($parentid);
        $parent->malicious = 0;
        $parent->totalengines = 64;
        $repo->update($parent);

        $scanner = new archive_scanner($service, plugin_config::from_site_config());
        $this->assertTrue($scanner->maybe_scan_container($repo->get_by_id($parentid), $file));
        $this->assertNotFalse(get_file_storage()->get_file_by_id($copyid));

        $scanner->process_container($parentid);
        $this->assertNotFalse(get_file_storage()->get_file_by_id($copyid));

        $children = $repo->find_children_by_parent($parentid);
        $this->assertCount(1, $children);
        $child = reset($children);
        $this->assertSame('test-clean.jpg', $child->filename);
        $this->assertSame(scan_source::ARCHIVE, $child->source);
        $this->assertGreaterThan(0, (int) $child->fileid);

        $this->assertFalse($service->process_scan((int) $child->id));
        $finished = $repo->get_by_id((int) $child->id);
        $this->assertSame(scan_status::CLEAN, $finished->status);

        (new archive_orchestrator($repo))->maybe_finalize_parent($parentid);
        $updated = $repo->get_by_id($parentid);
        $this->assertSame(scan_status::CLEAN, $updated->status);
        $this->assertNotSame('error_invalidfile', $updated->errorcode);
        $this->assertSame(archive_outcome::COMPLETE, $updated->archiveoutcome);
        $this->assertFalse(get_file_storage()->get_file_by_id($copyid));
    }

    /**
     * A malicious member dominates a clean outer ZIP VirusTotal result.
     */
    public function test_malicious_member_dominates_outer_clean_vt(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        set_config('archivescan', 1, 'antivirus_verdict');

        $clean = 'clean-jpg-bytes';
        $bad = 'malicious-member-bytes';
        $file = $this->create_plugin_zip([
            'clean.jpg' => $clean,
            'eicar.com.txt' => $bad,
        ]);
        $provider = new fake_provider();
        $cleanstats = ['malicious' => 0, 'suspicious' => 0, 'undetected' => 40, 'harmless' => 10, 'timeout' => 0];
        $badstats = ['malicious' => 42, 'suspicious' => 0, 'undetected' => 21, 'harmless' => 0, 'timeout' => 0];
        $provider->lookupsbyhash[hash('sha256', $clean)] = new file_lookup_result(true, hash('sha256', $clean), $cleanstats);
        $provider->lookupsbyhash[hash('sha256', $bad)] = new file_lookup_result(true, hash('sha256', $bad), $badstats);
        $provider->lookupresult = new file_lookup_result(true, str_repeat('c', 64), $cleanstats);

        $service = $this->make_service($provider);
        $repo = new scan_repository();
        $parentid = $repo->insert($this->minimal_row($file, scan_status::CLEAN));
        $parent = $repo->get_by_id($parentid);
        $parent->archiveoutcome = archive_outcome::PROCESSING;
        $parent->totalengines = 64;
        $repo->update($parent);

        $scanner = new archive_scanner($service, plugin_config::from_site_config());
        $scanner->process_container($parentid);
        $children = $repo->find_children_by_parent($parentid);
        $this->assertCount(2, $children);
        foreach ($children as $child) {
            $this->assertFalse($service->process_scan((int) $child->id));
        }
        (new archive_orchestrator($repo))->maybe_finalize_parent($parentid);
        $updated = $repo->get_by_id($parentid);
        $this->assertSame(scan_status::MALICIOUS, $updated->status);
        $this->assertNotSame('error_invalidfile', $updated->errorcode);
    }

    /**
     * MBZ uses the same extraction and member-queue path as ZIP.
     */
    public function test_mbz_plugin_copy_queues_members(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        set_config('archivescan', 1, 'antivirus_verdict');
        $file = $this->create_plugin_zip(['moodle_backup.xml' => '<backup/>'], 'course.mbz');
        $this->assertSame('mbz', (new \antivirus_verdict\local\archive_extractor(
            \antivirus_verdict\local\archive_limits::from_site_config(plugin_config::from_site_config())
        ))->detect_format($file));
        $repo = new scan_repository();
        $parentid = $repo->insert($this->minimal_row($file, scan_status::CLEAN));
        $parent = $repo->get_by_id($parentid);
        $parent->archiveoutcome = archive_outcome::PROCESSING;
        $repo->update($parent);
        $scanner = new archive_scanner($this->make_service(new fake_provider()), plugin_config::from_site_config());
        $scanner->process_container($parentid);
        $children = $repo->find_children_by_parent($parentid);
        $this->assertCount(1, $children);
        $this->assertSame('moodle_backup.xml', reset($children)->filename);
    }

    /**
     * Nested ZIP members are extracted only within the configured depth.
     */
    public function test_nested_zip_respects_configured_depth(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        set_config('archivescan', 1, 'antivirus_verdict');
        set_config('archivemaxdepth', 1, 'antivirus_verdict');

        $innerpath = archive_test_helper::fixtures_dir() . '/inner-depth.zip';
        $this->assertTrue(archive_test_helper::write_zip($innerpath, ['nested.jpg' => 'nested-clean']));
        $outerpath = archive_test_helper::fixtures_dir() . '/outer-depth.zip';
        $this->assertTrue(archive_test_helper::write_zip($outerpath, [
            'readme.txt' => 'outer-clean',
            'inner.zip' => file_get_contents($innerpath),
        ]));
        $fs = get_file_storage();
        $file = $fs->create_file_from_pathname([
            'contextid' => \context_system::instance()->id,
            'component' => 'antivirus_verdict',
            'filearea' => plugin_file_lifecycle::GATE_FILEAREA,
            'itemid' => random_int(1, 100000000),
            'filepath' => '/',
            'filename' => 'outer.zip',
        ], $outerpath);
        $repo = new scan_repository();
        $parentid = $repo->insert($this->minimal_row($file, scan_status::CLEAN));
        $parent = $repo->get_by_id($parentid);
        $parent->archiveoutcome = archive_outcome::PROCESSING;
        $repo->update($parent);
        $scanner = new archive_scanner($this->make_service(new fake_provider()), plugin_config::from_site_config());
        $scanner->process_container($parentid);
        $names = array_map(static fn($row) => $row->filename, $repo->find_children_by_parent($parentid));
        $this->assertContains('readme.txt', $names);
        $this->assertContains('nested.jpg', $names);
    }

    /**
     * Build a scan engine with a fake provider.
     *
     * @param fake_provider $provider Fake provider.
     * @return scan_service
     */
    private function make_service(fake_provider $provider): scan_service {
        return new scan_service(
            $provider,
            new scan_repository(),
            new file_hasher(),
            plugin_config::from_site_config(),
            new recording_scheduler()
        );
    }

    /**
     * Create a plugin-owned ZIP/MBZ used as a manual or gate copy.
     *
     * @param array<string,string> $entries Archive members.
     * @param string $filename Container filename.
     * @return \stored_file
     */
    private function create_plugin_zip(array $entries, string $filename = 'bundle.zip'): \stored_file {
        $zippath = archive_test_helper::fixtures_dir() . '/' . $filename;
        $this->assertTrue(archive_test_helper::write_zip($zippath, $entries));
        $fs = get_file_storage();
        return $fs->create_file_from_pathname([
            'contextid' => \context_system::instance()->id,
            'component' => 'antivirus_verdict',
            'filearea' => plugin_file_lifecycle::GATE_FILEAREA,
            'itemid' => random_int(1, 100000000),
            'filepath' => '/',
            'filename' => $filename,
        ], $zippath);
    }

    /**
     * Internal helper.
     *
     * @param \stored_file $file File.
     * @param string $status Status.
     * @return \stdClass
     */
    private function minimal_row(\stored_file $file, string $status): \stdClass {
        $row = new \stdClass();
        $row->fileid = $file->get_id();
        $row->contenthash = $file->get_contenthash();
        $row->pathnamehash = $file->get_pathnamehash();
        $row->contextid = $file->get_contextid();
        $row->courseid = 0;
        $row->component = $file->get_component();
        $row->filearea = $file->get_filearea();
        $row->itemid = $file->get_itemid();
        $row->filepath = $file->get_filepath();
        $row->filename = $file->get_filename();
        $row->userid = 2;
        $row->source = scan_source::MANUAL;
        $row->sha256 = str_repeat('b', 64);
        $row->filesize = $file->get_filesize();
        $row->mimetype = $file->get_mimetype();
        $row->status = $status;
        $row->phase = scan_phase::COMPLETED;
        $row->vtanalysisid = null;
        $row->vtfileid = null;
        $row->malicious = 0;
        $row->suspicious = 0;
        $row->undetected = 0;
        $row->harmless = 0;
        $row->timeout = 0;
        $row->totalengines = 0;
        $row->errorcode = null;
        $row->enforcement = enforcement_state::NONE;
        $row->pollattempts = 0;
        $row->timelastpoll = 0;
        $row->timesubmitted = 0;
        $row->timecreated = time();
        $row->timemodified = time();
        $row->timecompleted = time();
        $row->parentscanid = 0;
        $row->archiveoutcome = archive_outcome::NONE;
        return $row;
    }
}
