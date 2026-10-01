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
use antivirus_verdict\local\archive_extractor;
use antivirus_verdict\local\archive_limits;
use antivirus_verdict\local\archive_orchestrator;
use antivirus_verdict\local\archive_scanner;
use antivirus_verdict\local\file_hasher;
use antivirus_verdict\local\plugin_config;
use antivirus_verdict\local\scan_repository;
use antivirus_verdict\local\scan_service;
use antivirus_verdict\provider\file_lookup_result;
use antivirus_verdict\provider\provider_exception;
use antivirus_verdict\tests\archive_test_helper;
use antivirus_verdict\tests\fake_provider;
use antivirus_verdict\tests\recording_scheduler;

/**
 * Wave 3 consolidation: MBZ, encryption, dedup, provider errors on archive members.
 *
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @coversNothing
 */
final class archive_consolidation_test extends \advanced_testcase {
    /**
     * Encrypted ZIP fixtures are rejected as uninspectable when ZipArchive reports encryption.
     */
    public function test_encrypted_zip_is_uninspectable(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $path = archive_test_helper::fixtures_dir() . '/encrypted.zip';
        if (!archive_test_helper::write_encrypted_zip($path)) {
            $this->markTestSkipped('ZipArchive encryption APIs unavailable in this PHP build');
        }
        $extractor = new archive_extractor(new archive_limits(50, 1, 1024 * 1024, 1024 * 1024));
        $work = make_temp_directory('avvencrypted');
        $result = $extractor->extract_zip_path($path, $work);
        $this->assertTrue($result->uninspectable);
        $this->assertSame('error_archive_encrypted', $result->reason);
        $this->assertSame([], $result->members);
    }

    /**
     * Moodle .mbz backups use the same bounded ZIP engine as .zip.
     */
    public function test_mbz_extracts_members(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $mbz = archive_test_helper::fixtures_dir() . '/course.mbz';
        $this->assertTrue(archive_test_helper::write_zip($mbz, [
            'course.xml' => '<course id="1"/>',
            'sections/section.xml' => '<section/>',
        ]));
        $extractor = new archive_extractor(new archive_limits(50, 1, 1024 * 1024, 1024 * 1024));
        $work = make_temp_directory('avvmbz');
        $result = $extractor->extract_zip_path($mbz, $work);
        $this->assertTrue($result->hasscanmembers);
        $this->assertCount(2, $result->members);
    }

    /**
     * process_container on an MBZ stored file queues child scans with archive source.
     */
    public function test_process_mbz_container_queues_members(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');

        $mbzpath = archive_test_helper::fixtures_dir() . '/backup.mbz';
        archive_test_helper::write_zip($mbzpath, ['moodle_backup.xml' => '<backup/>']);

        $fs = get_file_storage();
        $file = $fs->create_file_from_pathname([
            'contextid' => \context_system::instance()->id,
            'component' => 'user',
            'filearea' => 'draft',
            'itemid' => file_get_unused_draft_itemid(),
            'filepath' => '/',
            'filename' => 'backup.mbz',
        ], $mbzpath);

        $provider = new fake_provider();
        $service = new scan_service(
            $provider,
            new scan_repository(),
            new file_hasher(),
            new plugin_config(true, 1024 * 1024),
            new recording_scheduler()
        );
        $repo = new scan_repository();
        $parentid = $repo->insert($this->parent_row($file));
        $parent = $repo->get_by_id($parentid);
        $parent->archiveoutcome = archive_outcome::PROCESSING;
        $repo->update($parent);

        (new archive_scanner($service, plugin_config::from_site_config()))->process_container($parentid);

        $children = $repo->find_children_by_parent($parentid);
        $this->assertCount(1, $children);
        $this->assertSame(scan_source::ARCHIVE, reset($children)->source);
        $this->assertStringContainsString('/archive/', (string) reset($children)->filepath);
    }

    /**
     * Identical member content reuses a completed SHA-256 verdict (one provider lookup).
     */
    public function test_duplicate_member_content_reuses_sha256_verdict(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');

        $payload = 'duplicate-archive-payload-bytes';
        $provider = new fake_provider();
        $provider->lookupresult = new file_lookup_result(
            true,
            hash('sha256', $payload),
            ['malicious' => 0, 'suspicious' => 0, 'undetected' => 1, 'harmless' => 70, 'timeout' => 0]
        );
        $repo = new scan_repository();
        $service = new scan_service(
            $provider,
            $repo,
            new file_hasher(),
            plugin_config::from_site_config(),
            new recording_scheduler()
        );

        $fs = get_file_storage();
        $context = \context_system::instance();
        $draft = file_get_unused_draft_itemid();
        $filea = $fs->create_file_from_string([
            'contextid' => $context->id,
            'component' => 'user',
            'filearea' => 'draft',
            'itemid' => $draft,
            'filepath' => '/',
            'filename' => 'a.bin',
        ], $payload);
        $fileb = $fs->create_file_from_string([
            'contextid' => $context->id,
            'component' => 'user',
            'filearea' => 'draft',
            'itemid' => $draft,
            'filepath' => '/',
            'filename' => 'b.bin',
        ], $payload);

        $parentid = $repo->insert($this->parent_row($filea));

        $first = $service->queue_file_scan($filea, scan_source::ARCHIVE, 2, false, $parentid, '/archive/a/');
        $this->assertSame(scan_status::CLEAN, $first->status);
        $this->assertSame(1, $provider->lookupcount);

        $second = $service->queue_file_scan($fileb, scan_source::ARCHIVE, 2, false, $parentid, '/archive/b/');
        $this->assertSame(scan_status::CLEAN, $second->status);
        $this->assertSame(1, $provider->lookupcount);
        $this->assertNotEquals((int) $first->id, (int) $second->id);
        $this->assertSame('/archive/a/', $first->filepath);
        $this->assertSame('/archive/b/', $second->filepath);
        $this->assertSame($parentid, (int) $second->parentscanid);
    }

    /**
     * Provider failure on a member propagates to the parent aggregate (not clean).
     */
    public function test_member_provider_error_elevates_parent(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');

        $provider = new fake_provider();
        $provider->lookupexception = new provider_exception('error_auth', '', 401);
        $repo = new scan_repository();
        $service = new scan_service(
            $provider,
            $repo,
            new file_hasher(),
            plugin_config::from_site_config(),
            new recording_scheduler()
        );

        $fs = get_file_storage();
        $file = $fs->create_file_from_string([
            'contextid' => \context_system::instance()->id,
            'component' => 'user',
            'filearea' => 'draft',
            'itemid' => file_get_unused_draft_itemid(),
            'filepath' => '/',
            'filename' => 'member.bin',
        ], 'member-bytes');

        $parentid = $repo->insert($this->parent_row($file));
        $parent = $repo->get_by_id($parentid);
        $parent->archiveoutcome = archive_outcome::PROCESSING;
        $repo->update($parent);

        $member = $fs->create_file_from_string([
            'contextid' => \context_system::instance()->id,
            'component' => 'user',
            'filearea' => 'draft',
            'itemid' => file_get_unused_draft_itemid(),
            'filepath' => '/',
            'filename' => 'member.bin',
        ], 'member-bytes');
        $child = $service->queue_file_scan($member, scan_source::ARCHIVE, 2, false, $parentid, '/archive/member.bin');
        $this->assertSame(scan_status::ERROR, $child->status);

        $updated = $repo->get_by_id($parentid);
        $this->assertSame(scan_status::ERROR, $updated->status);
        $this->assertSame('error_auth', $updated->errorcode);
        $this->assertSame(archive_outcome::COMPLETE, $updated->archiveoutcome);
    }

    /**
     * Open-circuit style provider unavailability leaves member pending, never clean.
     */
    public function test_member_provider_unavailable_is_not_clean(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        $provider = new fake_provider();
        $provider->lookupexception = new provider_exception('error_providerunavailable');
        $service = new scan_service(
            $provider,
            new scan_repository(),
            new file_hasher(),
            new plugin_config(true, 1024 * 1024),
            new recording_scheduler()
        );
        $file = get_file_storage()->create_file_from_string([
            'contextid' => \context_system::instance()->id,
            'component' => 'user',
            'filearea' => 'draft',
            'itemid' => file_get_unused_draft_itemid(),
            'filepath' => '/',
            'filename' => 'circuit.bin',
        ], 'c');
        $scan = $service->queue_file_scan($file, scan_source::ARCHIVE, 0, false, 99, '/archive/circuit.bin');
        $this->assertNotSame(scan_status::CLEAN, $scan->status);
        $this->assertSame(scan_status::PENDING, $scan->status);
    }

    /**
     * Symlink ZIP fixtures are not reliably creatable on Windows/ZipArchive; code uses in-memory extraction only.
     */
    public function test_symlink_zip_fixture_not_supported_on_this_platform(): void {
        if (PHP_OS_FAMILY === 'Windows') {
            $this->markTestSkipped(
                'Windows ZipArchive does not provide a portable symlink-in-zip fixture; extraction uses getFromIndex only.'
            );
        }
        $this->markTestSkipped('Symlink-in-zip regression is platform-dependent; manual review on Unix CI if added later.');
    }

    /**
     * Internal helper.
     *
     * @param \stored_file $file Container file.
     * @return \stdClass
     */
    private function parent_row(\stored_file $file): \stdClass {
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
        $row->sha256 = str_repeat('p', 64);
        $row->filesize = $file->get_filesize();
        $row->mimetype = $file->get_mimetype();
        $row->status = scan_status::CLEAN;
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
