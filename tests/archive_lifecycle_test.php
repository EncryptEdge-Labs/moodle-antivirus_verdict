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
use antivirus_verdict\local\bulk_scan_service;
use antivirus_verdict\local\file_hasher;
use antivirus_verdict\local\plugin_config;
use antivirus_verdict\local\plugin_file_lifecycle;
use antivirus_verdict\local\scan_presenter;
use antivirus_verdict\local\scan_repository;
use antivirus_verdict\local\scan_service;
use antivirus_verdict\provider\file_lookup_result;
use antivirus_verdict\provider\provider_exception;
use antivirus_verdict\tests\archive_test_helper;
use antivirus_verdict\tests\fake_provider;
use antivirus_verdict\tests\member_enqueue_failing_service;
use antivirus_verdict\tests\recording_enforcer;
use antivirus_verdict\tests\recording_notifier;
use antivirus_verdict\tests\environment_debugging_trait;
use antivirus_verdict\tests\recording_scheduler;

/**
 * Archive lifecycle invariants: publication, reuse, recovery, and notification.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @covers \antivirus_verdict\local\scan_service
 * @covers \antivirus_verdict\local\archive_scanner
 * @covers \antivirus_verdict\local\archive_orchestrator
 * @covers \antivirus_verdict\local\scan_repository
 * @covers \antivirus_verdict\local\antivirus_gate
 */
final class archive_lifecycle_test extends \advanced_testcase {
    use environment_debugging_trait;

    /**
     * A clean provider result on a ZIP stays pending until members finish.
     */
    public function test_clean_zip_stays_pending_until_members_are_clean(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        set_config('archivescan', 1, 'antivirus_verdict');

        $provider = new fake_provider();
        $provider->lookupresult = new file_lookup_result(true, str_repeat('a', 64), $this->clean_stats());
        $service = $this->make_service($provider);
        $file = $this->plugin_zip(['photo.jpg' => 'jpg-bytes']);
        $scan = $service->queue_file_scan($file, scan_source::MANUAL, 2);
        $this->assertFalse($service->process_scan((int) $scan->id));

        $repo = new scan_repository();
        $parent = $repo->get_by_id((int) $scan->id);
        $this->assertSame(scan_status::PENDING, $parent->status);
        $this->assertSame(scan_phase::COMPLETED, $parent->phase);
        $this->assertSame(archive_outcome::PROCESSING, $parent->archiveoutcome);
        $this->assertSame(0, (int) $parent->timecompleted);
        $this->assertSame(0, (int) $parent->malicious);
        $this->assertGreaterThan(0, (int) $parent->totalengines);
        $this->assertNull($repo->find_completed_verdict_by_sha256((string) $parent->sha256));

        $scanner = new archive_scanner($service, plugin_config::from_site_config());
        $scanner->process_container((int) $parent->id);
        $children = $repo->find_children_by_parent((int) $parent->id);
        $this->assertCount(1, $children);
        $child = reset($children);
        $this->assertFalse($service->process_scan((int) $child->id));
        $child = $repo->get_by_id((int) $child->id);
        $this->assertNotSame('', (string) $child->sha256);

        $finished = $repo->get_by_id((int) $parent->id);
        $this->assertSame(scan_status::CLEAN, $finished->status);
        $this->assertSame(archive_outcome::COMPLETE, $finished->archiveoutcome);
        $this->assertGreaterThan(0, (int) $finished->timecompleted);
        $this->assertSame(0, (int) $finished->malicious);
        $member = $repo->get_by_id((int) $child->id);
        $this->assertSame(hash('sha256', 'jpg-bytes'), $member->sha256);
        $this->assertSame(scan_status::CLEAN, $member->status);
    }

    /**
     * A malicious member dominates a pending clean container.
     */
    public function test_clean_zip_malicious_member_finalises_malicious(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        set_config('archivescan', 1, 'antivirus_verdict');

        $clean = 'clean-jpg-bytes';
        $bad = 'malicious-member-bytes';
        $provider = new fake_provider();
        $provider->lookupsbyhash[hash('sha256', $clean)] = new file_lookup_result(
            true,
            hash('sha256', $clean),
            $this->clean_stats()
        );
        $provider->lookupsbyhash[hash('sha256', $bad)] = new file_lookup_result(true, hash('sha256', $bad), [
            'malicious' => 4, 'suspicious' => 0, 'undetected' => 10, 'harmless' => 0, 'timeout' => 0,
        ]);
        $provider->lookupresult = new file_lookup_result(true, str_repeat('b', 64), $this->clean_stats());
        $service = $this->make_service($provider);
        $file = $this->plugin_zip(['photo.jpg' => $clean, 'eicar.com.txt' => $bad]);
        $repo = new scan_repository();
        $parentid = $repo->insert($this->row_for_file($file, scan_status::PENDING));
        $parent = $repo->get_by_id($parentid);
        $parent->archiveoutcome = archive_outcome::PROCESSING;
        $parent->phase = scan_phase::COMPLETED;
        $parent->malicious = 0;
        $parent->suspicious = 0;
        $parent->undetected = 10;
        $parent->harmless = 1;
        $parent->timeout = 0;
        $parent->totalengines = 11;
        $parent->timecompleted = 0;
        $repo->update($parent);

        (new archive_scanner($service, plugin_config::from_site_config()))->process_container($parentid);
        foreach ($repo->find_children_by_parent($parentid) as $child) {
            $this->assertFalse($service->process_scan((int) $child->id));
        }
        $finished = $repo->get_by_id($parentid);
        $this->assertSame(scan_status::MALICIOUS, $finished->status);
        $this->assertSame(archive_outcome::COMPLETE, $finished->archiveoutcome);
        $this->assertSame(0, (int) $finished->malicious);
        $this->assertSame(11, (int) $finished->totalengines);
    }

    /**
     * An already malicious provider verdict is not weakened by clean members.
     */
    public function test_malicious_outer_is_not_downgraded(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        set_config('archivescan', 1, 'antivirus_verdict');
        $provider = new fake_provider();
        $provider->lookupresult = new file_lookup_result(true, str_repeat('c', 64), $this->clean_stats());
        $service = $this->make_service($provider);
        $file = $this->plugin_zip(['photo.jpg' => 'clean-jpg-bytes']);
        $repo = new scan_repository();
        $parentid = $repo->insert($this->row_for_file($file, scan_status::MALICIOUS));
        $parent = $repo->get_by_id($parentid);
        $parent->archiveoutcome = archive_outcome::PROCESSING;
        $parent->malicious = 3;
        $parent->undetected = 20;
        $parent->totalengines = 23;
        $parent->enforcement = enforcement_state::QUARANTINED;
        $repo->update($parent);

        (new archive_scanner($service, plugin_config::from_site_config()))->process_container($parentid);
        foreach ($repo->find_children_by_parent($parentid) as $child) {
            $this->assertFalse($service->process_scan((int) $child->id));
        }
        $finished = $repo->get_by_id($parentid);
        $this->assertSame(scan_status::MALICIOUS, $finished->status);
        $this->assertSame(archive_outcome::COMPLETE, $finished->archiveoutcome);
        $this->assertSame(3, (int) $finished->malicious);
    }

    /**
     * Empty, malformed, and encrypted archives are errors, never clean.
     */
    public function test_unreadable_archives_are_extract_errors(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        set_config('archivescan', 1, 'antivirus_verdict');
        $service = $this->make_service(new fake_provider());
        $scanner = new archive_scanner($service, plugin_config::from_site_config());
        $repo = new scan_repository();

        $emptypath = archive_test_helper::fixtures_dir() . '/empty-lifecycle.zip';
        $this->assertTrue(archive_test_helper::write_dir_only_zip($emptypath));
        $empty = $this->store_path($emptypath, 'empty.zip');
        $emptyid = $this->processing_parent($repo, $empty);
        $scanner->process_container($emptyid);
        $emptied = $repo->get_by_id($emptyid);
        $this->assertSame(scan_status::ERROR, $emptied->status);
        $this->assertSame(archive_outcome::EXTRACT_ERROR, $emptied->archiveoutcome);
        $this->assertSame('error_archive_empty', $emptied->errorcode);

        $broken = $this->plugin_bytes('broken.zip', 'this is not a zip');
        $brokenid = $this->processing_parent($repo, $broken);
        $scanner->process_container($brokenid);
        $broke = $repo->get_by_id($brokenid);
        $this->assertSame(scan_status::ERROR, $broke->status);
        $this->assertSame(archive_outcome::EXTRACT_ERROR, $broke->archiveoutcome);
        $this->assertNotSame(scan_status::CLEAN, $broke->status);

        $encpath = archive_test_helper::fixtures_dir() . '/encrypted-lifecycle.zip';
        if (!archive_test_helper::write_encrypted_zip($encpath)) {
            return;
        }
        $encrypted = $this->store_path($encpath, 'encrypted.zip');
        $encid = $this->processing_parent($repo, $encrypted);
        $scanner->process_container($encid);
        $enc = $repo->get_by_id($encid);
        $this->assertSame(scan_status::ERROR, $enc->status);
        $this->assertSame(archive_outcome::EXTRACT_ERROR, $enc->archiveoutcome);
        $this->assertSame('error_archive_encrypted', $enc->errorcode);
    }

    /**
     * A second archive pass does not duplicate children or invent error_invalidfile.
     */
    public function test_process_container_is_idempotent_when_children_exist(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        set_config('archivescan', 1, 'antivirus_verdict');
        $service = $this->make_service(new fake_provider());
        $scanner = new archive_scanner($service, plugin_config::from_site_config());
        $repo = new scan_repository();
        $file = $this->plugin_zip(['a.txt' => 'alpha', 'b.txt' => 'beta']);
        $copyid = $file->get_id();
        $parentid = $this->processing_parent($repo, $file);

        $scanner->process_container($parentid);
        $first = $repo->find_children_by_parent($parentid);
        $this->assertCount(2, $first);
        $this->assertNotFalse(get_file_storage()->get_file_by_id($copyid));

        $scanner->process_container($parentid);
        $second = $repo->find_children_by_parent($parentid);
        $this->assertCount(2, $second);
        $parent = $repo->get_by_id($parentid);
        $this->assertNotSame('error_invalidfile', (string) $parent->errorcode);
        $this->assertSame(archive_outcome::PROCESSING, $parent->archiveoutcome);
        $this->assertNotFalse(get_file_storage()->get_file_by_id($copyid));
    }

    /**
     * A missing container with no children is an extraction error.
     */
    public function test_missing_copy_without_children_is_invalidfile(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        set_config('archivescan', 1, 'antivirus_verdict');
        $file = $this->plugin_zip(['a.txt' => 'alpha']);
        $repo = new scan_repository();
        $parentid = $this->processing_parent($repo, $file);
        $file->delete();
        (new archive_scanner($this->make_service(new fake_provider()), plugin_config::from_site_config()))
            ->process_container($parentid);
        $parent = $repo->get_by_id($parentid);
        $this->assertSame(scan_status::ERROR, $parent->status);
        $this->assertSame(archive_outcome::EXTRACT_ERROR, $parent->archiveoutcome);
        $this->assertSame('error_invalidfile', $parent->errorcode);
        $this->assertSame(11, (int) $parent->totalengines);
    }

    /**
     * A missing container copy plus existing children must not finalise clean.
     */
    public function test_missing_copy_with_terminal_children_is_not_clean(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        set_config('archivescan', 1, 'antivirus_verdict');
        $provider = new fake_provider();
        $service = $this->make_service($provider);
        $repo = new scan_repository();

        $file = $this->plugin_zip(['photo.jpg' => 'jpg-bytes'], 'partial.zip');
        $parentid = $this->processing_parent($repo, $file);
        $child = $this->row_for_file($file, scan_status::CLEAN);
        $child->parentscanid = $parentid;
        $child->phase = scan_phase::COMPLETED;
        $child->filename = 'photo.jpg';
        $child->filepath = '/archive/';
        $child->source = scan_source::ARCHIVE;
        $repo->insert($child);
        $file->delete();

        (new archive_scanner($service, plugin_config::from_site_config()))->process_container($parentid);
        $parent = $repo->get_by_id($parentid);
        $this->assertSame(scan_status::ERROR, $parent->status);
        $this->assertSame(archive_outcome::INCOMPLETE, $parent->archiveoutcome);
        $this->assertSame('error_invalidfile', $parent->errorcode);
        $this->assertNotSame(scan_status::CLEAN, $parent->status);
        $this->assertSame(0, $provider->lookupcount);

        $recoverfile = $this->plugin_zip(['other.jpg' => 'other'], 'recover-partial.zip');
        $recoverid = $this->processing_parent($repo, $recoverfile);
        $recoverchild = $this->row_for_file($recoverfile, scan_status::CLEAN);
        $recoverchild->parentscanid = $recoverid;
        $recoverchild->phase = scan_phase::COMPLETED;
        $recoverchild->filename = 'other.jpg';
        $recoverchild->filepath = '/archive/';
        $recoverchild->source = scan_source::ARCHIVE;
        $repo->insert($recoverchild);
        $recoverfile->delete();
        $this->age_row($recoverid);

        $service->recover_stale_scans(time());
        $recovered = $repo->get_by_id($recoverid);
        $this->assertSame(scan_status::ERROR, $recovered->status);
        $this->assertSame(archive_outcome::INCOMPLETE, $recovered->archiveoutcome);
        $this->assertNotSame(scan_status::CLEAN, $recovered->status);
        $this->assertSame(0, $provider->lookupcount);
    }

    /**
     * A later archive pass does not extract again when any child already exists.
     */
    public function test_partial_children_queue_only_missing_paths(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        set_config('archivescan', 1, 'antivirus_verdict');
        $file = $this->plugin_zip(['a.txt' => 'alpha', 'b.txt' => 'beta']);
        $repo = new scan_repository();
        $parentid = $this->processing_parent($repo, $file);
        $existing = $this->row_for_file($file, scan_status::PENDING);
        $existing->parentscanid = $parentid;
        $existing->filename = 'a.txt';
        $existing->filepath = '/archive/';
        $existing->source = scan_source::ARCHIVE;
        $existing->phase = scan_phase::QUEUED;
        $repo->insert($existing);

        (new archive_scanner($this->make_service(new fake_provider()), plugin_config::from_site_config()))
            ->process_container($parentid);
        $names = array_map(static fn($row): string => (string) $row->filename, $repo->find_children_by_parent($parentid));
        sort($names);
        $this->assertSame(['a.txt'], $names);
        $parent = $repo->get_by_id($parentid);
        $this->assertSame(archive_outcome::INCOMPLETE, $parent->archiveoutcome);
        $this->assertSame('error_archive_member', $parent->errorcode);
        $this->assertNotSame(scan_status::CLEAN, $parent->status);

        $children = $repo->find_children_by_parent($parentid);
        $only = reset($children);
        $only->status = scan_status::CLEAN;
        $only->phase = scan_phase::COMPLETED;
        $only->timecompleted = time();
        $repo->update($only);
        (new archive_orchestrator($repo, null, new recording_notifier()))->maybe_finalize_parent($parentid);
        $finished = $repo->get_by_id($parentid);
        $this->assertSame(scan_status::ERROR, $finished->status);
        $this->assertSame(archive_outcome::INCOMPLETE, $finished->archiveoutcome);
        $this->assertNotSame(scan_status::CLEAN, $finished->status);
        $left = array_map(
            static fn($row): string => (string) $row->filename,
            $repo->find_children_by_parent($parentid)
        );
        sort($left);
        $this->assertSame(['a.txt'], array_values($left));
    }

    /**
     * A full child set still finalises normally and is not extracted again.
     */
    public function test_complete_child_coverage_finalises_normally(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        set_config('archivescan', 1, 'antivirus_verdict');
        $file = $this->plugin_zip(['a.txt' => 'alpha', 'b.txt' => 'beta', 'c.txt' => 'gamma']);
        $repo = new scan_repository();
        $parentid = $this->processing_parent($repo, $file);
        foreach (['a.txt', 'b.txt', 'c.txt'] as $name) {
            $child = $this->row_for_file($file, scan_status::CLEAN);
            $child->parentscanid = $parentid;
            $child->filename = $name;
            $child->filepath = '/archive/';
            $child->source = scan_source::ARCHIVE;
            $child->phase = scan_phase::COMPLETED;
            $repo->insert($child);
        }
        (new archive_scanner($this->make_service(new fake_provider()), plugin_config::from_site_config()))
            ->process_container($parentid);
        $names = array_map(static fn($row): string => (string) $row->filename, $repo->find_children_by_parent($parentid));
        sort($names);
        $this->assertSame(['a.txt', 'b.txt', 'c.txt'], $names);
        $parent = $repo->get_by_id($parentid);
        $this->assertSame(scan_status::CLEAN, $parent->status);
        $this->assertSame(archive_outcome::COMPLETE, $parent->archiveoutcome);
    }

    /**
     * Partial children and a missing copy cannot become a clean parent.
     */
    public function test_partial_children_without_copy_cannot_become_clean(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        set_config('archivescan', 1, 'antivirus_verdict');
        $file = $this->plugin_zip(['a.txt' => 'alpha', 'b.txt' => 'beta', 'c.txt' => 'gamma'], 'missing-cover.zip');
        $repo = new scan_repository();
        $parentid = $this->processing_parent($repo, $file);
        foreach (['a.txt', 'b.txt'] as $name) {
            $child = $this->row_for_file($file, scan_status::CLEAN);
            $child->parentscanid = $parentid;
            $child->filename = $name;
            $child->filepath = '/archive/';
            $child->source = scan_source::ARCHIVE;
            $child->phase = scan_phase::COMPLETED;
            $repo->insert($child);
        }
        $file->delete();
        (new archive_scanner($this->make_service(new fake_provider()), plugin_config::from_site_config()))
            ->process_container($parentid);
        $names = array_map(static fn($row): string => (string) $row->filename, $repo->find_children_by_parent($parentid));
        sort($names);
        $this->assertSame(['a.txt', 'b.txt'], $names);
        $parent = $repo->get_by_id($parentid);
        $this->assertSame(scan_status::ERROR, $parent->status);
        $this->assertSame(archive_outcome::INCOMPLETE, $parent->archiveoutcome);
        $this->assertNotSame(scan_status::CLEAN, $parent->status);
    }

    /**
     * A valid member plus an unsafe member cannot publish a clean complete archive.
     */
    public function test_mixed_valid_and_unsafe_member_is_not_clean(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        set_config('archivescan', 1, 'antivirus_verdict');
        $path = archive_test_helper::fixtures_dir() . '/mixed-unsafe.zip';
        archive_test_helper::write_stored_entries($path, [
            'ok.txt' => 'ok-bytes',
            '../evil.txt' => 'secret',
        ]);
        $file = $this->store_path($path, 'mixed-unsafe.zip');
        $provider = new fake_provider();
        $provider->lookupresult = new file_lookup_result(true, str_repeat('a', 64), $this->clean_stats());
        $service = $this->make_service($provider);
        $repo = new scan_repository();
        $parentid = $this->processing_parent($repo, $file);
        (new archive_scanner($service, plugin_config::from_site_config()))->process_container($parentid);

        $children = $repo->find_children_by_parent($parentid);
        $byname = [];
        foreach ($children as $child) {
            $byname[(string) $child->filename] = $child;
        }
        $this->assertArrayHasKey('ok.txt', $byname);
        $this->assertArrayHasKey('evil.txt', $byname);
        $this->assertSame('error_archive_member', $byname['evil.txt']->errorcode);
        $this->assertSame(scan_status::ERROR, $byname['evil.txt']->status);
        $open = $repo->get_by_id($parentid);
        $this->assertNotSame(scan_status::CLEAN, $open->status);
        $this->assertNotSame(archive_outcome::COMPLETE, $open->archiveoutcome);
        $this->assertSame(archive_outcome::INCOMPLETE, $open->archiveoutcome);
        $this->assertSame('error_archive_member', $open->errorcode);

        $this->assertFalse($service->process_scan((int) $byname['ok.txt']->id));
        $finished = $repo->get_by_id($parentid);
        $this->assertSame(scan_status::CLEAN, $repo->get_by_id((int) $byname['ok.txt']->id)->status);
        $this->assertSame(scan_status::ERROR, $finished->status);
        $this->assertSame(archive_outcome::INCOMPLETE, $finished->archiveoutcome);
        $this->assertNotSame(scan_status::CLEAN, $finished->status);
        $this->assertNotSame(archive_outcome::COMPLETE, $finished->archiveoutcome);
        $evil = null;
        foreach ($repo->find_children_by_parent($parentid) as $child) {
            if ((string) $child->filename === 'evil.txt') {
                $evil = $child;
            }
        }
        $this->assertNotNull($evil);
        $this->assertSame('error_archive_member', $evil->errorcode);
    }

    /**
     * A malicious member still outranks an unextractable member.
     */
    public function test_malicious_member_wins_over_unextractable_member(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        set_config('archivescan', 1, 'antivirus_verdict');
        $path = archive_test_helper::fixtures_dir() . '/mixed-malicious.zip';
        archive_test_helper::write_stored_entries($path, [
            'ok.txt' => 'ok-bytes',
            'virus.txt' => 'virus-bytes',
            '../evil.txt' => 'secret',
        ]);
        $file = $this->store_path($path, 'mixed-malicious.zip');
        $provider = new fake_provider();
        $provider->lookupsbyhash[hash('sha256', 'ok-bytes')] = new file_lookup_result(
            true,
            hash('sha256', 'ok-bytes'),
            $this->clean_stats()
        );
        $provider->lookupsbyhash[hash('sha256', 'virus-bytes')] = new file_lookup_result(
            true,
            hash('sha256', 'virus-bytes'),
            ['malicious' => 4, 'suspicious' => 0, 'undetected' => 8, 'harmless' => 0, 'timeout' => 0]
        );
        $service = $this->make_service($provider);
        $repo = new scan_repository();
        $parentid = $this->processing_parent($repo, $file);
        (new archive_scanner($service, plugin_config::from_site_config()))->process_container($parentid);
        foreach ($repo->find_children_by_parent($parentid) as $child) {
            if ((string) $child->status === scan_status::ERROR) {
                $this->assertSame('evil.txt', $child->filename);
                continue;
            }
            $this->assertFalse($service->process_scan((int) $child->id));
        }
        $parent = $repo->get_by_id($parentid);
        $this->assertSame(scan_status::MALICIOUS, $parent->status);
        $this->assertNotSame(scan_status::CLEAN, $parent->status);
        $this->assertNotSame(archive_outcome::COMPLETE, $parent->archiveoutcome);
        $kept = false;
        foreach ($repo->find_children_by_parent($parentid) as $child) {
            if ((string) $child->filename === 'evil.txt') {
                $kept = (string) $child->errorcode === 'error_archive_member';
            }
        }
        $this->assertTrue($kept);
    }

    /**
     * A member that extracts but cannot be queued stays visible and blocks clean.
     */
    public function test_member_enqueue_failure_is_recorded_and_blocks_clean(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        set_config('archivescan', 1, 'antivirus_verdict');
        $provider = new fake_provider();
        $provider->lookupresult = new file_lookup_result(true, str_repeat('b', 64), $this->clean_stats());
        $service = new member_enqueue_failing_service(
            $provider,
            new scan_repository(),
            new file_hasher(),
            plugin_config::from_site_config(),
            new recording_scheduler()
        );
        $service->failfilename = 'fail.txt';
        $file = $this->plugin_zip(['ok.txt' => 'ok-bytes', 'fail.txt' => 'fail-bytes'], 'enqueue-fail.zip');
        $repo = new scan_repository();
        $parentid = $this->processing_parent($repo, $file);
        (new archive_scanner($service, plugin_config::from_site_config()))->process_container($parentid);
        $this->assertDebuggingCalled('antivirus_verdict archive member queue failed: fail.txt');

        $byname = [];
        foreach ($repo->find_children_by_parent($parentid) as $child) {
            $byname[(string) $child->filename] = $child;
        }
        $this->assertSame(scan_status::ERROR, $byname['fail.txt']->status);
        $this->assertSame('error_archive_member', $byname['fail.txt']->errorcode);
        $this->assertSame(scan_phase::FAILED, $byname['fail.txt']->phase);
        global $DB;
        $this->assertFalse($DB->record_exists('files', [
            'filename' => 'fail.txt',
            'component' => 'antivirus_verdict',
            'filearea' => plugin_file_lifecycle::GATE_FILEAREA,
        ]));
        $this->assertTrue($DB->record_exists('files', [
            'filename' => 'ok.txt',
            'component' => 'antivirus_verdict',
            'filearea' => plugin_file_lifecycle::GATE_FILEAREA,
        ]));

        $this->assertFalse($service->process_scan((int) $byname['ok.txt']->id));
        $parent = $repo->get_by_id($parentid);
        $this->assertSame(scan_status::CLEAN, $repo->get_by_id((int) $byname['ok.txt']->id)->status);
        $this->assertSame(scan_status::ERROR, $parent->status);
        $this->assertSame(archive_outcome::INCOMPLETE, $parent->archiveoutcome);
        $this->assertNotSame(scan_status::CLEAN, $parent->status);
        $this->assertSame(0, $provider->uploadcount);
    }

    /**
     * An enqueue failure does not hide a malicious member.
     */
    public function test_enqueue_failure_does_not_outrank_malicious_member(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        set_config('archivescan', 1, 'antivirus_verdict');
        $provider = new fake_provider();
        $provider->lookupsbyhash[hash('sha256', 'ok-bytes')] = new file_lookup_result(
            true,
            hash('sha256', 'ok-bytes'),
            $this->clean_stats()
        );
        $provider->lookupsbyhash[hash('sha256', 'virus-bytes')] = new file_lookup_result(
            true,
            hash('sha256', 'virus-bytes'),
            ['malicious' => 3, 'suspicious' => 0, 'undetected' => 4, 'harmless' => 0, 'timeout' => 0]
        );
        $service = new member_enqueue_failing_service(
            $provider,
            new scan_repository(),
            new file_hasher(),
            plugin_config::from_site_config(),
            new recording_scheduler()
        );
        $service->failfilename = 'fail.txt';
        $file = $this->plugin_zip([
            'ok.txt' => 'ok-bytes',
            'virus.txt' => 'virus-bytes',
            'fail.txt' => 'fail-bytes',
        ], 'enqueue-malicious.zip');
        $repo = new scan_repository();
        $parentid = $this->processing_parent($repo, $file);
        (new archive_scanner($service, plugin_config::from_site_config()))->process_container($parentid);
        $this->assertDebuggingCalled('antivirus_verdict archive member queue failed: fail.txt');
        foreach ($repo->find_children_by_parent($parentid) as $child) {
            if ((string) $child->filename === 'fail.txt') {
                $this->assertSame(scan_status::ERROR, $child->status);
                continue;
            }
            $this->assertFalse($service->process_scan((int) $child->id));
        }
        $parent = $repo->get_by_id($parentid);
        $this->assertSame(scan_status::MALICIOUS, $parent->status);
        $this->assertNotSame(scan_status::CLEAN, $parent->status);
        $this->assertNotSame(archive_outcome::COMPLETE, $parent->archiveoutcome);
    }

    /**
     * A second manual scan of the same archive SHA joins the open inspection.
     */
    public function test_manual_scan_reuses_open_container_across_pathnames(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        set_config('archivescan', 1, 'antivirus_verdict');
        $provider = new fake_provider();
        $provider->lookupresult = new file_lookup_result(true, str_repeat('c', 64), $this->clean_stats());
        $service = $this->make_service($provider);
        $file = $this->plugin_zip(['photo.jpg' => 'jpg-bytes'], 'first.zip');
        $scan = $service->queue_file_scan($file, scan_source::MANUAL, 2);
        $this->assertFalse($service->process_scan((int) $scan->id));
        $repo = new scan_repository();
        $parent = $repo->get_by_id((int) $scan->id);
        $this->assertSame(archive_outcome::PROCESSING, $parent->archiveoutcome);
        $this->assertSame(scan_status::PENDING, $parent->status);
        $lookups = $provider->lookupcount;
        global $DB;
        $tasks = $DB->count_records_select('task_adhoc', 'classname LIKE ?', ['%process_archive%']);

        $second = $this->store_path(
            archive_test_helper::fixtures_dir() . '/first.zip',
            'second.zip'
        );
        $reused = $service->queue_file_scan($second, scan_source::MANUAL, 2);
        $this->assertSame((int) $parent->id, (int) $reused->id);
        $this->assertSame($lookups, $provider->lookupcount);
        $this->assertSame($tasks, $DB->count_records_select('task_adhoc', 'classname LIKE ?', ['%process_archive%']));
        $rows = $DB->get_records('antivirus_verdict_scans', ['sha256' => $parent->sha256, 'parentscanid' => 0]);
        $this->assertCount(1, $rows);
        $this->assertSame(archive_outcome::PROCESSING, $repo->get_by_id((int) $parent->id)->archiveoutcome);
        $this->assertNotSame(scan_status::CLEAN, $repo->get_by_id((int) $parent->id)->status);

        $samepath = $service->queue_file_scan($file, scan_source::MANUAL, 2);
        $this->assertSame((int) $parent->id, (int) $samepath->id);
        $this->assertSame($lookups, $provider->lookupcount);

        $plain = $this->plugin_bytes('note.txt', 'plain-bytes');
        $plainb = $this->plugin_bytes('note-copy.txt', 'plain-bytes');
        $firstplain = $service->queue_file_scan($plain, scan_source::MANUAL, 2);
        $secondplain = $service->queue_file_scan($plainb, scan_source::MANUAL, 2);
        $this->assertNotSame((int) $firstplain->id, (int) $secondplain->id);
    }

    /**
     * Open clean and suspicious containers are not reusable. Malicious processing is.
     */
    public function test_repository_reuse_rules(): void {
        $this->resetAfterTest();
        $repo = new scan_repository();
        $sha = str_repeat('d', 64);
        $cases = [
            [scan_status::CLEAN, archive_outcome::NONE, true],
            [scan_status::CLEAN, archive_outcome::COMPLETE, true],
            [scan_status::CLEAN, archive_outcome::PROCESSING, false],
            [scan_status::SUSPICIOUS, archive_outcome::PROCESSING, false],
            [scan_status::PENDING, archive_outcome::PROCESSING, false],
            [scan_status::MALICIOUS, archive_outcome::PROCESSING, true],
            [scan_status::MALICIOUS, archive_outcome::COMPLETE, true],
            [scan_status::ERROR, archive_outcome::COMPLETE, false],
            [scan_status::CLEAN, archive_outcome::INCOMPLETE, false],
        ];
        foreach ($cases as [$status, $outcome, $reusable]) {
            global $DB;
            $DB->delete_records('antivirus_verdict_scans');
            $row = $this->bare_row($status, $sha);
            $row->archiveoutcome = $outcome;
            $row->phase = scan_phase::COMPLETED;
            $repo->insert($row);
            $found = $repo->find_completed_verdict_by_sha256($sha);
            if ($reusable) {
                $this->assertNotNull($found, $status . '/' . $outcome);
                $this->assertSame($status, $found->status);
            } else {
                $this->assertNull($found, $status . '/' . $outcome);
            }
        }
    }

    /**
     * A completed container whose archive is still processing blocks a second pathname scan.
     */
    public function test_processing_container_is_active_by_pathnamehash(): void {
        $this->resetAfterTest();
        $repo = new scan_repository();
        $hash = str_repeat('e', 40);
        $row = $this->bare_row(scan_status::PENDING, str_repeat('f', 64));
        $row->pathnamehash = $hash;
        $row->phase = scan_phase::COMPLETED;
        $row->archiveoutcome = archive_outcome::PROCESSING;
        $id = $repo->insert($row);
        $found = $repo->find_active_by_pathnamehash($hash);
        $this->assertNotNull($found);
        $this->assertEquals($id, $found->id);
    }

    /**
     * Legacy clean rows that are still processing are not purged.
     */
    public function test_processing_container_is_not_a_retention_candidate(): void {
        $this->resetAfterTest();
        $repo = new scan_repository();
        $row = $this->bare_row(scan_status::CLEAN, str_repeat('1', 64));
        $row->phase = scan_phase::COMPLETED;
        $row->archiveoutcome = archive_outcome::PROCESSING;
        $row->timecompleted = time() - (400 * DAYSECS);
        $row->timemodified = $row->timecompleted;
        $row->timecreated = $row->timecompleted;
        $id = $repo->insert($row);
        $repo->update($repo->get_by_id($id));
        $stored = $repo->get_by_id($id);
        $stored->timecompleted = time() - (400 * DAYSECS);
        $stored->timemodified = $stored->timecompleted;
        $repo->update($stored);
        // Update() stamps timemodified to now, so set the old timestamps directly.
        global $DB;
        $DB->set_field('antivirus_verdict_scans', 'timemodified', time() - (400 * DAYSECS), ['id' => $id]);
        $DB->set_field('antivirus_verdict_scans', 'timecompleted', time() - (400 * DAYSECS), ['id' => $id]);
        $cutoff = time() - (30 * DAYSECS);
        $ids = array_map(static fn($candidate): int => (int) $candidate->id, $repo->find_retention_candidates($cutoff, 50));
        $this->assertNotContains($id, $ids);
    }

    /**
     * Stale archive recovery never calls the provider.
     */
    public function test_archive_recovery_does_not_call_provider(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        set_config('archivescan', 1, 'antivirus_verdict');
        $provider = new fake_provider();
        $service = $this->make_service($provider);
        $repo = new scan_repository();

        $file = $this->plugin_zip(['photo.jpg' => 'jpg-bytes']);
        $requeueid = $this->processing_parent($repo, $file);
        $this->age_row($requeueid);

        $terminalfile = $this->plugin_zip(['done.jpg' => 'done-bytes'], 'done.zip');
        $terminalid = $this->processing_parent($repo, $terminalfile);
        $child = $this->row_for_file($terminalfile, scan_status::CLEAN);
        $child->parentscanid = $terminalid;
        $child->phase = scan_phase::COMPLETED;
        $child->filename = 'done.jpg';
        $child->filepath = '/archive/';
        $child->source = scan_source::ARCHIVE;
        $repo->insert($child);
        $this->age_row($terminalid);

        $missing = $this->plugin_zip(['gone.jpg' => 'gone'], 'gone.zip');
        $missingid = $this->processing_parent($repo, $missing);
        $missing->delete();
        $this->age_row($missingid);

        $partial = $this->plugin_zip(['part.jpg' => 'part'], 'part.zip');
        $partialid = $this->processing_parent($repo, $partial);
        $openchild = $this->row_for_file($partial, scan_status::PENDING);
        $openchild->parentscanid = $partialid;
        $openchild->phase = scan_phase::QUEUED;
        $openchild->filename = 'part.jpg';
        $openchild->filepath = '/archive/';
        $openchild->source = scan_source::ARCHIVE;
        $repo->insert($openchild);
        $partial->delete();
        $this->age_row($partialid);

        $handled = $service->recover_stale_scans(time());
        $this->assertGreaterThan(0, $handled);
        $this->assertSame(0, $provider->lookupcount);

        global $DB;
        $tasks = $DB->get_records_select('task_adhoc', 'classname LIKE :name', ['name' => '%process_archive%']);
        $this->assertNotEmpty($tasks);

        $requued = $repo->get_by_id($requeueid);
        $this->assertSame(archive_outcome::PROCESSING, $requued->archiveoutcome);
        $this->assertNotSame(scan_status::ERROR, $requued->status);

        $done = $repo->get_by_id($terminalid);
        $this->assertSame(scan_status::CLEAN, $done->status);
        $this->assertSame(archive_outcome::COMPLETE, $done->archiveoutcome);

        $lost = $repo->get_by_id($missingid);
        $this->assertSame(scan_status::ERROR, $lost->status);
        $this->assertSame(archive_outcome::EXTRACT_ERROR, $lost->archiveoutcome);
        $this->assertSame('error_invalidfile', $lost->errorcode);

        $open = $repo->get_by_id($partialid);
        $this->assertSame(archive_outcome::INCOMPLETE, $open->archiveoutcome);
        $this->assertNotSame(scan_status::CLEAN, $open->status);
        $this->assertSame('error_invalidfile', $open->errorcode);
    }

    /**
     * The native gate accepts a known-clean ZIP without calling it a final clean verdict.
     */
    public function test_gate_known_clean_zip_is_pending_not_clean(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        set_config('archivescan', 1, 'antivirus_verdict');
        $path = archive_test_helper::fixtures_dir() . '/gate-clean.zip';
        $this->assertTrue(archive_test_helper::write_zip($path, ['photo.jpg' => 'jpg-bytes']));
        $provider = new fake_provider();
        $provider->lookupresult = new file_lookup_result(true, str_repeat('9', 64), $this->clean_stats());
        $scanner = $this->make_gate_scanner($provider);
        $this->assertSame(scanner::SCAN_RESULT_OK, $scanner->scan_file($path, 'bundle.zip'));
        $this->assertStringContainsString('not a final verdict', $scanner->get_scanning_notice());

        global $DB;
        $row = $DB->get_record('antivirus_verdict_scans', ['filename' => 'bundle.zip'], '*', MUST_EXIST);
        $this->assertSame(scan_status::PENDING, $row->status);
        $this->assertSame(scan_phase::COMPLETED, $row->phase);
        $this->assertSame(archive_outcome::PROCESSING, $row->archiveoutcome);
        $this->assertSame(0, (int) $row->timecompleted);
        $this->assertGreaterThan(0, (int) $row->totalengines);
        $this->assertGreaterThan(0, (int) $row->fileid);
    }

    /**
     * A known malicious ZIP is still refused synchronously.
     */
    public function test_gate_known_malicious_zip_is_found(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        set_config('archivescan', 1, 'antivirus_verdict');
        $path = archive_test_helper::fixtures_dir() . '/gate-bad.zip';
        $this->assertTrue(archive_test_helper::write_zip($path, ['eicar.com.txt' => 'bad']));
        $provider = new fake_provider();
        $provider->lookupresult = new file_lookup_result(true, str_repeat('8', 64), [
            'malicious' => 5, 'suspicious' => 0, 'undetected' => 10, 'harmless' => 0, 'timeout' => 0,
        ]);
        $scanner = $this->make_gate_scanner($provider);
        $this->assertSame(scanner::SCAN_RESULT_FOUND, $scanner->scan_file($path, 'bad.zip'));
        global $DB;
        $row = $DB->get_record('antivirus_verdict_scans', ['filename' => 'bad.zip'], '*', MUST_EXIST);
        $this->assertSame(scan_status::MALICIOUS, $row->status);
        $this->assertNotSame(archive_outcome::PROCESSING, (string) $row->archiveoutcome);
    }

    /**
     * An open clean container is not copied as the verdict for a second upload.
     */
    public function test_gate_does_not_copy_processing_clean_zip(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        set_config('archivescan', 1, 'antivirus_verdict');
        $path = archive_test_helper::fixtures_dir() . '/gate-open.zip';
        $this->assertTrue(archive_test_helper::write_zip($path, ['photo.jpg' => 'jpg-bytes']));
        $sha = (new file_hasher())->hash_path($path);
        $repo = new scan_repository();
        $open = $this->bare_row(scan_status::CLEAN, $sha);
        $open->phase = scan_phase::COMPLETED;
        $open->archiveoutcome = archive_outcome::PROCESSING;
        $open->filename = 'already.zip';
        $repo->insert($open);

        $provider = new fake_provider();
        $provider->lookupresult = new file_lookup_result(true, $sha, $this->clean_stats());
        $scanner = $this->make_gate_scanner($provider);
        $this->assertSame(scanner::SCAN_RESULT_OK, $scanner->scan_file($path, 'second.zip'));
        $this->assertSame(0, $provider->lookupcount);
        global $DB;
        $rows = $DB->get_records('antivirus_verdict_scans', ['sha256' => $sha], 'id ASC');
        $this->assertCount(1, $rows);
        $only = reset($rows);
        $this->assertSame('already.zip', $only->filename);
        $this->assertSame(archive_outcome::PROCESSING, $only->archiveoutcome);
        $this->assertStringContainsString(
            get_string('archiveinspectionqueued', 'antivirus_verdict'),
            $scanner->get_scanning_notice()
        );
    }

    /**
     * Container notifications wait for a terminal user-facing verdict.
     */
    public function test_notification_timing_for_containers_and_children(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        set_config('archivescan', 1, 'antivirus_verdict');

        $notifier = new recording_notifier();
        $provider = new fake_provider();
        $provider->lookupresult = new file_lookup_result(true, str_repeat('a', 64), $this->clean_stats());
        $service = $this->make_service($provider, $notifier);
        $file = $this->plugin_zip(['photo.jpg' => 'jpg-bytes'], 'notify.zip');
        $scan = $service->queue_file_scan($file, scan_source::MANUAL, 2);
        $this->assertFalse($service->process_scan((int) $scan->id));
        $this->assertSame(0, $notifier->calls);

        $repo = new scan_repository();
        $parent = $repo->get_by_id((int) $scan->id);
        $child = $this->row_for_file($file, scan_status::CLEAN);
        $child->parentscanid = (int) $parent->id;
        $child->phase = scan_phase::COMPLETED;
        $child->filename = 'photo.jpg';
        $child->filepath = '/archive/';
        $child->source = scan_source::ARCHIVE;
        $repo->insert($child);
        $orchestrator = new archive_orchestrator($repo, null, $notifier);
        $orchestrator->maybe_finalize_parent((int) $parent->id);
        $this->assertSame(1, $notifier->calls);
        $this->assertSame(scan_status::CLEAN, $notifier->statuses[0]);
        $orchestrator->maybe_finalize_parent((int) $parent->id);
        $this->assertSame(1, $notifier->calls);

        $childnotifier = new recording_notifier();
        $childprovider = new fake_provider();
        $childprovider->lookupresult = new file_lookup_result(true, str_repeat('b', 64), $this->clean_stats());
        $childservice = $this->make_service($childprovider, $childnotifier);
        $member = $this->plugin_bytes('member.bin', 'member-bytes');
        $childservice->queue_file_scan($member, scan_source::ARCHIVE, 2, false, (int) $parent->id, '/archive/member.bin');
        $this->assertSame(0, $childnotifier->calls);
    }

    /**
     * A throwing notifier cannot change a persisted verdict.
     */
    public function test_throwing_notifier_does_not_change_verdict(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        set_config('archivescan', 0, 'antivirus_verdict');
        $notifier = new recording_notifier();
        $notifier->throw = true;
        $provider = new fake_provider();
        $provider->lookupresult = new file_lookup_result(true, str_repeat('c', 64), [
            'malicious' => 2, 'suspicious' => 0, 'undetected' => 4, 'harmless' => 0, 'timeout' => 0,
        ]);
        $service = $this->make_service($provider, $notifier);
        $file = $this->plugin_bytes('eicar.bin', 'bad-bytes');
        $scan = $service->queue_file_scan($file, scan_source::MANUAL, 2);
        $this->assertFalse($service->process_scan((int) $scan->id));
        $stored = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame(scan_status::MALICIOUS, $stored->status);
        $this->assertSame(scan_phase::COMPLETED, $stored->phase);
        $this->assertSame(1, $notifier->calls);
        $this->assertSame(0, (int) $stored->pollattempts);
        $this->assert_verdict_debugging_with_optional_environment_noise('antivirus_verdict notification hook failed');
    }

    /**
     * Provider counts on an archive row are labelled as a provider report.
     */
    public function test_presenter_does_not_treat_provider_counts_as_archive_verdict(): void {
        $this->resetAfterTest();
        $scan = (object) [
            'status' => scan_status::ERROR,
            'malicious' => 0,
            'totalengines' => 66,
            'archiveoutcome' => archive_outcome::EXTRACT_ERROR,
            'errorcode' => 'error_archive_corrupt',
            'sha256' => '',
            'filename' => 'pack.zip',
        ];
        $compact = scan_presenter::detection_compact($scan);
        $this->assertStringContainsString('Provider', $compact);
        $this->assertStringContainsString('0', $compact);
        $this->assertStringContainsString('66', $compact);
        $this->assertNotSame(
            get_string('detectioncompact', 'antivirus_verdict', (object) ['malicious' => 0, 'total' => 66]),
            $compact
        );
        $pending = (object) [
            'status' => scan_status::PENDING,
            'archiveoutcome' => archive_outcome::PROCESSING,
            'errorcode' => null,
            'filename' => 'pack.zip',
        ];
        [$message, $level] = scan_presenter::manual_submit_notification($pending);
        $this->assertSame(get_string('archiveinspectionqueued', 'antivirus_verdict'), $message);
        $this->assertNotSame(get_string('scanclean', 'antivirus_verdict'), $message);
        $this->assertSame(\core\output\notification::NOTIFY_INFO, $level);
    }

    /**
     * Bulk skip uses the repository rule and does not treat an open container as finished.
     */
    public function test_bulk_does_not_treat_processing_container_as_completed(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $this->resetAfterTest();
        $this->setAdminUser();
        $file = $this->plugin_zip(['photo.jpg' => 'jpg-bytes'], 'bulk.zip');
        $sha = (new file_hasher())->hash_stored_file($file);
        $repo = new scan_repository();
        $row = $this->row_for_file($file, scan_status::CLEAN);
        $row->sha256 = $sha;
        $row->phase = scan_phase::COMPLETED;
        $row->archiveoutcome = archive_outcome::PROCESSING;
        $repo->insert($row);

        $bulk = new bulk_scan_service(
            $this->make_service(new fake_provider()),
            $repo,
            plugin_config::from_site_config()
        );
        $method = new \ReflectionMethod($bulk, 'has_completed_scan');
        $this->assertFalse($method->invoke($bulk, $file));

        global $DB;
        $DB->set_field('antivirus_verdict_scans', 'archiveoutcome', archive_outcome::COMPLETE, ['sha256' => $sha]);
        $this->assertTrue($method->invoke($bulk, $file));
    }

    /**
     * Repeated finalisation does not enforce twice, and enforcement uses the parent file.
     */
    public function test_parent_enforcement_runs_once_on_the_container(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        $file = $this->plugin_zip(['eicar.com.txt' => 'bad'], 'enforce.zip');
        $repo = new scan_repository();
        $parentid = $repo->insert($this->row_for_file($file, scan_status::PENDING));
        $parent = $repo->get_by_id($parentid);
        $parent->archiveoutcome = archive_outcome::PROCESSING;
        $parent->phase = scan_phase::COMPLETED;
        $parent->malicious = 0;
        $parent->suspicious = 0;
        $parent->undetected = 4;
        $parent->harmless = 0;
        $parent->timeout = 0;
        $parent->totalengines = 4;
        $parent->sha256 = (new file_hasher())->hash_stored_file($file);
        $repo->update($parent);
        $child = $this->row_for_file($file, scan_status::MALICIOUS);
        $child->parentscanid = $parentid;
        $child->phase = scan_phase::COMPLETED;
        $child->filename = 'eicar.com.txt';
        $child->filepath = '/archive/';
        $child->source = scan_source::ARCHIVE;
        $child->sha256 = hash('sha256', 'bad');
        $repo->insert($child);

        $enforcer = new recording_enforcer($repo, plugin_config::from_site_config(), new file_hasher());
        $orchestrator = new archive_orchestrator($repo, $enforcer, new recording_notifier());
        $orchestrator->maybe_finalize_parent($parentid);
        $orchestrator->maybe_finalize_parent($parentid);
        $finished = $repo->get_by_id($parentid);
        $this->assertSame(scan_status::MALICIOUS, $finished->status);
        $this->assertCount(1, $enforcer->quarantined);
        $this->assertSame('enforce.zip', $enforcer->quarantined[0]['filename']);
    }

    /**
     * A rate-limited provider result stays pending and does not complete.
     */
    public function test_rate_limit_stays_pending(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        $provider = new fake_provider();
        $provider->lookupexception = new provider_exception('error_ratelimit', '', 429);
        $service = $this->make_service($provider);
        $file = $this->plugin_bytes('limited.bin', 'bytes');
        $scan = $service->enqueue_file_scan($file, scan_source::MANUAL, 2);
        $service->process_scan((int) $scan->id);
        $stored = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame(scan_status::PENDING, $stored->status);
        $this->assertNotSame(scan_status::CLEAN, $stored->status);
        $this->assertSame(0, (int) $stored->timecompleted);
    }

    /**
     * Clean provider stats for a container row.
     *
     * @return array<string,int>
     */
    private function clean_stats(): array {
        return ['malicious' => 0, 'suspicious' => 0, 'undetected' => 10, 'harmless' => 1, 'timeout' => 0];
    }

    /**
     * Build a scan engine.
     *
     * @param fake_provider $provider Fake provider.
     * @param recording_notifier|null $notifier Recording notifier.
     * @return scan_service
     */
    private function make_service(fake_provider $provider, ?recording_notifier $notifier = null): scan_service {
        return new scan_service(
            $provider,
            new scan_repository(),
            new file_hasher(),
            plugin_config::from_site_config(),
            new recording_scheduler(),
            null,
            null,
            $notifier
        );
    }

    /**
     * Build a native gate scanner.
     *
     * @param fake_provider $provider Fake provider.
     * @return scanner
     */
    private function make_gate_scanner(fake_provider $provider): scanner {
        $gate = new \antivirus_verdict\local\antivirus_gate(
            $provider,
            new scan_repository(),
            new file_hasher(),
            new plugin_config(true, 1048576, false),
            new recording_scheduler()
        );
        $scanner = new scanner();
        $scanner->set_gate($gate);
        return $scanner;
    }

    /**
     * Store a ZIP in the plugin gate area.
     *
     * @param array<string,string> $entries Members.
     * @param string $filename Filename.
     * @return \stored_file
     */
    private function plugin_zip(array $entries, string $filename = 'bundle.zip'): \stored_file {
        $path = archive_test_helper::fixtures_dir() . '/' . $filename;
        $this->assertTrue(archive_test_helper::write_zip($path, $entries));
        return $this->store_path($path, $filename);
    }

    /**
     * Store raw bytes in the plugin gate area.
     *
     * @param string $filename Filename.
     * @param string $bytes Contents.
     * @return \stored_file
     */
    private function plugin_bytes(string $filename, string $bytes): \stored_file {
        $fs = get_file_storage();
        return $fs->create_file_from_string([
            'contextid' => \context_system::instance()->id,
            'component' => 'antivirus_verdict',
            'filearea' => plugin_file_lifecycle::GATE_FILEAREA,
            'itemid' => random_int(1, 100000000),
            'filepath' => '/',
            'filename' => $filename,
        ], $bytes);
    }

    /**
     * Store a filesystem path in the plugin gate area.
     *
     * @param string $path Source path.
     * @param string $filename Filename.
     * @return \stored_file
     */
    private function store_path(string $path, string $filename): \stored_file {
        $fs = get_file_storage();
        return $fs->create_file_from_pathname([
            'contextid' => \context_system::instance()->id,
            'component' => 'antivirus_verdict',
            'filearea' => plugin_file_lifecycle::GATE_FILEAREA,
            'itemid' => random_int(1, 100000000),
            'filepath' => '/',
            'filename' => $filename,
        ], $path);
    }

    /**
     * Insert a processing container with provider counts.
     *
     * @param scan_repository $repo Repository.
     * @param \stored_file $file Container file.
     * @return int
     */
    private function processing_parent(scan_repository $repo, \stored_file $file): int {
        $id = $repo->insert($this->row_for_file($file, scan_status::PENDING));
        $parent = $repo->get_by_id($id);
        $parent->phase = scan_phase::COMPLETED;
        $parent->archiveoutcome = archive_outcome::PROCESSING;
        $parent->malicious = 0;
        $parent->suspicious = 0;
        $parent->undetected = 10;
        $parent->harmless = 1;
        $parent->timeout = 0;
        $parent->totalengines = 11;
        $parent->timecompleted = 0;
        $repo->update($parent);
        return $id;
    }

    /**
     * Push timemodified far enough into the past for stale recovery.
     *
     * @param int $id Scan id.
     */
    private function age_row(int $id): void {
        global $DB;
        $DB->set_field('antivirus_verdict_scans', 'timemodified', time() - (3 * 3600), ['id' => $id]);
    }

    /**
     * Scan row for a stored file.
     *
     * @param \stored_file $file File.
     * @param string $status Status.
     * @return \stdClass
     */
    private function row_for_file(\stored_file $file, string $status): \stdClass {
        $row = $this->bare_row($status, str_repeat('a', 64));
        $row->fileid = $file->get_id();
        $row->contenthash = $file->get_contenthash();
        $row->pathnamehash = $file->get_pathnamehash();
        $row->contextid = $file->get_contextid();
        $row->component = $file->get_component();
        $row->filearea = $file->get_filearea();
        $row->itemid = $file->get_itemid();
        $row->filename = $file->get_filename();
        $row->filesize = $file->get_filesize();
        $row->mimetype = $file->get_mimetype();
        return $row;
    }

    /**
     * Minimal scan row.
     *
     * @param string $status Status.
     * @param string $sha256 SHA-256.
     * @return \stdClass
     */
    private function bare_row(string $status, string $sha256): \stdClass {
        $now = time();
        $row = new \stdClass();
        $row->fileid = 0;
        $row->contenthash = str_repeat('b', 40);
        $row->pathnamehash = str_repeat('c', 40);
        $row->contextid = \context_system::instance()->id;
        $row->courseid = 0;
        $row->component = 'antivirus_verdict';
        $row->filearea = 'unittest';
        $row->itemid = 0;
        $row->filepath = '/';
        $row->filename = 'file.bin';
        $row->userid = 2;
        $row->source = scan_source::MANUAL;
        $row->sha256 = $sha256;
        $row->filesize = 4;
        $row->mimetype = 'application/octet-stream';
        $row->status = $status;
        $row->phase = scan_phase::COMPLETED;
        $row->vtanalysisid = null;
        $row->vtfileid = null;
        $row->malicious = 0;
        $row->suspicious = 0;
        $row->undetected = 1;
        $row->harmless = 0;
        $row->timeout = 0;
        $row->totalengines = 1;
        $row->errorcode = null;
        $row->enforcement = enforcement_state::NONE;
        $row->pollattempts = 0;
        $row->timelastpoll = 0;
        $row->timesubmitted = 0;
        $row->timecreated = $now;
        $row->timemodified = $now;
        $row->timecompleted = $status === scan_status::PENDING ? 0 : $now;
        $row->parentscanid = 0;
        $row->archiveoutcome = archive_outcome::NONE;
        return $row;
    }
}
