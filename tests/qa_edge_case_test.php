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
 * Phase 2–4 edge-case QA tests (mock PHPUnit only).
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\antivirus_gate;
use antivirus_verdict\local\archive_aggregate;
use antivirus_verdict\local\archive_scanner;
use antivirus_verdict\local\bulk_scan_service;
use antivirus_verdict\local\file_area_scanner;
use antivirus_verdict\local\file_hasher;
use antivirus_verdict\local\plugin_config;
use antivirus_verdict\local\restore_course_scanner;
use antivirus_verdict\local\scan_policy;
use antivirus_verdict\local\scan_repository;
use antivirus_verdict\local\scan_service;
use antivirus_verdict\provider\file_lookup_result;
use antivirus_verdict\provider\provider_exception;
use antivirus_verdict\tests\archive_test_helper;
use antivirus_verdict\tests\fake_provider;
use antivirus_verdict\tests\recording_scheduler;
use antivirus_verdict\tests\spy_bulk_scan_service;
use antivirus_verdict\tests\throwing_archive_extractor;


/**
 * Targeted coverage for VERDICT_EDGE_CASE_TEST_PLAN Phases 2–4.
 *
 * @coversNothing
 */
final class qa_edge_case_test extends \advanced_testcase {
    /** SHA-256 of "hello". */
    private const HELLO_SHA256 = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';

    /**
     * VT-EC-D04: a prior ERROR row must not short-circuit lookup as if it were clean.
     */
    public function test_vt_ec_d04_prior_error_does_not_skip_provider_lookup_at_gate(): void {
        global $DB;

        $this->resetAfterTest();
        $repo = new scan_repository();
        $errorrow = $this->terminal_row(self::HELLO_SHA256, scan_status::ERROR, scan_phase::FAILED, 'error_network');
        $repo->insert($errorrow);

        $provider = new fake_provider();
        $provider->lookupresult = new file_lookup_result(true, self::HELLO_SHA256, [
            'malicious' => 0,
            'suspicious' => 0,
            'undetected' => 10,
            'harmless' => 5,
            'timeout' => 0,
        ]);
        $scanner = $this->make_gate_scanner($provider);

        $this->assertSame(scanner::SCAN_RESULT_OK, $scanner->scan_file($this->temp_file('hello'), 'retry.bin'));
        $this->assertSame(1, $provider->lookupcount, 'ERROR history must not suppress the hash lookup.');

        $rows = $DB->get_records('antivirus_verdict_scans', ['sha256' => self::HELLO_SHA256], 'id DESC');
        $this->assertGreaterThan(1, count($rows));
        $latest = reset($rows);
        $this->assertSame(scan_status::CLEAN, $latest->status);
    }

    /**
     * VT-EC-D04 (async): reuse_completed_hash ignores terminal ERROR rows.
     */
    public function test_vt_ec_d04_async_error_hash_requires_fresh_lookup(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $repo = new scan_repository();
        $sha = hash('sha256', 'async-error-payload');
        $repo->insert($this->terminal_row($sha, scan_status::ERROR, scan_phase::FAILED, 'error_server'));

        $provider = new fake_provider();
        $provider->lookupresult = new file_lookup_result(
            true,
            $sha,
            ['malicious' => 0, 'suspicious' => 0, 'undetected' => 5, 'harmless' => 5, 'timeout' => 0]
        );
        $service = new scan_service(
            $provider,
            $repo,
            new file_hasher(),
            new plugin_config(true, 1024 * 1024),
            new recording_scheduler()
        );
        $file = $this->create_stored_file('async-error.bin', 'async-error-payload');
        $scan = $service->queue_file_scan($file, scan_source::FORUM, 3);

        $this->assertSame(1, $provider->lookupcount);
        $this->assertSame(scan_status::CLEAN, $scan->status);
        $this->assertSame(0, $provider->uploadcount);
    }

    /**
     * VT-EC-G10: first-time gate decision performs exactly one provider lookup.
     */
    public function test_vt_ec_g10_sync_gate_single_lookup_for_unknown_hash(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $scanner = $this->make_gate_scanner($provider, scan_policy::ALLOW, scan_policy::ALLOW, scan_policy::REPORT);
        $this->assertSame(scanner::SCAN_RESULT_OK, $scanner->scan_file($this->temp_file('unique-g10'), 'g10.bin'));
        $this->assertSame(1, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
    }

    /**
     * VT-EC-COV03: forum consumer path queues with the forum source label.
     */
    public function test_vt_ec_cov03_file_area_scanner_forum_source(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $scheduler = new recording_scheduler();
        $service = new scan_service(
            $provider,
            new scan_repository(),
            new file_hasher(),
            new plugin_config(true, 1024 * 1024),
            $scheduler
        );
        $scanner = new file_area_scanner($service, plugin_config::from_site_config());
        $file = $this->create_stored_file('forum-attach.txt', 'forum bytes');
        $scan = $scanner->queue_file($file, scan_source::FORUM, 42);

        $this->assertSame(scan_source::FORUM, $scan->source);
        $this->assertSame(42, (int) $scan->userid);
        $this->assertSame([(int) $scan->id], $scheduler->queued);
    }

    /**
     * VT-EC-COV04: restore scanner delegates a course sweep with restore source.
     */
    public function test_vt_ec_cov04_restore_queue_uses_restore_source(): void {
        $this->resetAfterTest();
        set_config('apikey', 'qa-restore-key', 'antivirus_verdict');
        set_config('restorescan', 1, 'antivirus_verdict');

        $course = $this->getDataGenerator()->create_course();
        $provider = new fake_provider();
        $config = plugin_config::from_site_config();
        $spy = new spy_bulk_scan_service(
            new scan_service($provider, new scan_repository(), new file_hasher(), $config, new recording_scheduler()),
            new scan_repository(),
            $config
        );
        $restore = new restore_course_scanner($spy, $config);

        $this->assertTrue($restore->queue_course((int) $course->id, 9));
        $this->assertCount(1, $spy->sweepcalls);
        $this->assertSame([(int) $course->id, 9, true, scan_source::RESTORE], $spy->sweepcalls[0]);
    }

    /**
     * VT-EC-COV04: bulk can_start requires credentials.
     */
    public function test_vt_ec_cov04_bulk_can_start_requires_api_key(): void {
        $this->resetAfterTest();
        unset_config('apikey', 'antivirus_verdict');
        $service = bulk_scan_service::from_site_config();
        $this->assertFalse($service->can_start());

        set_config('apikey', 'bulk-key', 'antivirus_verdict');
        $service = bulk_scan_service::from_site_config();
        $this->assertTrue($service->can_start());
    }

    /**
     * VT-EC-AR21: table-driven aggregate precedence for member pairs.
     *
     * @param string $left Left member status.
     * @param string $right Right member status.
     * @param string $expected Winning aggregate status.
     * @dataProvider aggregate_status_pair_provider
     */
    public function test_vt_ec_ar21_aggregate_status_pairs(string $left, string $right, string $expected): void {
        $children = [
            (object) ['status' => $left, 'phase' => scan_phase::COMPLETED],
            (object) ['status' => $right, 'phase' => scan_phase::COMPLETED],
        ];
        $this->assertSame($expected, archive_aggregate::aggregate_status($children));
    }

    /**
     * Internal helper.
     *
     * @return array<string, array{0:string,1:string,2:string}>
     */
    public static function aggregate_status_pair_provider(): array {
        return [
            'malicious over clean' => [scan_status::MALICIOUS, scan_status::CLEAN, scan_status::MALICIOUS],
            'malicious over suspicious' => [scan_status::SUSPICIOUS, scan_status::MALICIOUS, scan_status::MALICIOUS],
            'malicious over error' => [scan_status::ERROR, scan_status::MALICIOUS, scan_status::MALICIOUS],
            'malicious over pending' => [scan_status::PENDING, scan_status::MALICIOUS, scan_status::MALICIOUS],
            'suspicious over clean' => [scan_status::SUSPICIOUS, scan_status::CLEAN, scan_status::SUSPICIOUS],
            'suspicious over error' => [scan_status::ERROR, scan_status::SUSPICIOUS, scan_status::SUSPICIOUS],
            'error over clean' => [scan_status::ERROR, scan_status::CLEAN, scan_status::ERROR],
            'error over pending' => [scan_status::PENDING, scan_status::ERROR, scan_status::ERROR],
            'pending over clean' => [scan_status::PENDING, scan_status::CLEAN, scan_status::PENDING],
            'notscanned over clean' => [scan_status::NOTSCANNED, scan_status::CLEAN, scan_status::NOTSCANNED],
        ];
    }

    /**
     * VT-EC-AR24: extraction work directories are removed when extraction throws.
     */
    public function test_vt_ec_ar24_workdir_removed_after_extract_throws(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');

        $zippath = archive_test_helper::fixtures_dir() . '/ar24.zip';
        archive_test_helper::write_zip($zippath, ['inner.txt' => 'data']);
        $fs = get_file_storage();
        $file = $fs->create_file_from_pathname([
            'contextid' => \context_system::instance()->id,
            'component' => 'user',
            'filearea' => 'draft',
            'itemid' => file_get_unused_draft_itemid(),
            'filepath' => '/',
            'filename' => 'ar24.zip',
        ], $zippath);

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

        $extractor = new throwing_archive_extractor();
        $scanner = new archive_scanner($service, plugin_config::from_site_config(), $extractor);

        try {
            $scanner->process_container($parentid);
            $this->fail('Expected simulated extract failure.');
        } catch (\RuntimeException $e) {
            $this->assertSame('simulated extract failure', $e->getMessage());
        }

        $this->assertNotSame('', $extractor->lastworkdir);
        $this->assertFalse(is_dir($extractor->lastworkdir), 'Work directory must be removed in finally.');
    }

    /**
     * VT-EC-D04: prior ERROR with a failing lookup stays ERROR, not OK.
     */
    public function test_vt_ec_d04_prior_error_with_lookup_failure_stays_error(): void {
        $this->resetAfterTest();
        $repo = new scan_repository();
        $repo->insert($this->terminal_row(self::HELLO_SHA256, scan_status::ERROR, scan_phase::FAILED, 'error_network'));

        $provider = new fake_provider();
        $provider->lookupexception = new provider_exception('error_network', '', 0);
        $scanner = $this->make_gate_scanner($provider, scan_policy::ALLOW, scan_policy::ALLOW, scan_policy::REPORT);
        $this->assertSame(scanner::SCAN_RESULT_ERROR, $scanner->scan_file($this->temp_file('hello'), 'fail.bin'));
        $this->assertSame(1, $provider->lookupcount);
    }

    /**
     * Internal helper.
     *
     * @param fake_provider $provider Provider double.
     * @param string $unknown Unknown policy.
     * @param string $suspicious Suspicious policy.
     * @param string $providererror Provider-error policy.
     * @return scanner
     */
    private function make_gate_scanner(
        fake_provider $provider,
        string $unknown = scan_policy::ALLOW,
        string $suspicious = scan_policy::ALLOW,
        string $providererror = scan_policy::BLOCK
    ): scanner {
        $gate = new antivirus_gate(
            $provider,
            new scan_repository(),
            new file_hasher(),
            new plugin_config(true, 1048576, false, $unknown, $suspicious, $providererror),
            new recording_scheduler()
        );
        $scanner = new scanner();
        $scanner->set_gate($gate);
        return $scanner;
    }

    /**
     * Internal helper.
     *
     * @param string $sha256 Content hash.
     * @param string $status Terminal status.
     * @param string $phase Terminal phase.
     * @param string $errorcode Provider error code.
     * @return \stdClass
     */
    private function terminal_row(string $sha256, string $status, string $phase, string $errorcode): \stdClass {
        $now = time();
        $row = new \stdClass();
        $row->fileid = 0;
        $row->contenthash = null;
        $row->pathnamehash = '';
        $row->contextid = \context_system::instance()->id;
        $row->courseid = 0;
        $row->component = 'user';
        $row->filearea = 'draft';
        $row->itemid = 0;
        $row->filepath = '/';
        $row->filename = 'prior.bin';
        $row->userid = 2;
        $row->source = scan_source::MANUAL;
        $row->sha256 = $sha256;
        $row->filesize = 5;
        $row->mimetype = null;
        $row->status = $status;
        $row->phase = $phase;
        $row->vtanalysisid = null;
        $row->vtfileid = null;
        $row->malicious = 0;
        $row->suspicious = 0;
        $row->undetected = 0;
        $row->harmless = 0;
        $row->timeout = 0;
        $row->totalengines = 0;
        $row->errorcode = $errorcode;
        $row->enforcement = enforcement_state::NONE;
        $row->pollattempts = 0;
        $row->timelastpoll = 0;
        $row->timesubmitted = 0;
        $row->timecreated = $now - 60;
        $row->timemodified = $now - 60;
        $row->timecompleted = $now - 60;
        $row->parentscanid = 0;
        $row->archiveoutcome = archive_outcome::NONE;
        return $row;
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
        $row->sha256 = str_repeat('c', 64);
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

    /**
     * Internal helper.
     *
     * @param string $filename Name.
     * @param string $content Bytes.
     * @return \stored_file
     */
    private function create_stored_file(string $filename, string $content): \stored_file {
        $fs = get_file_storage();
        return $fs->create_file_from_string([
            'contextid' => \context_system::instance()->id,
            'component' => 'user',
            'filearea' => 'draft',
            'itemid' => file_get_unused_draft_itemid(),
            'filepath' => '/',
            'filename' => $filename,
        ], $content);
    }

    /**
     * Internal helper.
     *
     * @param string $contents File bytes.
     * @return string Absolute path.
     */
    private function temp_file(string $contents): string {
        $path = make_request_directory() . '/qa-' . random_int(1, 100000000) . '.bin';
        file_put_contents($path, $contents);
        return $path;
    }
}
