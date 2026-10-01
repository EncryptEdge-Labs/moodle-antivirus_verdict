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
 * Central analysis path: reuse, in-flight join, and the native gate.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\antivirus_gate;
use antivirus_verdict\local\file_hasher;
use antivirus_verdict\local\plugin_config;
use antivirus_verdict\local\scan_policy;
use antivirus_verdict\local\scan_repository;
use antivirus_verdict\local\scan_scope;
use antivirus_verdict\local\scan_service;
use antivirus_verdict\provider\provider_exception;
use antivirus_verdict\tests\fake_provider;
use antivirus_verdict\tests\recording_scheduler;

/**
 * Phase 2: admitted provider work goes through scan_service.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @covers \antivirus_verdict\local\scan_service
 * @covers \antivirus_verdict\local\antivirus_gate
 */
final class scan_analysis_path_test extends \advanced_testcase {
    /**
     * Every-upload unknown files are looked up by scan_service, not the gate.
     */
    public function test_every_upload_lookup_is_centralized(): void {
        global $DB;

        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $scanner = $this->scanner($provider, scan_scope::EVERY_UPLOAD);
        $gate = file_get_contents(__DIR__ . '/../classes/local/antivirus_gate.php');
        $this->assertStringNotContainsString('lookup_file_hash', $gate);
        $this->assertStringContainsString('resolve_admitted_hash', $gate);

        $this->assertSame(scanner::SCAN_RESULT_OK, $scanner->scan_file($this->temp_file('fresh'), 'fresh.txt'));
        $this->assertSame(1, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
        $this->assertTrue($DB->record_exists('antivirus_verdict_scans', ['filename' => 'fresh.txt']));
    }

    /**
     * A completed reusable verdict is copied with no provider call.
     */
    public function test_completed_sha_is_reused_without_provider(): void {
        global $DB;

        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $path = $this->temp_file('already-known');
        $sha = (new file_hasher())->hash_path($path);
        $this->store($sha, scan_status::MALICIOUS, scan_phase::COMPLETED, 'analysis-done');
        $scanner = $this->scanner($provider, scan_scope::EVERY_UPLOAD);

        $this->assertSame(scanner::SCAN_RESULT_FOUND, $scanner->scan_file($path, 'again.txt'));
        $this->assertSame(0, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
        $copy = $DB->get_record('antivirus_verdict_scans', ['filename' => 'again.txt'], '*', MUST_EXIST);
        $this->assertSame(scan_status::MALICIOUS, $copy->status);
        $this->assertSame('analysis-done', $copy->vtanalysisid);
        $this->assertSame(scan_source::ANTIVIRUS, $copy->source);
    }

    /**
     * A second admitted upload joins an in-flight analysis and does not upload.
     */
    public function test_inflight_sha_is_joined_without_upload(): void {
        global $DB;

        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $path = $this->temp_file('inflight-bytes');
        $sha = (new file_hasher())->hash_path($path);
        $seedid = $this->store($sha, scan_status::PENDING, scan_phase::POLLING, 'analysis-live');
        $scanner = $this->scanner($provider, scan_scope::EVERY_UPLOAD);

        $this->assertSame(scanner::SCAN_RESULT_OK, $scanner->scan_file($path, 'second.txt'));
        $this->assertSame(0, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
        $second = $DB->get_record('antivirus_verdict_scans', ['filename' => 'second.txt'], '*', MUST_EXIST);
        $this->assertNotSame($seedid, (int) $second->id);
        $this->assertSame('analysis-live', $second->vtanalysisid);
        $this->assertSame(scan_status::PENDING, $second->status);
    }

    /**
     * Different hashes do not share a lookup or an analysis id.
     */
    public function test_different_sha_values_stay_independent(): void {
        global $DB;

        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $scanner = $this->scanner($provider, scan_scope::EVERY_UPLOAD);

        $this->assertSame(scanner::SCAN_RESULT_OK, $scanner->scan_file($this->temp_file('alpha'), 'a.txt'));
        $this->assertSame(scanner::SCAN_RESULT_OK, $scanner->scan_file($this->temp_file('beta'), 'b.txt'));
        $this->assertSame(2, $provider->lookupcount);
        $a = $DB->get_record('antivirus_verdict_scans', ['filename' => 'a.txt'], '*', MUST_EXIST);
        $b = $DB->get_record('antivirus_verdict_scans', ['filename' => 'b.txt'], '*', MUST_EXIST);
        $this->assertNotSame($a->sha256, $b->sha256);
        $this->assertNotSame((int) $a->id, (int) $b->id);
    }

    /**
     * A gate event and a later queued scan stay separate rows and share one analysis.
     */
    public function test_two_audit_rows_share_one_analysis(): void {
        global $DB;

        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $bytes = 'shared-bytes';
        $path = $this->temp_file($bytes);
        $sha = (new file_hasher())->hash_path($path);
        $seedid = $this->store($sha, scan_status::PENDING, scan_phase::POLLING, 'analysis-shared');
        $scanner = $this->scanner($provider, scan_scope::EVERY_UPLOAD);
        $this->assertSame(scanner::SCAN_RESULT_OK, $scanner->scan_file($path, 'gate.txt'));

        $fs = get_file_storage();
        $file = $fs->create_file_from_string([
            'contextid' => \context_system::instance()->id,
            'component' => 'user',
            'filearea' => 'draft',
            'itemid' => file_get_unused_draft_itemid(),
            'filepath' => '/',
            'filename' => 'later.txt',
        ], $bytes);
        $service = new scan_service(
            $provider,
            new scan_repository(),
            new file_hasher(),
            $this->config(scan_scope::EVERY_UPLOAD),
            new recording_scheduler()
        );
        $queued = $service->enqueue_file_scan($file, scan_source::MANUAL, 2);
        $service->process_scan((int) $queued->id);

        $gate = $DB->get_record('antivirus_verdict_scans', ['filename' => 'gate.txt'], '*', MUST_EXIST);
        $manual = $DB->get_record('antivirus_verdict_scans', ['id' => $queued->id], '*', MUST_EXIST);
        $this->assertNotSame((int) $gate->id, (int) $manual->id);
        $this->assertNotSame($seedid, (int) $gate->id);
        $this->assertSame(scan_source::ANTIVIRUS, $gate->source);
        $this->assertSame(scan_source::MANUAL, $manual->source);
        $this->assertSame('analysis-shared', $gate->vtanalysisid);
        $this->assertSame('analysis-shared', $manual->vtanalysisid);
        $this->assertSame(0, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
    }

    /**
     * Selected-areas unknown uploads still never enter the provider path.
     */
    public function test_selected_areas_unknown_stays_outside_provider_path(): void {
        global $DB;

        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $scanner = $this->scanner($provider, scan_scope::SELECTED_AREAS, scan_policy::BLOCK);

        $this->assertSame(scanner::SCAN_RESULT_OK, $scanner->scan_file($this->temp_file('draft'), 'draft.txt'));
        $this->assertSame(0, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
        $this->assertSame(0, $DB->count_records('antivirus_verdict_scans'));
    }

    /**
     * An admitted contextual enqueue is fulfilled by scan_service, not the provider directly.
     */
    public function test_contextual_scan_uses_scan_service(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $file = $this->stored('assign.txt', 'assign-bytes');
        $service = new scan_service(
            $provider,
            new scan_repository(),
            new file_hasher(),
            $this->config(scan_scope::SELECTED_AREAS),
            new recording_scheduler()
        );
        $scan = $service->enqueue_file_scan($file, scan_source::ASSIGN, 2);
        $this->assertSame(0, $provider->lookupcount);
        $service->process_scan((int) $scan->id);
        $this->assertSame(1, $provider->lookupcount);
        $this->assertSame(1, $provider->uploadcount);
    }

    /**
     * Explicit manual enqueue still creates a scan row when scope is selected areas.
     */
    public function test_manual_scan_still_enters_scan_service(): void {
        global $DB;

        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $file = $this->stored('manual.txt', 'manual-bytes');
        $service = new scan_service(
            $provider,
            new scan_repository(),
            new file_hasher(),
            $this->config(scan_scope::SELECTED_AREAS),
            new recording_scheduler()
        );
        $scan = $service->enqueue_file_scan($file, scan_source::MANUAL, 2);
        $this->assertSame(scan_source::MANUAL, $scan->source);
        $this->assertSame(0, $provider->lookupcount);
        $this->assertTrue($DB->record_exists('antivirus_verdict_scans', ['source' => scan_source::MANUAL]));
    }

    /**
     * A provider lookup failure stays an error and is not stored as clean.
     */
    public function test_provider_lookup_failure_is_not_clean(): void {
        global $DB;

        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $provider->lookupexception = new provider_exception('error_auth');
        $scanner = $this->scanner($provider, scan_scope::EVERY_UPLOAD);

        try {
            $scanner->scan_file($this->temp_file('nope'), 'failed.txt');
            $this->fail('Provider authentication failure must not allow a clean upload.');
        } catch (\core\antivirus\scanner_exception $e) {
            $this->assertNotSame('virusfound', $e->errorcode);
        }
        $this->assertSame(1, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
        $row = $DB->get_record('antivirus_verdict_scans', ['filename' => 'failed.txt'], '*', MUST_EXIST);
        $this->assertSame(scan_status::ERROR, $row->status);
        $this->assertNotSame(scan_status::CLEAN, $row->status);
    }

    /**
     * Disabled archive scanning still skips a ZIP before any provider lookup.
     */
    public function test_disabled_archive_scan_still_skips_zip_without_lookup(): void {
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
                archivescan: false,
                scanscope: scan_scope::EVERY_UPLOAD
            ),
            new recording_scheduler()
        );
        $scanner = new scanner();
        $scanner->set_gate($gate);

        $this->assertSame(scanner::SCAN_RESULT_OK, $scanner->scan_file($this->temp_file('PK'), 'pack.zip'));
        $this->assertSame(0, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
        $this->assertSame(0, $DB->count_records('antivirus_verdict_scans'));
    }

    /**
     * Disabling member inspection does not bypass a completed malicious container verdict.
     */
    public function test_disabled_archive_scan_blocks_known_malicious_container(): void {
        global $DB;

        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $path = $this->temp_file('known-bad-zip');
        $sha = (new file_hasher())->hash_path($path);
        $this->store($sha, scan_status::MALICIOUS, scan_phase::COMPLETED, 'analysis-done');
        $gate = new antivirus_gate(
            $provider,
            new scan_repository(),
            new file_hasher(),
            new plugin_config(
                enabled: true,
                maxbytes: 1048576,
                archivescan: false,
                scanscope: scan_scope::EVERY_UPLOAD
            ),
            new recording_scheduler()
        );
        $scanner = new scanner();
        $scanner->set_gate($gate);

        $this->assertSame(scanner::SCAN_RESULT_FOUND, $scanner->scan_file($path, 'known.zip'));
        $this->assertSame(0, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
        $this->assertSame(0, $provider->analysiscount);
        $row = $DB->get_record('antivirus_verdict_scans', ['filename' => 'known.zip'], '*', MUST_EXIST);
        $this->assertSame(scan_status::MALICIOUS, $row->status);
        $this->assertNotSame(scan_status::CLEAN, $row->status);
    }

    /**
     * Build a scanner for the given scope and unknown policy.
     *
     * @param fake_provider $provider Provider.
     * @param string $scope Scope.
     * @param string $unknown Unknown policy.
     * @return scanner
     */
    private function scanner(fake_provider $provider, string $scope, string $unknown = scan_policy::ALLOW): scanner {
        $gate = new antivirus_gate(
            $provider,
            new scan_repository(),
            new file_hasher(),
            $this->config($scope, $unknown),
            new recording_scheduler()
        );
        $scanner = new scanner();
        $scanner->set_gate($gate);
        return $scanner;
    }

    /**
     * Build plugin config for the given scope and unknown policy.
     *
     * @param string $scope Scope.
     * @param string $unknown Unknown policy.
     * @return plugin_config
     */
    private function config(string $scope, string $unknown = scan_policy::ALLOW): plugin_config {
        return new plugin_config(
            enabled: true,
            maxbytes: 1048576,
            unknownpolicy: $unknown,
            scanscope: $scope
        );
    }

    /**
     * Insert a scan row in the requested state.
     *
     * @param string $sha256 SHA-256.
     * @param string $status Status.
     * @param string $phase Phase.
     * @param string $analysisid Analysis id.
     * @return int
     */
    private function store(string $sha256, string $status, string $phase, string $analysisid): int {
        $now = time();
        return (new scan_repository())->insert((object) [
            'fileid' => 0,
            'contenthash' => '',
            'pathnamehash' => '',
            'contextid' => \context_system::instance()->id,
            'courseid' => 0,
            'component' => 'antivirus_verdict',
            'filearea' => 'gate',
            'itemid' => 0,
            'filepath' => '/',
            'filename' => 'seed.bin',
            'userid' => 2,
            'initiatedby' => 0,
            'submissionid' => 0,
            'source' => scan_source::ANTIVIRUS,
            'sha256' => $sha256,
            'filesize' => 10,
            'mimetype' => 'text/plain',
            'status' => $status,
            'phase' => $phase,
            'vtanalysisid' => $analysisid,
            'vtfileid' => $sha256,
            'malicious' => $status === scan_status::MALICIOUS ? 2 : 0,
            'suspicious' => 0,
            'undetected' => 3,
            'harmless' => 1,
            'timeout' => 0,
            'totalengines' => 6,
            'errorcode' => null,
            'enforcement' => enforcement_state::NONE,
            'pollattempts' => 0,
            'timelastpoll' => 0,
            'timesubmitted' => $now,
            'timecreated' => $now,
            'timemodified' => $now,
            'timecompleted' => $status === scan_status::PENDING ? 0 : $now,
            'parentscanid' => 0,
            'archiveoutcome' => '',
        ]);
    }

    /**
     * Store a draft file.
     *
     * @param string $filename Filename.
     * @param string $contents Bytes.
     * @return \stored_file
     */
    private function stored(string $filename, string $contents): \stored_file {
        $fs = get_file_storage();
        return $fs->create_file_from_string([
            'contextid' => \context_system::instance()->id,
            'component' => 'user',
            'filearea' => 'draft',
            'itemid' => file_get_unused_draft_itemid(),
            'filepath' => '/',
            'filename' => $filename,
        ], $contents);
    }

    /**
     * Write bytes to a temporary file.
     *
     * @param string $contents Bytes.
     * @return string
     */
    private function temp_file(string $contents): string {
        $path = make_request_directory() . '/analysis-' . random_int(1, 100000000) . '.bin';
        file_put_contents($path, $contents);
        return $path;
    }
}
