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
 * Scanning-scope admission for the native upload gate.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\file_hasher;
use antivirus_verdict\local\plugin_config;
use antivirus_verdict\local\scan_policy;
use antivirus_verdict\local\scan_repository;
use antivirus_verdict\local\scan_scope;
use antivirus_verdict\local\scan_service;
use antivirus_verdict\local\antivirus_gate;
use antivirus_verdict\tests\fake_provider;
use antivirus_verdict\tests\recording_scheduler;
use antivirus_verdict\tests\throwing_scan_repository;

/**
 * Phase 1: every-upload behaviour stays, selected areas does not call the provider.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @covers \antivirus_verdict\local\antivirus_gate
 * @covers \antivirus_verdict\local\scan_scope
 */
final class scan_admission_test extends \advanced_testcase {
    /**
     * Every upload still looks up an unknown file and records the scan.
     */
    public function test_every_upload_unknown_keeps_provider_path(): void {
        global $DB;

        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $scanner = $this->scanner($provider, scan_scope::EVERY_UPLOAD);

        $this->assertSame(scanner::SCAN_RESULT_OK, $scanner->scan_file($this->temp_file('unknown-bytes'), 'report.txt'));
        $this->assertSame(1, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
        $this->assertTrue($DB->record_exists('antivirus_verdict_scans', ['filename' => 'report.txt']));
    }

    /**
     * Selected areas allows an unknown upload with no provider call and no scan row.
     */
    public function test_selected_areas_unknown_is_allowed_without_provider(): void {
        global $DB;

        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $scanner = $this->scanner($provider, scan_scope::SELECTED_AREAS, scan_policy::BLOCK);

        $this->assertSame(scanner::SCAN_RESULT_OK, $scanner->scan_file($this->temp_file('unknown-bytes'), 'draft.txt'));
        $this->assertSame(0, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
        $this->assertSame(0, $provider->analysiscount);
        $this->assertSame(0, $DB->count_records('antivirus_verdict_scans'));
    }

    /**
     * A completed local malicious verdict blocks without a provider call.
     */
    public function test_selected_areas_known_malicious_blocks_without_provider(): void {
        global $DB;

        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $path = $this->temp_file('bad-bytes');
        $this->store_verdict($path, scan_status::MALICIOUS);
        $scanner = $this->scanner($provider, scan_scope::SELECTED_AREAS);

        $this->assertSame(scanner::SCAN_RESULT_FOUND, $scanner->scan_file($path, 'blocked.txt'));
        $this->assertSame(0, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
        $blocked = $DB->get_record('antivirus_verdict_scans', ['filename' => 'blocked.txt'], '*', MUST_EXIST);
        $this->assertSame(scan_status::MALICIOUS, $blocked->status);
        $this->assertSame(scan_source::ANTIVIRUS, $blocked->source);
    }

    /**
     * Suspicious blocks only when that policy is block, and still does not call the provider.
     */
    public function test_selected_areas_suspicious_block_policy_refuses_upload(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $path = $this->temp_file('odd-bytes');
        $this->store_verdict($path, scan_status::SUSPICIOUS);
        $scanner = $this->scanner($provider, scan_scope::SELECTED_AREAS, scan_policy::ALLOW, scan_policy::BLOCK);

        $this->expectException(\core\antivirus\scanner_exception::class);
        try {
            $scanner->scan_file($path, 'suspicious.txt');
        } finally {
            $this->assertSame(0, $provider->lookupcount);
            $this->assertSame(0, $provider->uploadcount);
        }
    }

    /**
     * A completed non-blocking verdict is allowed and does not start provider work.
     */
    public function test_selected_areas_known_clean_is_allowed_without_provider(): void {
        global $DB;

        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $path = $this->temp_file('clean-bytes');
        $this->store_verdict($path, scan_status::CLEAN);
        $before = $DB->count_records('antivirus_verdict_scans');
        $scanner = $this->scanner($provider, scan_scope::SELECTED_AREAS, scan_policy::BLOCK);

        $this->assertSame(scanner::SCAN_RESULT_OK, $scanner->scan_file($path, 'clean.txt'));
        $this->assertSame(0, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
        $this->assertSame($before, $DB->count_records('antivirus_verdict_scans'));
        $this->assertFalse($DB->record_exists('antivirus_verdict_scans', ['filename' => 'clean.txt']));
    }

    /**
     * A failed local verdict read is not treated as a clean allow.
     */
    public function test_selected_areas_lookup_failure_is_not_clean(): void {
        global $DB;

        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $gate = new antivirus_gate(
            $provider,
            new throwing_scan_repository(),
            new file_hasher(),
            $this->config(scan_scope::SELECTED_AREAS),
            new recording_scheduler()
        );
        $scanner = new scanner();
        $scanner->set_gate($gate);

        try {
            $scanner->scan_file($this->temp_file('oops'), 'broken.txt');
            $this->fail('A local lookup failure must not allow the upload as clean.');
        } catch (\core\antivirus\scanner_exception $e) {
            $this->assertNotSame('virusfound', $e->errorcode);
        }
        $this->assertSame(0, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
        $row = $DB->get_record('antivirus_verdict_scans', ['filename' => 'broken.txt'], '*', MUST_EXIST);
        $this->assertSame(scan_status::ERROR, $row->status);
        $this->assertNotSame(scan_status::CLEAN, $row->status);
        $this->assertDebuggingCalled('antivirus_verdict gate failed without a provider result');
    }

    /**
     * An explicit manual enqueue still creates a scan when native uploads are deferred.
     */
    public function test_selected_areas_does_not_disable_manual_enqueue(): void {
        global $DB;

        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $fs = get_file_storage();
        $file = $fs->create_file_from_string([
            'contextid' => \context_system::instance()->id,
            'component' => 'user',
            'filearea' => 'draft',
            'itemid' => file_get_unused_draft_itemid(),
            'filepath' => '/',
            'filename' => 'manual.txt',
        ], 'manual-bytes');
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
        $this->assertSame(0, $provider->uploadcount);
        $this->assertTrue($DB->record_exists('antivirus_verdict_scans', ['source' => scan_source::MANUAL]));
    }

    /**
     * Build a gate whose native-upload scope is explicit.
     *
     * @param fake_provider $provider Provider.
     * @param string $scope Scanning scope.
     * @param string $unknown Unknown-file policy.
     * @param string $suspicious Suspicious-file policy.
     * @return scanner
     */
    private function scanner(
        fake_provider $provider,
        string $scope,
        string $unknown = scan_policy::ALLOW,
        string $suspicious = scan_policy::ALLOW
    ): scanner {
        $gate = new antivirus_gate(
            $provider,
            new scan_repository(),
            new file_hasher(),
            $this->config($scope, $unknown, $suspicious),
            new recording_scheduler()
        );
        $scanner = new scanner();
        $scanner->set_gate($gate);
        return $scanner;
    }

    /**
     * Settings with an explicit scope. Other policies stay at the given values.
     *
     * @param string $scope Scanning scope.
     * @param string $unknown Unknown-file policy.
     * @param string $suspicious Suspicious-file policy.
     * @return plugin_config
     */
    private function config(
        string $scope,
        string $unknown = scan_policy::ALLOW,
        string $suspicious = scan_policy::ALLOW
    ): plugin_config {
        return new plugin_config(
            enabled: true,
            maxbytes: 1048576,
            unknownpolicy: $unknown,
            suspiciouspolicy: $suspicious,
            scanscope: $scope
        );
    }

    /**
     * Store a completed local verdict for the bytes in a temp file.
     *
     * @param string $path Filesystem path.
     * @param string $status Product status.
     */
    private function store_verdict(string $path, string $status): void {
        $now = time();
        $row = (object) [
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
            'source' => scan_source::MANUAL,
            'sha256' => (new file_hasher())->hash_path($path),
            'filesize' => filesize($path),
            'mimetype' => 'text/plain',
            'status' => $status,
            'phase' => scan_phase::COMPLETED,
            'vtanalysisid' => 'analysis-seed',
            'vtfileid' => (new file_hasher())->hash_path($path),
            'malicious' => $status === scan_status::MALICIOUS ? 2 : 0,
            'suspicious' => $status === scan_status::SUSPICIOUS ? 2 : 0,
            'undetected' => 4,
            'harmless' => 1,
            'timeout' => 0,
            'totalengines' => 7,
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
        (new scan_repository())->insert($row);
    }

    /**
     * Writable temp file.
     *
     * @param string $contents Bytes.
     * @return string
     */
    private function temp_file(string $contents): string {
        $path = make_request_directory() . '/admission-' . random_int(1, 100000000) . '.bin';
        file_put_contents($path, $contents);
        return $path;
    }
}
