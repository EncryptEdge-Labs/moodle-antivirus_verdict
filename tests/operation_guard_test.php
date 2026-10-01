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
 * Local provider-operation ceilings and reservations.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\antivirus_gate;
use antivirus_verdict\local\file_hasher;
use antivirus_verdict\local\operation_counts;
use antivirus_verdict\local\operation_reservation;
use antivirus_verdict\local\plugin_config;
use antivirus_verdict\local\reservation_result;
use antivirus_verdict\local\scan_repository;
use antivirus_verdict\local\scan_scope;
use antivirus_verdict\local\scan_service;
use antivirus_verdict\provider\analysis_result;
use antivirus_verdict\provider\provider_exception;
use antivirus_verdict\tests\failing_operation_reservation;
use antivirus_verdict\tests\fake_provider;
use antivirus_verdict\tests\recording_scheduler;
use antivirus_verdict\tests\throwing_operation_counts;

/**
 * Phase 5: reserve a provider slot before VirusTotal HTTP.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @covers \antivirus_verdict\local\operation_reservation
 * @covers \antivirus_verdict\local\scan_service
 */
final class operation_guard_test extends \advanced_testcase {
    /**
     * A zero ceiling leaves the provider path open and reserves nothing.
     */
    public function test_unlimited_ceiling_allows_provider_work(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $before = $this->reserved();
        $counts = $this->counts();
        $scanner = $this->scanner($provider, $this->limits());
        $this->assertSame(scanner::SCAN_RESULT_OK, $scanner->scan_file($this->temp_file('fresh'), 'fresh.txt'));
        $this->assertSame(1, $provider->lookupcount);
        $this->assertEquals($before, $this->reserved());
        $this->assertSame($counts->hashlookups + 1, $this->counts()->hashlookups);
    }

    /**
     * One allowed lookup reserves one slot and calls the provider once.
     */
    public function test_lookup_reservation_allows_one_lookup(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $before = $this->reserved();
        $scanner = $this->scanner($provider, $this->limits(lookup: 5));
        $this->assertSame(scanner::SCAN_RESULT_OK, $scanner->scan_file($this->temp_file('fresh'), 'fresh.txt'));
        $this->assertSame(1, $provider->lookupcount);
        $this->assertSame($before->lookups + 1, $this->reserved()->lookups);
        $this->assertSame($before->uploads, $this->reserved()->uploads);
        $this->assertSame($before->polls, $this->reserved()->polls);
    }

    /**
     * One allowed upload reserves one upload slot and uploads once.
     */
    public function test_upload_reservation_allows_one_upload(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $file = $this->stored('upload.txt', 'upload-bytes');
        $service = $this->service($provider, $this->limits(upload: 5));
        $scan = $service->enqueue_file_scan($file, scan_source::MANUAL, 2);
        $before = $this->reserved();
        $service->process_scan((int) $scan->id);
        $this->assertSame(1, $provider->uploadcount);
        $this->assertSame($before->uploads + 1, $this->reserved()->uploads);
        $this->assertSame($before->lookups, $this->reserved()->lookups);
    }

    /**
     * One allowed poll reserves one poll slot and polls once.
     */
    public function test_poll_reservation_allows_one_poll(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $provider->analysisresult = new analysis_result('analysis-x', 'completed', $this->clean_stats());
        $id = $this->waiting(str_repeat('a', 64), 'analysis-x', 'one.txt');
        $before = $this->reserved();
        $counts = $this->counts();
        $this->service($provider, $this->limits(poll: 5))->process_scan($id);
        $this->assertSame(1, $provider->analysiscount);
        $this->assertSame($before->polls + 1, $this->reserved()->polls);
        $this->assertSame($counts->polls + 1, $this->counts()->polls);
        $this->assertSame(scan_status::CLEAN, (new scan_repository())->get_by_id($id)->status);
    }

    /**
     * A consumed lookup ceiling blocks the provider call and is not a clean result.
     */
    public function test_lookup_ceiling_blocks_provider_http(): void {
        global $DB;

        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $this->assertSame(
            reservation_result::ALLOWED,
            (new operation_reservation())->reserve_lookup(1)->outcome
        );
        $counts = $this->counts();
        $reserved = $this->reserved();
        $scanner = $this->scanner($provider, $this->limits(lookup: 1));
        try {
            $scanner->scan_file($this->temp_file('over'), 'over.txt');
            $this->fail('A reached lookup ceiling must not allow the upload as clean.');
        } catch (\core\antivirus\scanner_exception $e) {
            $this->assertSame('error_operationlimit', $e->errorcode);
        }
        $row = $DB->get_record('antivirus_verdict_scans', ['filename' => 'over.txt'], '*', MUST_EXIST);
        $this->assertSame(0, $provider->lookupcount);
        $this->assertSame($counts->hashlookups, $this->counts()->hashlookups);
        $this->assertSame($reserved->lookups, $this->reserved()->lookups);
        $this->assertSame(scan_status::ERROR, $row->status);
        $this->assertSame('error_operationlimit', $row->errorcode);
        $this->assertNotSame(scan_status::CLEAN, $row->status);
        $this->assertNotSame(scan_status::MALICIOUS, $row->status);
    }

    /**
     * A consumed upload ceiling does not upload.
     */
    public function test_upload_ceiling_blocks_upload(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $this->assertSame(
            reservation_result::ALLOWED,
            (new operation_reservation())->reserve_upload(1)->outcome
        );
        $counts = $this->counts();
        $file = $this->stored('noupload.txt', 'noupload-bytes');
        $service = $this->service($provider, $this->limits(upload: 1));
        $scan = $service->enqueue_file_scan($file, scan_source::MANUAL, 2);
        $service->process_scan((int) $scan->id);
        $row = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame(0, $provider->uploadcount);
        $this->assertSame($counts->uploads, $this->counts()->uploads);
        $this->assertSame(1, $this->reserved()->uploads);
        $this->assertSame(scan_status::ERROR, $row->status);
        $this->assertSame('error_operationlimit', $row->errorcode);
        $this->assertNotSame(scan_status::CLEAN, $row->status);
    }

    /**
     * A consumed poll ceiling does not poll.
     */
    public function test_poll_ceiling_blocks_poll(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $this->assertSame(
            reservation_result::ALLOWED,
            (new operation_reservation())->reserve_poll(1)->outcome
        );
        $counts = $this->counts();
        $id = $this->waiting(str_repeat('b', 64), 'analysis-x', 'wait.txt');
        $this->service($provider, $this->limits(poll: 1))->process_scan($id);
        $row = (new scan_repository())->get_by_id($id);
        $this->assertSame(0, $provider->analysiscount);
        $this->assertSame($counts->polls, $this->counts()->polls);
        $this->assertSame(1, $this->reserved()->polls);
        $this->assertSame(scan_status::ERROR, $row->status);
        $this->assertSame('error_operationlimit', $row->errorcode);
        $this->assertNotSame(scan_status::CLEAN, $row->status);
    }

    /**
     * Two rows sharing an analysis consume one poll reservation and one poll.
     */
    public function test_shared_poll_reserves_once(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $provider->analysisresult = new analysis_result('analysis-x', 'completed', $this->clean_stats());
        $sha = str_repeat('c', 64);
        $first = $this->waiting($sha, 'analysis-x', 'a.txt');
        $second = $this->waiting($sha, 'analysis-x', 'b.txt');
        $before = $this->reserved();
        $counts = $this->counts();
        $service = $this->service($provider, $this->limits(poll: 5));
        $service->process_scan($first);
        $service->process_scan($second);
        $this->assertSame(1, $provider->analysiscount);
        $this->assertSame($before->polls + 1, $this->reserved()->polls);
        $this->assertSame($counts->polls + 1, $this->counts()->polls);
        $repo = new scan_repository();
        $this->assertSame(scan_status::CLEAN, $repo->get_by_id($first)->status);
        $this->assertSame(scan_status::CLEAN, $repo->get_by_id($second)->status);
    }

    /**
     * Two analysis ids consume two poll reservations.
     */
    public function test_different_analyses_reserve_separately(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $provider->analysisresult = new analysis_result('analysis-x', 'completed', $this->clean_stats());
        $first = $this->waiting(str_repeat('d', 64), 'analysis-x', 'x.txt');
        $second = $this->waiting(str_repeat('e', 64), 'analysis-y', 'y.txt');
        $before = $this->reserved();
        $counts = $this->counts();
        $service = $this->service($provider, $this->limits(poll: 5));
        $service->process_scan($first);
        $service->process_scan($second);
        $this->assertSame(2, $provider->analysiscount);
        $this->assertSame($before->polls + 2, $this->reserved()->polls);
        $this->assertSame($counts->polls + 2, $this->counts()->polls);
    }

    /**
     * Completed reuse reserves nothing and does not call the provider.
     */
    public function test_completed_reuse_reserves_nothing(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $path = $this->temp_file('known');
        $sha = (new file_hasher())->hash_path($path);
        $this->store_completed($sha, scan_status::MALICIOUS);
        $before = $this->reserved();
        $counts = $this->counts();
        $scanner = $this->scanner($provider, $this->limits(lookup: 5, upload: 5, poll: 5));
        $this->assertSame(scanner::SCAN_RESULT_FOUND, $scanner->scan_file($path, 'again.txt'));
        $this->assertSame(0, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
        $this->assertSame(0, $provider->analysiscount);
        $this->assertEquals($before, $this->reserved());
        $this->assertSame($counts->completedreuses + 1, $this->counts()->completedreuses);
        $this->assertSame($counts->hashlookups, $this->counts()->hashlookups);
    }

    /**
     * An in-flight join does not reserve an upload.
     */
    public function test_inflight_join_reserves_no_upload(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $path = $this->temp_file('inflight');
        $sha = (new file_hasher())->hash_path($path);
        $this->waiting($sha, 'analysis-live', 'seed.txt');
        $before = $this->reserved();
        $counts = $this->counts();
        $scanner = $this->scanner($provider, $this->limits(lookup: 5, upload: 5));
        $this->assertSame(scanner::SCAN_RESULT_OK, $scanner->scan_file($path, 'second.txt'));
        $this->assertSame(0, $provider->uploadcount);
        $this->assertSame(0, $provider->lookupcount);
        $this->assertEquals($before, $this->reserved());
        $this->assertSame($counts->inflightjoins + 1, $this->counts()->inflightjoins);
        $this->assertSame($counts->uploads, $this->counts()->uploads);
    }

    /**
     * Selected-area unknown uploads do not reserve or call the provider.
     */
    public function test_selected_area_unknown_reserves_nothing(): void {
        global $DB;

        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $before = $this->reserved();
        $counts = $this->counts();
        $scanner = $this->scanner($provider, $this->limits(lookup: 5, upload: 5, poll: 5, scope: scan_scope::SELECTED_AREAS));
        $this->assertSame(scanner::SCAN_RESULT_OK, $scanner->scan_file($this->temp_file('draft'), 'draft.txt'));
        $this->assertSame(0, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
        $this->assertSame(0, $provider->analysiscount);
        $this->assertSame(0, $DB->count_records('antivirus_verdict_scans'));
        $this->assertEquals($before, $this->reserved());
        $this->assertEquals($counts, $this->counts());
    }

    /**
     * A local blocking verdict consumes no reservation and no provider operation.
     */
    public function test_selected_area_blocking_verdict_reserves_nothing(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $path = $this->temp_file('blocked');
        $sha = (new file_hasher())->hash_path($path);
        $this->store_completed($sha, scan_status::MALICIOUS);
        $before = $this->reserved();
        $counts = $this->counts();
        $scanner = $this->scanner($provider, $this->limits(lookup: 5, scope: scan_scope::SELECTED_AREAS));
        $this->assertSame(scanner::SCAN_RESULT_FOUND, $scanner->scan_file($path, 'blocked.txt'));
        $this->assertSame(0, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
        $this->assertSame(0, $provider->analysiscount);
        $this->assertEquals($before, $this->reserved());
        $this->assertEquals($counts, $this->counts());
    }

    /**
     * A provider error after a successful reservation still counts as one poll.
     */
    public function test_provider_error_keeps_reservation_and_poll_count(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $provider->analysisexception = new provider_exception('error_auth', '', 401);
        $id = $this->waiting(str_repeat('f', 64), 'analysis-x', 'bad.txt');
        $before = $this->reserved();
        $counts = $this->counts();
        $this->service($provider, $this->limits(poll: 5))->process_scan($id);
        $row = (new scan_repository())->get_by_id($id);
        $this->assertSame(1, $provider->analysiscount);
        $this->assertSame($before->polls + 1, $this->reserved()->polls);
        $this->assertSame($counts->polls + 1, $this->counts()->polls);
        $this->assertSame(scan_status::ERROR, $row->status);
        $this->assertSame('error_auth', $row->errorcode);
        $this->assertNotSame(scan_status::CLEAN, $row->status);
    }

    /**
     * A still-running poll keeps its reservation and leaves the scan pending.
     */
    public function test_still_processing_poll_keeps_reservation(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $provider->analysisresult = new analysis_result('analysis-x', 'queued', null);
        $id = $this->waiting(str_repeat('1', 64), 'analysis-x', 'pending.txt');
        $before = $this->reserved();
        $counts = $this->counts();
        $retry = $this->service($provider, $this->limits(poll: 5))->process_scan($id);
        $row = (new scan_repository())->get_by_id($id);
        $this->assertTrue($retry);
        $this->assertSame(1, $provider->analysiscount);
        $this->assertSame($before->polls + 1, $this->reserved()->polls);
        $this->assertSame($counts->polls + 1, $this->counts()->polls);
        $this->assertSame(scan_status::PENDING, $row->status);
        $this->assertSame(scan_phase::POLLING, $row->phase);
    }

    /**
     * Reservation storage failure does not call the provider or mark the file clean.
     */
    public function test_reservation_storage_failure_is_not_clean(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $provider->analysisresult = new analysis_result('analysis-x', 'completed', $this->clean_stats());
        $id = $this->waiting(str_repeat('2', 64), 'analysis-x', 'guard.txt');
        $service = new scan_service(
            provider: $provider,
            repository: new scan_repository(),
            hasher: new file_hasher(),
            config: $this->limits(poll: 5),
            scheduler: new recording_scheduler(),
            reservations: new failing_operation_reservation()
        );
        $service->process_scan($id);
        $row = (new scan_repository())->get_by_id($id);
        $this->assertSame(0, $provider->analysiscount);
        $this->assertSame(scan_status::ERROR, $row->status);
        $this->assertSame('error_guardunavailable', $row->errorcode);
        $this->assertNotSame(scan_status::CLEAN, $row->status);
        $this->assertNotSame(scan_status::MALICIOUS, $row->status);
    }

    /**
     * A totals failure after the provider responds leaves the provider verdict in place.
     */
    public function test_accounting_failure_does_not_replace_provider_result(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $provider->analysisresult = new analysis_result('analysis-x', 'completed', $this->clean_stats());
        $id = $this->waiting(str_repeat('3', 64), 'analysis-x', 'kept.txt');
        $service = new scan_service(
            provider: $provider,
            repository: new scan_repository(),
            hasher: new file_hasher(),
            config: $this->limits(poll: 5),
            scheduler: new recording_scheduler(),
            operations: new throwing_operation_counts()
        );
        $service->process_scan($id);
        $row = (new scan_repository())->get_by_id($id);
        $this->assertSame(1, $provider->analysiscount);
        $this->assertSame(1, $this->reserved()->polls);
        $this->assertSame(scan_status::CLEAN, $row->status);
        $this->assertDebuggingCalled('antivirus_verdict operation accounting failed');
    }

    /**
     * Repeated claims stop at the ceiling instead of writing past it.
     *
     * PHPUnit runs these claims one after another. The ceiling test is the
     * single conditional UPDATE, which is what concurrent workers share.
     */
    public function test_reservation_does_not_pass_the_ceiling(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $guard = new operation_reservation();
        $allowed = 0;
        $denied = 0;
        for ($i = 0; $i < 8; $i++) {
            $result = $guard->reserve_lookup(5);
            if ($result->outcome === reservation_result::ALLOWED) {
                $allowed++;
            } else if ($result->outcome === reservation_result::DENIED) {
                $denied++;
            }
        }
        $this->assertSame(5, $allowed);
        $this->assertSame(3, $denied);
        $this->assertSame(5, $guard->totals()->lookups);
    }

    /**
     * Current reserved operation totals.
     *
     * @return \stdClass
     */
    private function reserved(): \stdClass {
        return (new operation_reservation())->totals();
    }

    /**
     * Current accounted operation totals.
     *
     * @return \stdClass
     */
    private function counts(): \stdClass {
        return (new operation_counts())->totals();
    }

    /**
     * Build plugin config with the given ceilings.
     *
     * @param int $lookup Lookup ceiling.
     * @param int $upload Upload ceiling.
     * @param int $poll Poll ceiling.
     * @param string $scope Scanning scope.
     * @return plugin_config
     */
    private function limits(
        int $lookup = 0,
        int $upload = 0,
        int $poll = 0,
        string $scope = scan_scope::EVERY_UPLOAD
    ): plugin_config {
        return new plugin_config(
            enabled: true,
            maxbytes: 1048576,
            scanscope: $scope,
            lookupceiling: $lookup,
            uploadceiling: $upload,
            pollceiling: $poll
        );
    }

    /**
     * Build a scan service around the fake provider.
     *
     * @param fake_provider $provider Provider.
     * @param plugin_config $config Config.
     * @return scan_service
     */
    private function service(fake_provider $provider, plugin_config $config): scan_service {
        return new scan_service(
            $provider,
            new scan_repository(),
            new file_hasher(),
            $config,
            new recording_scheduler()
        );
    }

    /**
     * Build a scanner for the given config.
     *
     * @param fake_provider $provider Provider.
     * @param plugin_config $config Config.
     * @return scanner
     */
    private function scanner(fake_provider $provider, plugin_config $config): scanner {
        $gate = new antivirus_gate(
            $provider,
            new scan_repository(),
            new file_hasher(),
            $config,
            new recording_scheduler()
        );
        $scanner = new scanner();
        $scanner->set_gate($gate);
        return $scanner;
    }

    /**
     * Insert a waiting scan row.
     *
     * @param string $sha256 SHA-256.
     * @param string $analysisid Analysis id.
     * @param string $filename Filename.
     * @return int
     */
    private function waiting(string $sha256, string $analysisid, string $filename): int {
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
            'filename' => $filename,
            'userid' => 2,
            'initiatedby' => 0,
            'submissionid' => 0,
            'source' => scan_source::ASSIGN,
            'sha256' => $sha256,
            'filesize' => 10,
            'mimetype' => 'text/plain',
            'status' => scan_status::PENDING,
            'phase' => scan_phase::POLLING,
            'vtanalysisid' => $analysisid,
            'vtfileid' => $sha256,
            'malicious' => 0,
            'suspicious' => 0,
            'undetected' => 0,
            'harmless' => 0,
            'timeout' => 0,
            'totalengines' => 0,
            'errorcode' => null,
            'enforcement' => enforcement_state::NONE,
            'pollattempts' => 0,
            'timelastpoll' => 0,
            'timesubmitted' => $now,
            'timecreated' => $now,
            'timemodified' => $now,
            'timecompleted' => 0,
            'parentscanid' => 0,
            'archiveoutcome' => '',
        ]);
    }

    /**
     * Insert a completed scan row.
     *
     * @param string $sha256 SHA-256.
     * @param string $status Status.
     */
    private function store_completed(string $sha256, string $status): void {
        $now = time();
        (new scan_repository())->insert((object) [
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
            'phase' => scan_phase::COMPLETED,
            'vtanalysisid' => 'analysis-done',
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
            'timecompleted' => $now,
            'parentscanid' => 0,
            'archiveoutcome' => '',
        ]);
    }

    /**
     * Engine counts for a clean result.
     *
     * @return array<string, int>
     */
    private function clean_stats(): array {
        return [
            'malicious' => 0,
            'suspicious' => 0,
            'undetected' => 8,
            'harmless' => 2,
            'timeout' => 0,
        ];
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
        $path = make_request_directory() . '/guard-' . random_int(1, 100000000) . '.bin';
        file_put_contents($path, $contents);
        return $path;
    }
}
