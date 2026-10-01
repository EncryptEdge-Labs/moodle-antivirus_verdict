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
 * Site-wide provider operation totals.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\antivirus_gate;
use antivirus_verdict\local\file_hasher;
use antivirus_verdict\local\operation_counts;
use antivirus_verdict\local\plugin_config;
use antivirus_verdict\local\scan_repository;
use antivirus_verdict\local\scan_scope;
use antivirus_verdict\local\scan_service;
use antivirus_verdict\provider\analysis_result;
use antivirus_verdict\provider\provider_exception;
use antivirus_verdict\tests\fake_provider;
use antivirus_verdict\tests\recording_scheduler;
use antivirus_verdict\tests\throwing_operation_counts;

/**
 * Phase 4: count provider operations and avoided provider work.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @covers \antivirus_verdict\local\operation_counts
 * @covers \antivirus_verdict\local\scan_service
 */
final class operation_accounting_test extends \advanced_testcase {
    /**
     * One admitted unknown hash lookup adds one lookup and nothing else.
     */
    public function test_hash_lookup_increments_once(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $before = $this->totals();
        $scanner = $this->scanner($provider, scan_scope::EVERY_UPLOAD);
        $this->assertSame(scanner::SCAN_RESULT_OK, $scanner->scan_file($this->temp_file('fresh'), 'fresh.txt'));
        $after = $this->totals();
        $this->assertSame(1, $provider->lookupcount);
        $this->assertSame($before->hashlookups + 1, $after->hashlookups);
        $this->assertSame($before->uploads, $after->uploads);
        $this->assertSame($before->polls, $after->polls);
        $this->assertSame($before->completedreuses, $after->completedreuses);
        $this->assertSame($before->inflightjoins, $after->inflightjoins);
    }

    /**
     * One provider upload adds one upload.
     */
    public function test_upload_increments_once(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $file = $this->stored('upload.txt', 'upload-bytes');
        $service = $this->service($provider);
        $scan = $service->enqueue_file_scan($file, scan_source::MANUAL, 2);
        $before = $this->totals();
        $service->process_scan((int) $scan->id);
        $after = $this->totals();
        $this->assertSame(1, $provider->uploadcount);
        $this->assertSame($before->uploads + 1, $after->uploads);
        $this->assertSame($before->hashlookups + 1, $after->hashlookups);
        $this->assertSame($before->polls, $after->polls);
    }

    /**
     * One analysis poll adds one poll.
     */
    public function test_poll_increments_once(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $provider->analysisresult = new analysis_result('analysis-x', 'completed', $this->clean_stats());
        $id = $this->waiting(str_repeat('a', 64), 'analysis-x', scan_source::ASSIGN, 'one.txt');
        $before = $this->totals();
        $this->service($provider)->process_scan($id);
        $after = $this->totals();
        $this->assertSame(1, $provider->analysiscount);
        $this->assertSame($before->polls + 1, $after->polls);
        $this->assertSame($before->hashlookups, $after->hashlookups);
        $this->assertSame($before->uploads, $after->uploads);
        $this->assertSame(scan_status::CLEAN, (new scan_repository())->get_by_id($id)->status);
    }

    /**
     * Two rows sharing an analysis count as one poll.
     */
    public function test_shared_analysis_poll_is_counted_once(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $provider->analysisresult = new analysis_result('analysis-x', 'completed', $this->clean_stats());
        $sha = str_repeat('b', 64);
        $first = $this->waiting($sha, 'analysis-x', scan_source::ASSIGN, 'a.txt');
        $second = $this->waiting($sha, 'analysis-x', scan_source::FORUM, 'b.txt');
        $before = $this->totals();
        $this->service($provider)->process_scan($first);
        $this->service($provider)->process_scan($second);
        $after = $this->totals();
        $repo = new scan_repository();
        $this->assertSame(1, $provider->analysiscount);
        $this->assertSame($before->polls + 1, $after->polls);
        $this->assertSame(scan_status::CLEAN, $repo->get_by_id($first)->status);
        $this->assertSame(scan_status::CLEAN, $repo->get_by_id($second)->status);
        $this->assertNotSame($first, $second);
    }

    /**
     * Reusing a completed verdict does not count a provider operation.
     */
    public function test_completed_reuse_does_not_call_provider(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $path = $this->temp_file('known');
        $sha = (new file_hasher())->hash_path($path);
        $this->store_completed($sha, scan_status::MALICIOUS);
        $before = $this->totals();
        $scanner = $this->scanner($provider, scan_scope::EVERY_UPLOAD);
        $this->assertSame(scanner::SCAN_RESULT_FOUND, $scanner->scan_file($path, 'again.txt'));
        $after = $this->totals();
        $this->assertSame(0, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
        $this->assertSame(0, $provider->analysiscount);
        $this->assertSame($before->completedreuses + 1, $after->completedreuses);
        $this->assertSame($before->hashlookups, $after->hashlookups);
        $this->assertSame($before->uploads, $after->uploads);
        $this->assertSame($before->polls, $after->polls);
        $this->assertSame($before->inflightjoins, $after->inflightjoins);
    }

    /**
     * Joining an in-flight analysis does not count an upload.
     */
    public function test_inflight_join_does_not_upload(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $path = $this->temp_file('inflight');
        $sha = (new file_hasher())->hash_path($path);
        $this->waiting($sha, 'analysis-live', scan_source::ASSIGN, 'seed.txt');
        $before = $this->totals();
        $scanner = $this->scanner($provider, scan_scope::EVERY_UPLOAD);
        $this->assertSame(scanner::SCAN_RESULT_OK, $scanner->scan_file($path, 'second.txt'));
        $after = $this->totals();
        $this->assertSame(0, $provider->uploadcount);
        $this->assertSame(0, $provider->lookupcount);
        $this->assertSame($before->inflightjoins + 1, $after->inflightjoins);
        $this->assertSame($before->uploads, $after->uploads);
        $this->assertSame($before->hashlookups, $after->hashlookups);
        $this->assertSame($before->polls, $after->polls);
        $this->assertSame($before->completedreuses, $after->completedreuses);
    }

    /**
     * A failed poll still counts, and the scan stays an error.
     */
    public function test_provider_poll_error_counts_and_stays_error(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $provider->analysisexception = new provider_exception('error_auth', '', 401);
        $id = $this->waiting(str_repeat('c', 64), 'analysis-x', scan_source::ASSIGN, 'bad.txt');
        $before = $this->totals();
        $this->service($provider)->process_scan($id);
        $after = $this->totals();
        $row = (new scan_repository())->get_by_id($id);
        $this->assertSame(1, $provider->analysiscount);
        $this->assertSame($before->polls + 1, $after->polls);
        $this->assertSame(scan_status::ERROR, $row->status);
        $this->assertSame('error_auth', $row->errorcode);
        $this->assertNotSame(scan_status::CLEAN, $row->status);
    }

    /**
     * A still-running poll counts once and leaves the scan pending.
     */
    public function test_still_processing_poll_counts_once(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $provider->analysisresult = new analysis_result('analysis-x', 'queued', null);
        $id = $this->waiting(str_repeat('d', 64), 'analysis-x', scan_source::ASSIGN, 'wait.txt');
        $before = $this->totals();
        $retry = $this->service($provider)->process_scan($id);
        $after = $this->totals();
        $row = (new scan_repository())->get_by_id($id);
        $this->assertTrue($retry);
        $this->assertSame($before->polls + 1, $after->polls);
        $this->assertSame(scan_status::PENDING, $row->status);
        $this->assertSame(scan_phase::POLLING, $row->phase);
        $this->assertSame(0, (int) $row->timecompleted);
    }

    /**
     * A selected-area unknown upload does not touch provider totals.
     */
    public function test_selected_area_unknown_does_not_count(): void {
        global $DB;

        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $before = $this->totals();
        $scanner = $this->scanner($provider, scan_scope::SELECTED_AREAS);
        $this->assertSame(scanner::SCAN_RESULT_OK, $scanner->scan_file($this->temp_file('draft'), 'draft.txt'));
        $after = $this->totals();
        $this->assertSame(0, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
        $this->assertSame(0, $provider->analysiscount);
        $this->assertSame(0, $DB->count_records('antivirus_verdict_scans'));
        $this->assertEquals($before, $after);
    }

    /**
     * A local blocking verdict is not a provider operation or a reuse count.
     */
    public function test_selected_area_blocking_verdict_does_not_count(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $path = $this->temp_file('blocked');
        $sha = (new file_hasher())->hash_path($path);
        $this->store_completed($sha, scan_status::MALICIOUS);
        $before = $this->totals();
        $scanner = $this->scanner($provider, scan_scope::SELECTED_AREAS);
        $this->assertSame(scanner::SCAN_RESULT_FOUND, $scanner->scan_file($path, 'blocked.txt'));
        $after = $this->totals();
        $this->assertSame(0, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
        $this->assertSame(0, $provider->analysiscount);
        $this->assertEquals($before, $after);
    }

    /**
     * Two separate analyses count as two polls.
     */
    public function test_two_analyses_count_two_polls(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $provider->analysisresult = new analysis_result('analysis-x', 'completed', $this->clean_stats());
        $first = $this->waiting(str_repeat('e', 64), 'analysis-x', scan_source::ASSIGN, 'x.txt');
        $second = $this->waiting(str_repeat('f', 64), 'analysis-y', scan_source::FORUM, 'y.txt');
        $before = $this->totals();
        $service = $this->service($provider);
        $service->process_scan($first);
        $service->process_scan($second);
        $after = $this->totals();
        $this->assertSame(2, $provider->analysiscount);
        $this->assertSame($before->polls + 2, $after->polls);
    }

    /**
     * A second writer adds to the stored total instead of replacing it.
     */
    public function test_counter_updates_add_to_the_stored_total(): void {
        global $DB;

        $this->resetAfterTest();
        $this->setAdminUser();
        $counts = new operation_counts();
        $counts->record_poll();
        $id = $DB->get_field_sql('SELECT MIN(id) FROM {antivirus_verdict_opcounts}');
        $DB->set_field('antivirus_verdict_opcounts', 'polls', 40, ['id' => $id]);
        $counts->record_poll();
        $DB->execute('UPDATE {antivirus_verdict_opcounts} SET polls = polls + 3 WHERE id = :id', ['id' => $id]);
        (new operation_counts())->record_poll();
        $this->assertSame(45, $counts->totals()->polls);
    }

    /**
     * A totals failure leaves the provider verdict in place.
     */
    public function test_accounting_failure_does_not_change_verdict(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $provider->analysisresult = new analysis_result('analysis-x', 'completed', $this->clean_stats());
        $id = $this->waiting(str_repeat('9', 64), 'analysis-x', scan_source::ASSIGN, 'still.txt');
        $service = new scan_service(
            provider: $provider,
            repository: new scan_repository(),
            hasher: new file_hasher(),
            config: new plugin_config(enabled: true, maxbytes: 1048576),
            scheduler: new recording_scheduler(),
            operations: new throwing_operation_counts()
        );
        $service->process_scan($id);
        $row = (new scan_repository())->get_by_id($id);
        $this->assertSame(1, $provider->analysiscount);
        $this->assertSame(scan_status::CLEAN, $row->status);
        $this->assertSame(scan_phase::COMPLETED, $row->phase);
        $this->assertDebuggingCalled('antivirus_verdict operation accounting failed');
    }

    /**
     * Current accounted operation totals.
     *
     * @return \stdClass
     */
    private function totals(): \stdClass {
        return (new operation_counts())->totals();
    }

    /**
     * Build a scan service around the fake provider.
     *
     * @param fake_provider $provider Provider.
     * @return scan_service
     */
    private function service(fake_provider $provider): scan_service {
        return new scan_service(
            $provider,
            new scan_repository(),
            new file_hasher(),
            new plugin_config(enabled: true, maxbytes: 1048576),
            new recording_scheduler()
        );
    }

    /**
     * Build a scanner for the given scope.
     *
     * @param fake_provider $provider Provider.
     * @param string $scope Scanning scope.
     * @return scanner
     */
    private function scanner(fake_provider $provider, string $scope): scanner {
        $gate = new antivirus_gate(
            $provider,
            new scan_repository(),
            new file_hasher(),
            new plugin_config(enabled: true, maxbytes: 1048576, scanscope: $scope),
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
     * @param string $source Source.
     * @param string $filename Filename.
     * @return int
     */
    private function waiting(string $sha256, string $analysisid, string $source, string $filename): int {
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
            'source' => $source,
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
        $path = make_request_directory() . '/counts-' . random_int(1, 100000000) . '.bin';
        file_put_contents($path, $contents);
        return $path;
    }
}
