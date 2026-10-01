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
 * One provider poll applied to every scan waiting on that analysis.
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
use antivirus_verdict\provider\analysis_result;
use antivirus_verdict\provider\provider_exception;
use antivirus_verdict\tests\fake_provider;
use antivirus_verdict\tests\recording_scheduler;

/**
 * Phase 3: shared in-flight analysis is polled once.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @covers \antivirus_verdict\local\scan_service
 * @covers \antivirus_verdict\local\scan_repository
 */
final class scan_poll_fanout_test extends \advanced_testcase {
    /**
     * Two audit rows sharing an analysis are both finalised by one poll.
     */
    public function test_shared_analysis_is_polled_once(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $provider->analysisresult = new analysis_result('analysis-x', 'completed', $this->clean_stats());
        $sha = str_repeat('a', 64);
        $first = $this->waiting($sha, 'analysis-x', scan_source::ASSIGN, 'assign.txt', 11);
        $second = $this->waiting($sha, 'analysis-x', scan_source::FORUM, 'forum.txt', 22);
        $this->service($provider)->process_scan($first);

        $repo = new scan_repository();
        $assign = $repo->get_by_id($first);
        $forum = $repo->get_by_id($second);
        $this->assertSame(1, $provider->analysiscount);
        $this->assertNotSame($first, $second);
        $this->assertSame(scan_status::CLEAN, $assign->status);
        $this->assertSame(scan_status::CLEAN, $forum->status);
        $this->assertSame(scan_phase::COMPLETED, $assign->phase);
        $this->assertSame(scan_phase::COMPLETED, $forum->phase);
        $this->assertSame('analysis-x', $assign->vtanalysisid);
        $this->assertSame('analysis-x', $forum->vtanalysisid);
        $this->assertSame(scan_source::ASSIGN, $assign->source);
        $this->assertSame(scan_source::FORUM, $forum->source);
        $this->assertSame(11, (int) $assign->userid);
        $this->assertSame(22, (int) $forum->userid);
        $this->assertSame('assign.txt', $assign->filename);
        $this->assertSame('forum.txt', $forum->filename);
        $this->service($provider)->process_scan($second);
        $this->assertSame(1, $provider->analysiscount);
    }

    /**
     * A poll of analysis X does not finalise a row waiting on analysis Y.
     */
    public function test_different_analysis_ids_stay_independent(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $provider->analysisresult = new analysis_result('analysis-x', 'completed', $this->clean_stats());
        $sha = str_repeat('b', 64);
        $first = $this->waiting($sha, 'analysis-x', scan_source::ASSIGN, 'one.txt', 3);
        $other = $this->waiting($sha, 'analysis-y', scan_source::FORUM, 'two.txt', 4);
        $this->service($provider)->process_scan($first);

        $repo = new scan_repository();
        $done = $repo->get_by_id($first);
        $untouched = $repo->get_by_id($other);
        $this->assertSame(1, $provider->analysiscount);
        $this->assertSame(scan_status::CLEAN, $done->status);
        $this->assertSame(scan_status::PENDING, $untouched->status);
        $this->assertSame(scan_phase::POLLING, $untouched->phase);
        $this->assertSame('analysis-y', $untouched->vtanalysisid);
        $this->assertSame('two.txt', $untouched->filename);
    }

    /**
     * A different SHA is not updated even when processed in the same service.
     */
    public function test_different_sha_is_not_fanned_out(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $provider->analysisresult = new analysis_result('analysis-x', 'completed', $this->malicious_stats());
        $first = $this->waiting(str_repeat('c', 64), 'analysis-x', scan_source::ASSIGN, 'x.txt', 5);
        $other = $this->waiting(str_repeat('d', 64), 'analysis-y', scan_source::MANUAL, 'y.txt', 6);
        $this->service($provider)->process_scan($first);

        $otherrow = (new scan_repository())->get_by_id($other);
        $this->assertSame(1, $provider->analysiscount);
        $this->assertSame(scan_status::PENDING, $otherrow->status);
        $this->assertSame(scan_phase::POLLING, $otherrow->phase);
        $this->assertSame('analysis-y', $otherrow->vtanalysisid);
        $this->assertSame(str_repeat('d', 64), $otherrow->sha256);
    }

    /**
     * A still-running analysis leaves every waiting row pending.
     */
    public function test_still_processing_does_not_finalise(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $provider->analysisresult = new analysis_result('analysis-x', 'in-progress', null);
        $sha = str_repeat('e', 64);
        $first = $this->waiting($sha, 'analysis-x', scan_source::ASSIGN, 'wait-a.txt', 7);
        $second = $this->waiting($sha, 'analysis-x', scan_source::FORUM, 'wait-b.txt', 8);
        $retry = $this->service($provider)->process_scan($first);

        $repo = new scan_repository();
        $a = $repo->get_by_id($first);
        $b = $repo->get_by_id($second);
        $this->assertTrue($retry);
        $this->assertSame(1, $provider->analysiscount);
        $this->assertSame(scan_status::PENDING, $a->status);
        $this->assertSame(scan_status::PENDING, $b->status);
        $this->assertSame(scan_phase::POLLING, $a->phase);
        $this->assertSame(scan_phase::POLLING, $b->phase);
        $this->assertGreaterThan(0, (int) $a->timelastpoll);
        $this->assertGreaterThan(0, (int) $b->timelastpoll);
        $this->assertSame(0, (int) $a->timecompleted);
        $this->assertSame(0, (int) $b->timecompleted);
        $this->assertNotSame(scan_status::CLEAN, $a->status);
    }

    /**
     * A provider poll error is stored as an error on every waiting row.
     */
    public function test_provider_poll_error_is_not_clean(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $provider->analysisexception = new provider_exception('error_auth', '', 401);
        $sha = str_repeat('f', 64);
        $first = $this->waiting($sha, 'analysis-x', scan_source::ASSIGN, 'bad-a.txt', 9);
        $second = $this->waiting($sha, 'analysis-x', scan_source::FORUM, 'bad-b.txt', 10);
        $this->service($provider)->process_scan($first);

        $repo = new scan_repository();
        $a = $repo->get_by_id($first);
        $b = $repo->get_by_id($second);
        $this->assertSame(1, $provider->analysiscount);
        $this->assertSame(scan_status::ERROR, $a->status);
        $this->assertSame(scan_status::ERROR, $b->status);
        $this->assertSame(scan_phase::FAILED, $a->phase);
        $this->assertSame(scan_phase::FAILED, $b->phase);
        $this->assertSame('error_auth', $a->errorcode);
        $this->assertSame('error_auth', $b->errorcode);
        $this->assertNotSame(scan_status::CLEAN, $a->status);
        $this->assertNotSame(scan_status::CLEAN, $b->status);
        $this->assertSame(scan_source::ASSIGN, $a->source);
        $this->assertSame(scan_source::FORUM, $b->source);
    }

    /**
     * A malicious poll reaches each scan event and then the existing enforcer.
     */
    public function test_malicious_result_fans_out_through_enforcement(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $provider->analysisresult = new analysis_result('analysis-x', 'completed', $this->malicious_stats());
        $sha = str_repeat('1', 64);
        $first = $this->waiting($sha, 'analysis-x', scan_source::ASSIGN, 'bad-assign.txt', 12);
        $second = $this->waiting($sha, 'analysis-x', scan_source::MANUAL, 'bad-manual.txt', 13);
        $this->service($provider)->process_scan($first);

        $repo = new scan_repository();
        $assign = $repo->get_by_id($first);
        $manual = $repo->get_by_id($second);
        $this->assertSame(1, $provider->analysiscount);
        $this->assertSame(scan_status::MALICIOUS, $assign->status);
        $this->assertSame(scan_status::MALICIOUS, $manual->status);
        $this->assertNotSame(enforcement_state::NONE, $assign->enforcement);
        $this->assertNotSame(enforcement_state::NONE, $manual->enforcement);
        $this->assertSame(scan_source::ASSIGN, $assign->source);
        $this->assertSame(scan_source::MANUAL, $manual->source);
        $this->assertSame(3, (int) $assign->malicious);
        $this->assertSame(3, (int) $manual->malicious);
    }

    /**
     * Suspicious stays suspicious, and the upload gate still applies its own policy.
     */
    public function test_suspicious_result_respects_suspicious_policy(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $provider->analysisresult = new analysis_result('analysis-x', 'completed', [
            'malicious' => 0,
            'suspicious' => 2,
            'undetected' => 4,
            'harmless' => 1,
            'timeout' => 0,
        ]);
        $path = $this->temp_file('suspicious-bytes');
        $sha = (new file_hasher())->hash_path($path);
        $first = $this->waiting($sha, 'analysis-x', scan_source::ASSIGN, 'sus-a.txt', 14);
        $second = $this->waiting($sha, 'analysis-x', scan_source::FORUM, 'sus-b.txt', 15);
        $this->service($provider)->process_scan($first);

        $repo = new scan_repository();
        $a = $repo->get_by_id($first);
        $b = $repo->get_by_id($second);
        $this->assertSame(scan_status::SUSPICIOUS, $a->status);
        $this->assertSame(scan_status::SUSPICIOUS, $b->status);
        $this->assertSame(1, $provider->analysiscount);

        $blocked = $this->scanner($provider, scan_policy::BLOCK);
        try {
            $blocked->scan_file($path, 'later-block.txt');
            $this->fail('Suspicious policy block must refuse the later upload.');
        } catch (\core\antivirus\scanner_exception $e) {
            $this->assertSame('error_suspiciousblocked', $e->errorcode);
        }
        $allowed = $this->scanner($provider, scan_policy::ALLOW);
        $this->assertSame(scanner::SCAN_RESULT_OK, $allowed->scan_file($path, 'later-allow.txt'));
        $this->assertSame(1, $provider->analysiscount);
        $this->assertSame(0, $provider->lookupcount);
    }

    /**
     * A child poll must not copy its verdict onto the open archive parent.
     */
    public function test_archive_parent_is_not_finalised_by_child_fanout(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $provider->analysisresult = new analysis_result('child-analysis', 'completed', $this->clean_stats());
        $parentsha = str_repeat('9', 64);
        $childsha = str_repeat('8', 64);
        $parent = $this->waiting($parentsha, 'parent-analysis', scan_source::ANTIVIRUS, 'pack.zip', 2);
        $repo = new scan_repository();
        $parentrow = $repo->get_by_id($parent);
        $parentrow->phase = scan_phase::COMPLETED;
        $parentrow->status = scan_status::PENDING;
        $parentrow->archiveoutcome = archive_outcome::PROCESSING;
        $parentrow->malicious = 0;
        $parentrow->harmless = 1;
        $repo->update($parentrow);

        $child = $this->waiting($childsha, 'child-analysis', scan_source::ANTIVIRUS, 'member.txt', 2, $parent);
        $sibling = $this->waiting($childsha, 'child-analysis', scan_source::MANUAL, 'member-again.txt', 4);
        $otherchild = $this->waiting(str_repeat('7', 64), 'other-analysis', scan_source::ANTIVIRUS, 'other.txt', 2, $parent);

        $this->service($provider)->process_scan($child);

        $parentafter = $repo->get_by_id($parent);
        $childafter = $repo->get_by_id($child);
        $siblingafter = $repo->get_by_id($sibling);
        $otherafter = $repo->get_by_id($otherchild);
        $this->assertSame(1, $provider->analysiscount);
        $this->assertSame(scan_status::CLEAN, $childafter->status);
        $this->assertSame(scan_status::CLEAN, $siblingafter->status);
        $this->assertSame(scan_status::PENDING, $parentafter->status);
        $this->assertSame(scan_phase::COMPLETED, $parentafter->phase);
        $this->assertSame(archive_outcome::PROCESSING, $parentafter->archiveoutcome);
        $this->assertSame('parent-analysis', $parentafter->vtanalysisid);
        $this->assertSame(0, (int) $parentafter->malicious);
        $this->assertSame(scan_status::PENDING, $otherafter->status);
        $this->assertSame(scan_phase::POLLING, $otherafter->phase);
        $this->assertNotSame(scan_status::CLEAN, $parentafter->status);
    }

    /**
     * Selected-area unknown uploads still never enter the provider.
     */
    public function test_selected_areas_unknown_stays_outside_provider_path(): void {
        global $DB;

        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $scanner = $this->scanner($provider, scan_policy::BLOCK, scan_scope::SELECTED_AREAS);
        $this->assertSame(scanner::SCAN_RESULT_OK, $scanner->scan_file($this->temp_file('draft'), 'draft.txt'));
        $this->assertSame(0, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
        $this->assertSame(0, $provider->analysiscount);
        $this->assertSame(0, $DB->count_records('antivirus_verdict_scans'));
    }

    /**
     * Every-upload unknown files are still admitted onto the central path.
     */
    public function test_every_upload_unknown_uses_central_path(): void {
        global $DB;

        $this->resetAfterTest();
        $this->setAdminUser();
        $provider = new fake_provider();
        $scanner = $this->scanner($provider, scan_policy::ALLOW, scan_scope::EVERY_UPLOAD);
        $this->assertSame(scanner::SCAN_RESULT_OK, $scanner->scan_file($this->temp_file('fresh'), 'fresh.txt'));
        $this->assertSame(1, $provider->lookupcount);
        $this->assertSame(0, $provider->uploadcount);
        $this->assertSame(0, $provider->analysiscount);
        $this->assertTrue($DB->record_exists('antivirus_verdict_scans', ['filename' => 'fresh.txt']));
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
     * Build a scanner for the given suspicious policy and scope.
     *
     * @param fake_provider $provider Provider.
     * @param string $suspicious Suspicious policy.
     * @param string $scope Scanning scope.
     * @return scanner
     */
    private function scanner(
        fake_provider $provider,
        string $suspicious,
        string $scope = scan_scope::EVERY_UPLOAD
    ): scanner {
        $gate = new antivirus_gate(
            $provider,
            new scan_repository(),
            new file_hasher(),
            new plugin_config(
                enabled: true,
                maxbytes: 1048576,
                suspiciouspolicy: $suspicious,
                scanscope: $scope
            ),
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
     * @param string $source Scan source.
     * @param string $filename Filename.
     * @param int $userid User id.
     * @param int $parentscanid Parent scan id.
     * @return int
     */
    private function waiting(
        string $sha256,
        string $analysisid,
        string $source,
        string $filename,
        int $userid,
        int $parentscanid = 0
    ): int {
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
            'userid' => $userid,
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
            'parentscanid' => $parentscanid,
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
     * Engine counts for a malicious result.
     *
     * @return array<string, int>
     */
    private function malicious_stats(): array {
        return [
            'malicious' => 3,
            'suspicious' => 0,
            'undetected' => 5,
            'harmless' => 1,
            'timeout' => 0,
        ];
    }

    /**
     * Write bytes to a temporary file.
     *
     * @param string $contents Bytes.
     * @return string
     */
    private function temp_file(string $contents): string {
        $path = make_request_directory() . '/poll-' . random_int(1, 100000000) . '.bin';
        file_put_contents($path, $contents);
        return $path;
    }
}
