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
 * Tests for scan history retention policy and cleanup.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\enforcement_state;
use antivirus_verdict\local\manual_scan;
use antivirus_verdict\local\plugin_file_lifecycle;
use antivirus_verdict\local\scan_repository;
use antivirus_verdict\local\scan_retention;
use antivirus_verdict\local\scan_retention_cleanup;

/**
 * Retention eligibility, batch purge, and file lifecycle.
 *
 * @covers \antivirus_verdict\local\scan_retention
 * @covers \antivirus_verdict\local\scan_retention_cleanup
 * @covers \antivirus_verdict\local\scan_repository::find_retention_candidates
 */
final class scan_retention_test extends \advanced_testcase {
    /** Frozen clock for deterministic eligibility. */
    private const NOW = 1_800_000_000;

    /**
     * Retention day normalisation rejects ambiguous zero.
     */
    public function test_retention_normalisation(): void {
        $this->assertSame(365, scan_retention::normalise_days(0));
        $this->assertSame(365, scan_retention::normalise_days(-5));
        $this->assertSame(-1, scan_retention::normalise_days(-1));
        $this->assertSame(90, scan_retention::normalise_days(90));
        $this->assertSame(scan_retention::MAX_DAYS, scan_retention::normalise_days(99999));
        $this->assertFalse(scan_retention::purge_enabled(-1));
        $this->assertTrue(scan_retention::purge_enabled(30));
    }

    /**
     * Old completed clean scans are purged.
     */
    public function test_old_clean_scan_is_purged(): void {
        $this->resetAfterTest();
        $repo = new scan_repository();
        $id = $this->insert_terminal_scan($repo, scan_status::CLEAN, scan_phase::COMPLETED, self::NOW - (400 * DAYSECS));
        $stats = (new scan_retention_cleanup($repo, self::NOW))->run(365);
        $this->assertSame(1, $stats['purged']);
        $this->assertNull($repo->get_by_id($id));
    }

    /**
     * Recent completed scans are kept.
     */
    public function test_recent_scan_is_not_purged(): void {
        $this->resetAfterTest();
        $repo = new scan_repository();
        $id = $this->insert_terminal_scan($repo, scan_status::CLEAN, scan_phase::COMPLETED, self::NOW - (10 * DAYSECS));
        $stats = (new scan_retention_cleanup($repo, self::NOW))->run(365);
        $this->assertSame(0, $stats['purged']);
        $this->assertNotNull($repo->get_by_id($id));
    }

    /**
     * Active scans are never purged.
     */
    public function test_active_scan_is_not_purged(): void {
        $this->resetAfterTest();
        $repo = new scan_repository();
        $record = $this->base_record(scan_status::PENDING, scan_phase::POLLING);
        $record->timecompleted = 0;
        $record->timemodified = self::NOW - (500 * DAYSECS);
        $record->timecreated = $record->timemodified;
        $id = $repo->insert($record);
        $stats = (new scan_retention_cleanup($repo, self::NOW))->run(365);
        $this->assertSame(0, $stats['purged']);
        $this->assertNotNull($repo->get_by_id($id));
    }

    /**
     * Malicious scans awaiting enforcement are kept.
     */
    public function test_malicious_without_enforcement_outcome_is_not_purged(): void {
        $this->resetAfterTest();
        $repo = new scan_repository();
        $id = $this->insert_terminal_scan(
            $repo,
            scan_status::MALICIOUS,
            scan_phase::COMPLETED,
            self::NOW - (500 * DAYSECS),
            enforcement_state::NONE
        );
        (new scan_retention_cleanup($repo, self::NOW))->run(365);
        $this->assertNotNull($repo->get_by_id($id));
    }

    /**
     * Malicious scans with pending enforcement are kept.
     */
    public function test_malicious_pending_enforcement_is_not_purged(): void {
        $this->resetAfterTest();
        $repo = new scan_repository();
        $id = $this->insert_terminal_scan(
            $repo,
            scan_status::MALICIOUS,
            scan_phase::COMPLETED,
            self::NOW - (500 * DAYSECS),
            enforcement_state::PENDING
        );
        $stats = (new scan_retention_cleanup($repo, self::NOW))->run(365);
        $this->assertSame(0, $stats['purged']);
        $this->assertNotNull($repo->get_by_id($id));
    }

    /**
     * Malicious scans with completed enforcement follow the same retention policy.
     */
    public function test_malicious_quarantined_scan_is_purged_when_old(): void {
        $this->resetAfterTest();
        $repo = new scan_repository();
        $id = $this->insert_terminal_scan(
            $repo,
            scan_status::MALICIOUS,
            scan_phase::COMPLETED,
            self::NOW - (500 * DAYSECS),
            enforcement_state::QUARANTINED
        );
        $stats = (new scan_retention_cleanup($repo, self::NOW))->run(365);
        $this->assertSame(1, $stats['purged']);
        $this->assertNull($repo->get_by_id($id));
    }

    /**
     * Never-purge configuration disables deletion.
     */
    public function test_never_purge_setting(): void {
        $this->resetAfterTest();
        $repo = new scan_repository();
        $id = $this->insert_terminal_scan($repo, scan_status::SUSPICIOUS, scan_phase::COMPLETED, self::NOW - (900 * DAYSECS));
        $stats = (new scan_retention_cleanup($repo, self::NOW))->run(scan_retention::RETENTION_NEVER);
        $this->assertSame(0, $stats['purged']);
        $this->assertNotNull($repo->get_by_id($id));
    }

    /**
     * Plugin manual copies are removed with the scan when unreferenced.
     */
    public function test_manual_copy_removed_on_purge(): void {
        $this->resetAfterTest();
        $fs = get_file_storage();
        $context = \context_system::instance();
        $copy = $fs->create_file_from_string([
            'contextid' => $context->id,
            'component' => plugin_file_lifecycle::COMPONENT,
            'filearea' => manual_scan::FILEAREA,
            'itemid' => 501,
            'filepath' => '/',
            'filename' => 'retention.bin',
        ], 'bytes');
        $repo = new scan_repository();
        $record = $this->base_record(scan_status::CLEAN, scan_phase::COMPLETED);
        $record->fileid = $copy->get_id();
        $record->pathnamehash = $copy->get_pathnamehash();
        $record->component = plugin_file_lifecycle::COMPONENT;
        $record->filearea = manual_scan::FILEAREA;
        $record->timecompleted = self::NOW - (500 * DAYSECS);
        $record->timemodified = $record->timecompleted;
        $record->timecreated = $record->timecompleted;
        $id = $repo->insert($record);

        (new scan_retention_cleanup($repo, self::NOW))->run(365);
        $this->assertNull($repo->get_by_id($id));
        $this->assertFalse($fs->get_file_by_id($copy->get_id()));
    }

    /**
     * Assignment files are never deleted by retention cleanup.
     */
    public function test_assignment_file_is_not_deleted(): void {
        $this->resetAfterTest();
        $fs = get_file_storage();
        $assign = $fs->create_file_from_string([
            'contextid' => \context_system::instance()->id,
            'component' => 'assignsubmission_file',
            'filearea' => 'submission_files',
            'itemid' => 601,
            'filepath' => '/',
            'filename' => 'keep.bin',
        ], 'keep');
        $repo = new scan_repository();
        $record = $this->base_record(scan_status::CLEAN, scan_phase::COMPLETED);
        $record->fileid = $assign->get_id();
        $record->pathnamehash = $assign->get_pathnamehash();
        $record->component = 'assignsubmission_file';
        $record->filearea = 'submission_files';
        $record->timecompleted = self::NOW - (500 * DAYSECS);
        $record->timemodified = $record->timecompleted;
        $record->timecreated = $record->timecompleted;
        $id = $repo->insert($record);

        (new scan_retention_cleanup($repo, self::NOW))->run(365);
        $this->assertNull($repo->get_by_id($id));
        $this->assertNotFalse($fs->get_file_by_id($assign->get_id()));
    }

    /**
     * Shared plugin copies survive until the last referencing scan is purged.
     */
    public function test_shared_copy_kept_until_last_reference_gone(): void {
        $this->resetAfterTest();
        $fs = get_file_storage();
        $copy = $fs->create_file_from_string([
            'contextid' => \context_system::instance()->id,
            'component' => plugin_file_lifecycle::COMPONENT,
            'filearea' => manual_scan::FILEAREA,
            'itemid' => 701,
            'filepath' => '/',
            'filename' => 'shared.bin',
        ], 'shared');
        $repo = new scan_repository();
        $old = self::NOW - (500 * DAYSECS);
        $first = $this->base_record(scan_status::CLEAN, scan_phase::COMPLETED);
        $first->fileid = $copy->get_id();
        $first->pathnamehash = $copy->get_pathnamehash();
        $first->component = plugin_file_lifecycle::COMPONENT;
        $first->filearea = manual_scan::FILEAREA;
        $first->timecompleted = $old;
        $first->timemodified = $old;
        $first->timecreated = $old;
        $firstid = $repo->insert($first);

        $second = $this->base_record(scan_status::SUSPICIOUS, scan_phase::COMPLETED);
        $second->fileid = $copy->get_id();
        $second->pathnamehash = $copy->get_pathnamehash();
        $second->component = plugin_file_lifecycle::COMPONENT;
        $second->filearea = manual_scan::FILEAREA;
        $second->timecompleted = self::NOW - (10 * DAYSECS);
        $second->timemodified = $second->timecompleted;
        $second->timecreated = $second->timecompleted;
        $secondid = $repo->insert($second);

        $cleanup = new scan_retention_cleanup($repo, self::NOW);
        $cleanup->run(365);
        $this->assertNull($repo->get_by_id($firstid));
        $this->assertNotNull($repo->get_by_id($secondid));
        $this->assertNotFalse($fs->get_file_by_id($copy->get_id()));

        $updated = $repo->get_by_id($secondid);
        $updated->timecompleted = $old;
        $updated->timemodified = $old;
        $repo->update($updated);

        $cleanup->run(365);
        $this->assertNull($repo->get_by_id($secondid));
        $this->assertFalse($fs->get_file_by_id($copy->get_id()));
    }

    /**
     * Missing plugin copies do not abort the purge run.
     */
    public function test_missing_copy_does_not_block_purge(): void {
        $this->resetAfterTest();
        $repo = new scan_repository();
        $record = $this->base_record(scan_status::ERROR, scan_phase::FAILED);
        $record->fileid = 999999999;
        $record->pathnamehash = str_repeat('a', 40);
        $record->timecompleted = self::NOW - (500 * DAYSECS);
        $record->timemodified = $record->timecompleted;
        $record->timecreated = $record->timecompleted;
        $id = $repo->insert($record);
        $stats = (new scan_retention_cleanup($repo, self::NOW))->run(365);
        $this->assertSame(1, $stats['purged']);
        $this->assertNull($repo->get_by_id($id));
    }

    /**
     * Candidate query never returns active scans.
     */
    public function test_active_scan_not_in_retention_candidates(): void {
        $this->resetAfterTest();
        $repo = new scan_repository();
        $record = $this->base_record(scan_status::PENDING, scan_phase::POLLING);
        $record->timecompleted = 0;
        $record->timemodified = self::NOW - (500 * DAYSECS);
        $record->timecreated = $record->timemodified;
        $repo->insert($record);
        $cutoff = scan_retention::cutoff_timestamp(self::NOW, 365);
        $this->assertSame([], $repo->find_retention_candidates($cutoff, 50));
    }

    /**
     * One scheduled run can process more than a single batch.
     */
    public function test_large_backlog_is_purged_in_one_run(): void {
        $this->resetAfterTest();
        $repo = new scan_repository();
        $old = self::NOW - (500 * DAYSECS);
        $ids = [];
        $total = scan_retention_cleanup::BATCH_SIZE + 3;
        for ($i = 0; $i < $total; $i++) {
            $ids[] = $this->insert_terminal_scan($repo, scan_status::NOTSCANNED, scan_phase::SKIPPED, $old);
        }
        $stats = (new scan_retention_cleanup($repo, self::NOW))->run(365);
        $this->assertSame($total, $stats['purged']);
        $this->assertGreaterThan(1, $stats['batches']);
        foreach ($ids as $id) {
            $this->assertNull($repo->get_by_id($id));
        }
    }

    /**
     * A second run after a complete purge is a no-op.
     */
    public function test_second_run_after_complete_purge_is_safe(): void {
        $this->resetAfterTest();
        $repo = new scan_repository();
        $id = $this->insert_terminal_scan($repo, scan_status::CLEAN, scan_phase::COMPLETED, self::NOW - (500 * DAYSECS));
        $cleanup = new scan_retention_cleanup($repo, self::NOW);
        $this->assertSame(1, $cleanup->run(365)['purged']);
        $this->assertSame(0, $cleanup->run(365)['purged']);
        $this->assertNull($repo->get_by_id($id));
    }

    /**
     * Failed terminal scans use the same retention window.
     */
    public function test_old_error_scan_is_purged(): void {
        $this->resetAfterTest();
        $repo = new scan_repository();
        $record = $this->base_record(scan_status::ERROR, scan_phase::FAILED);
        $record->errorcode = 'error_network';
        $record->timecompleted = self::NOW - (500 * DAYSECS);
        $record->timemodified = $record->timecompleted;
        $record->timecreated = $record->timecompleted;
        $id = $repo->insert($record);
        (new scan_retention_cleanup($repo, self::NOW))->run(365);
        $this->assertNull($repo->get_by_id($id));
    }

    /**
     * Site config retention affects eligibility after save.
     */
    public function test_configured_retention_days(): void {
        $this->resetAfterTest();
        set_config('scanretentiondays', 30, 'antivirus_verdict');
        $this->assertSame(30, scan_retention::days_from_config());
        $repo = new scan_repository();
        $recent = $this->insert_terminal_scan($repo, scan_status::CLEAN, scan_phase::COMPLETED, self::NOW - (20 * DAYSECS));
        $old = $this->insert_terminal_scan($repo, scan_status::CLEAN, scan_phase::COMPLETED, self::NOW - (40 * DAYSECS));
        (new scan_retention_cleanup($repo, self::NOW))->run();
        $this->assertNotNull($repo->get_by_id($recent));
        $this->assertNull($repo->get_by_id($old));
    }

    /**
     * Insert a terminal scan row.
     *
     * @param scan_repository $repo Repository.
     * @param string $status User-facing status.
     * @param string $phase Internal phase.
     * @param int $completed Time completed.
     * @param string $enforcement Enforcement outcome.
     * @return int Scan id.
     */
    private function insert_terminal_scan(
        scan_repository $repo,
        string $status,
        string $phase,
        int $completed,
        string $enforcement = enforcement_state::NONE
    ): int {
        $record = $this->base_record($status, $phase);
        $record->enforcement = $enforcement;
        $record->timecompleted = $completed;
        $record->timemodified = $completed;
        $record->timecreated = $completed - DAYSECS;
        return $repo->insert($record);
    }

    /**
     * Minimal scan row for tests.
     *
     * @param string $status Status.
     * @param string $phase Phase.
     * @return \stdClass
     */
    private function base_record(string $status, string $phase): \stdClass {
        $record = new \stdClass();
        $record->fileid = 0;
        $record->contenthash = null;
        $record->pathnamehash = '';
        $record->contextid = \context_system::instance()->id;
        $record->courseid = 0;
        $record->component = 'user';
        $record->filearea = 'draft';
        $record->itemid = 0;
        $record->filepath = '/';
        $record->filename = 'test.bin';
        $record->userid = 2;
        $record->source = scan_source::MANUAL;
        $record->sha256 = hash('sha256', random_bytes(8));
        $record->filesize = 4;
        $record->mimetype = null;
        $record->status = $status;
        $record->phase = $phase;
        $record->vtanalysisid = null;
        $record->vtfileid = null;
        $record->malicious = 0;
        $record->suspicious = 0;
        $record->undetected = 0;
        $record->harmless = 0;
        $record->timeout = 0;
        $record->totalengines = 0;
        $record->errorcode = null;
        $record->enforcement = enforcement_state::NONE;
        $record->pollattempts = 0;
        $record->timelastpoll = 0;
        $record->timesubmitted = 0;
        $record->timecreated = self::NOW;
        $record->timemodified = self::NOW;
        $record->timecompleted = 0;
        return $record;
    }
}
