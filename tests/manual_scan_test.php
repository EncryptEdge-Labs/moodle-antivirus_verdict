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
 * Tests for the manual scan adapter.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\file_hasher;
use antivirus_verdict\local\manual_scan;
use antivirus_verdict\local\plugin_config;
use antivirus_verdict\local\plugin_file_lifecycle;
use antivirus_verdict\local\scan_repository;
use antivirus_verdict\local\scan_service;
use antivirus_verdict\archive_outcome;
use antivirus_verdict\scan_phase;
use antivirus_verdict\scan_source;
use antivirus_verdict\scan_status;
use antivirus_verdict\tests\fake_provider;
use antivirus_verdict\tests\recording_scheduler;
use antivirus_verdict\tests\test_credentials;


/**
 * Manual scan queues through the existing engine.
 *
 * @covers \antivirus_verdict\local\manual_scan
 */
final class manual_scan_test extends \advanced_testcase {
    /**
     * A Moodle stored file is queued asynchronously with source manual.
     */
    public function test_queue_stored_file_is_async_manual(): void {
        $this->resetAfterTest();
        $course = $this->getDataGenerator()->create_course();
        $teacher = $this->getDataGenerator()->create_and_enrol($course, 'editingteacher');
        $context = \context_course::instance($course->id);
        $provider = new fake_provider();
        $scheduler = new recording_scheduler();
        $manual = $this->make_manual($provider, $scheduler, true);
        $file = $this->create_file('report.pdf', 'payload');

        $scan = $manual->queue_stored_file($file, $context, (int) $teacher->id);

        $this->assertSame(scan_source::MANUAL, $scan->source);
        $owner = (int) $file->get_userid();
        $expectedowner = ($owner > 0 && \core_user::is_real_user($owner, true)) ? $owner : 0;
        $this->assertSame((int) $teacher->id, (int) $scan->initiatedby);
        $this->assertSame($expectedowner, (int) $scan->userid);
        $this->assertSame((int) $context->id, (int) $scan->contextid);
        $this->assertSame((int) $course->id, (int) $scan->courseid);
        $this->assertSame(manual_scan::FILEAREA, $scan->filearea);
        $this->assertSame('antivirus_verdict', $scan->component);
        $this->assertContains($scan->phase, [scan_phase::QUEUED, scan_phase::HASHLOOKUP, scan_phase::COMPLETED]);
        $this->assertNotSame('', $scan->sha256);
        $this->assertContains((int) $scan->id, $scheduler->queued);
        $this->assertNotEmpty($scheduler->queued);
    }

    /**
     * Manual queue removes a gate preflight row for the same file content.
     */
    public function test_manual_scan_discards_gate_preflight_duplicate(): void {
        global $DB;

        $this->resetAfterTest();
        $course = $this->getDataGenerator()->create_course();
        $teacher = $this->getDataGenerator()->create_and_enrol($course, 'editingteacher');
        $context = \context_course::instance($course->id);
        $content = 'manual-preflight-payload';
        $filename = 'preflight.bin';
        $hasher = new file_hasher();
        $sha256 = hash('sha256', $content);
        $now = time();
        $repo = new scan_repository();
        $preflight = (object) [
            'fileid' => 0,
            'contenthash' => '',
            'pathnamehash' => '',
            'contextid' => \context_system::instance()->id,
            'courseid' => 0,
            'component' => plugin_file_lifecycle::COMPONENT,
            'filearea' => plugin_file_lifecycle::GATE_FILEAREA,
            'itemid' => 0,
            'filepath' => '/',
            'filename' => $filename,
            'userid' => (int) $teacher->id,
            'source' => scan_source::ANTIVIRUS,
            'sha256' => $sha256,
            'filesize' => strlen($content),
            'mimetype' => null,
            'status' => scan_status::ERROR,
            'phase' => scan_phase::FAILED,
            'vtanalysisid' => null,
            'vtfileid' => null,
            'malicious' => null,
            'suspicious' => null,
            'undetected' => null,
            'harmless' => null,
            'timeout' => null,
            'totalengines' => null,
            'errorcode' => 'error_network',
            'enforcement' => 'none',
            'pollattempts' => 0,
            'timelastpoll' => 0,
            'timesubmitted' => 0,
            'timecreated' => $now - 30,
            'timemodified' => $now - 30,
            'timecompleted' => $now - 30,
            'parentscanid' => 0,
            'archiveoutcome' => archive_outcome::NONE,
        ];
        $provider = new fake_provider();
        $manual = $this->make_manual($provider, new recording_scheduler(), true);
        $file = $this->create_file($filename, $content);
        $preflight->sha256 = $hasher->hash_stored_file($file);
        $repo->insert($preflight);

        $scan = $manual->queue_stored_file($file, $context, (int) $teacher->id);

        $this->assertSame(1, $DB->count_records('antivirus_verdict_scans'));
        $this->assertSame(scan_source::MANUAL, $DB->get_field('antivirus_verdict_scans', 'source', ['id' => $scan->id]));
    }

    /**
     * Draft file picker files are resolved through the File API.
     */
    public function test_queue_from_draft(): void {
        $this->resetAfterTest();
        $course = $this->getDataGenerator()->create_course();
        $teacher = $this->getDataGenerator()->create_and_enrol($course, 'editingteacher');
        $this->setUser($teacher);
        $context = \context_course::instance($course->id);
        $provider = new fake_provider();
        $manual = $this->make_manual($provider, new recording_scheduler(), true);
        $draftid = file_get_unused_draft_itemid();
        $fs = get_file_storage();
        $fs->create_file_from_string([
            'contextid' => \context_user::instance($teacher->id)->id,
            'component' => 'user',
            'filearea' => 'draft',
            'itemid' => $draftid,
            'filepath' => '/',
            'filename' => 'from-draft.bin',
        ], 'draft-bytes');

        $scan = $manual->queue_from_draft($draftid, $context, (int) $teacher->id);
        $this->assertSame('from-draft.bin', $scan->filename);
        $scan = $this->run_scan_to_completion($provider, $scan);
        $this->assertGreaterThanOrEqual(1, $provider->lookupcount);
        $this->assertSame(scan_status::CLEAN, $scan->status);
    }

    /**
     * Manual scanning can queue when native antivirus is not enabled, if a key exists.
     */
    public function test_manual_scan_does_not_require_antivirus_enablement(): void {
        $this->resetAfterTest();
        $course = $this->getDataGenerator()->create_course();
        $context = \context_course::instance($course->id);
        $provider = new fake_provider();
        $manual = $this->make_manual($provider, new recording_scheduler(), false);
        $file = $this->create_file('off.bin', 'x');

        $this->assertFalse($manual->can_queue());
        $this->assertSame('scanningincomplete', $manual->unavailable_reason());

        $withkey = $this->make_manual($provider, new recording_scheduler(), true);
        $this->assertTrue($withkey->can_queue());
        $scan = $withkey->queue_stored_file($file, $context, 2);
        $this->assertSame(scan_source::MANUAL, $scan->source);
        $this->run_scan_to_completion($provider, $scan);
        $this->assertGreaterThanOrEqual(1, $provider->lookupcount);
    }

    /**
     * Missing credentials do not queue work.
     */
    public function test_missing_credentials_do_not_queue(): void {
        $this->resetAfterTest();
        $course = $this->getDataGenerator()->create_course();
        $context = \context_course::instance($course->id);
        $provider = new fake_provider();
        $service = new scan_service(
            $provider,
            new scan_repository(),
            new file_hasher(),
            new plugin_config(true, 1048576, false),
            new recording_scheduler()
        );
        $manual = new manual_scan($service, new plugin_config(true, 1048576, false), new test_credentials(''));
        $this->assertFalse($manual->can_queue());
        $this->assertSame('scanningincomplete', $manual->unavailable_reason());
        try {
            $manual->queue_stored_file($this->create_file('a.bin', 'a'), $context, 2);
            $this->fail('Missing credentials should throw.');
        } catch (\moodle_exception $e) {
            $this->assertSame('scanningincomplete', $e->errorcode);
        }
    }

    /**
     * Invalid draft areas fail safely.
     */
    public function test_invalid_draft_is_safe(): void {
        $this->resetAfterTest();
        $user = $this->getDataGenerator()->create_user();
        $manual = $this->make_manual(new fake_provider(), new recording_scheduler(), true);
        $this->expectException(\moodle_exception::class);
        $manual->file_from_draft(0, (int) $user->id);
    }

    /**
     * Two manual queue attempts on different copies create two history rows.
     */
    public function test_two_manual_attempts_create_two_records(): void {
        global $DB;

        $this->resetAfterTest();
        $course = $this->getDataGenerator()->create_course();
        $teacher = $this->getDataGenerator()->create_and_enrol($course, 'editingteacher');
        $context = \context_course::instance($course->id);
        $manual = $this->make_manual(new fake_provider(), new recording_scheduler(), true);
        $manual->queue_stored_file($this->create_file('a.bin', 'a'), $context, (int) $teacher->id);
        $manual->queue_stored_file($this->create_file('a.bin', 'a'), $context, (int) $teacher->id);
        $this->assertSame(2, $DB->count_records('antivirus_verdict_scans', ['source' => scan_source::MANUAL]));
    }

    /**
     * Build a manual scan adapter.
     *
     * @param fake_provider $provider Fake provider.
     * @param recording_scheduler $scheduler Fake scheduler.
     * @param bool $enabled Master switch.
     * @return manual_scan
     */
    private function make_manual(
        fake_provider $provider,
        recording_scheduler $scheduler,
        bool $enabled
    ): manual_scan {
        $this->lastscanservice = new scan_service(
            $provider,
            new scan_repository(),
            new file_hasher(),
            new plugin_config($enabled, 1048576, false),
            $scheduler
        );
        return new manual_scan(
            $this->lastscanservice,
            new plugin_config($enabled, 1048576, false),
            new test_credentials($enabled ? 'unit-test-key' : '')
        );
    }

    /** @var scan_service|null Last service from make_manual(). */
    private ?scan_service $lastscanservice = null;

    /**
     * Drive background processing until the scan reaches a terminal phase.
     *
     * @param fake_provider $provider Provider (unused; kept for call-site clarity).
     * @param \stdClass $scan Scan row.
     * @return \stdClass Updated scan row.
     */
    private function run_scan_to_completion(fake_provider $provider, \stdClass $scan): \stdClass {
        if ($this->lastscanservice === null) {
            return $scan;
        }
        $limit = 0;
        while ($this->lastscanservice->process_scan((int) $scan->id) && $limit < 12) {
            $limit++;
        }
        return (new scan_repository())->get_by_id((int) $scan->id) ?? $scan;
    }

    /**
     * Create a stored file.
     *
     * @param string $filename File name.
     * @param string $content Bytes.
     * @return \stored_file
     */
    private function create_file(string $filename, string $content): \stored_file {
        $fs = get_file_storage();
        return $fs->create_file_from_string([
            'contextid' => \context_system::instance()->id,
            'component' => 'antivirus_verdict',
            'filearea' => 'unittest',
            'itemid' => random_int(1, 100000000),
            'filepath' => '/',
            'filename' => $filename,
        ], $content);
    }
}
