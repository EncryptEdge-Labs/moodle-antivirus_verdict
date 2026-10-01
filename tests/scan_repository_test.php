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
 * Tests for scan record persistence.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\scan_repository;


/**
 * Repository create, find, and update behaviour.
 *
 * @covers \antivirus_verdict\local\scan_repository
 */
final class scan_repository_test extends \advanced_testcase {
    /**
     * Insert, load, update, and look up by hash and analysis id.
     */
    public function test_create_find_update(): void {
        $this->resetAfterTest();
        $repo = new scan_repository();
        $now = time();
        $record = (object) [
            'fileid' => 9,
            'contenthash' => str_repeat('a', 40),
            'pathnamehash' => str_repeat('b', 40),
            'contextid' => 1,
            'courseid' => 0,
            'component' => 'antivirus_verdict',
            'filearea' => 'unittest',
            'itemid' => 3,
            'filepath' => '/',
            'filename' => 'a.bin',
            'userid' => 2,
            'source' => scan_source::MANUAL,
            'sha256' => str_repeat('c', 64),
            'filesize' => 4,
            'mimetype' => 'application/octet-stream',
            'status' => scan_status::PENDING,
            'phase' => scan_phase::POLLING,
            'vtanalysisid' => 'analysis-repo-1',
            'vtfileid' => str_repeat('c', 64),
            'malicious' => null,
            'suspicious' => null,
            'undetected' => null,
            'harmless' => null,
            'timeout' => null,
            'totalengines' => null,
            'errorcode' => null,
            'pollattempts' => 0,
            'timelastpoll' => 0,
            'timesubmitted' => $now,
            'timecreated' => $now,
            'timemodified' => $now,
            'timecompleted' => 0,
        ];
        $id = $repo->insert($record);
        $this->assertGreaterThan(0, $id);

        $loaded = $repo->get_by_id($id);
        $this->assertNotNull($loaded);
        $this->assertSame('analysis-repo-1', $loaded->vtanalysisid);
        $this->assertNull($loaded->malicious);

        $loaded->phase = scan_phase::COMPLETED;
        $loaded->status = scan_status::CLEAN;
        $loaded->malicious = 0;
        $repo->update($loaded);

        $this->assertSame(scan_phase::COMPLETED, $repo->get_by_id($id)->phase);
        $this->assertNotNull($repo->find_by_analysis_id('analysis-repo-1'));
        $this->assertCount(1, $repo->find_by_sha256(str_repeat('c', 64)));
        $this->assertNull($repo->find_active_by_pathnamehash(str_repeat('b', 40)));
    }

    /**
     * Active lookup matches in-flight phases only.
     */
    public function test_active_pathnamehash_lookup(): void {
        $this->resetAfterTest();
        $repo = new scan_repository();
        $now = time();
        $base = [
            'fileid' => 1,
            'contenthash' => str_repeat('1', 40),
            'pathnamehash' => str_repeat('2', 40),
            'contextid' => 1,
            'courseid' => 0,
            'component' => 'antivirus_verdict',
            'filearea' => 'unittest',
            'itemid' => 0,
            'filepath' => '/',
            'filename' => 'a.bin',
            'userid' => 0,
            'source' => scan_source::MANUAL,
            'sha256' => str_repeat('3', 64),
            'filesize' => 1,
            'mimetype' => 'text/plain',
            'vtanalysisid' => null,
            'vtfileid' => null,
            'malicious' => null,
            'suspicious' => null,
            'undetected' => null,
            'harmless' => null,
            'timeout' => null,
            'totalengines' => null,
            'errorcode' => null,
            'pollattempts' => 0,
            'timelastpoll' => 0,
            'timesubmitted' => 0,
            'timecreated' => $now,
            'timemodified' => $now,
            'timecompleted' => 0,
        ];
        $done = (object) array_merge($base, [
            'status' => scan_status::CLEAN,
            'phase' => scan_phase::COMPLETED,
        ]);
        $repo->insert($done);
        $this->assertNull($repo->find_active_by_pathnamehash(str_repeat('2', 40)));

        $active = (object) array_merge($base, [
            'status' => scan_status::PENDING,
            'phase' => scan_phase::HASHLOOKUP,
        ]);
        $activeid = $repo->insert($active);
        $found = $repo->find_active_by_pathnamehash(str_repeat('2', 40));
        $this->assertNotNull($found);
        $this->assertEquals($activeid, $found->id);
    }

    /**
     * Stale active lookup is SQL-limited and ignores completed rows.
     */
    public function test_find_stale_active_is_bounded(): void {
        $this->resetAfterTest();
        $repo = new scan_repository();
        $now = time();
        $base = [
            'fileid' => 1,
            'contenthash' => str_repeat('1', 40),
            'pathnamehash' => str_repeat('9', 40),
            'contextid' => 1,
            'courseid' => 0,
            'component' => 'antivirus_verdict',
            'filearea' => 'unittest',
            'itemid' => 0,
            'filepath' => '/',
            'filename' => 'stale.bin',
            'userid' => 0,
            'source' => scan_source::MANUAL,
            'sha256' => str_repeat('3', 64),
            'filesize' => 1,
            'mimetype' => 'text/plain',
            'vtanalysisid' => null,
            'vtfileid' => null,
            'malicious' => null,
            'suspicious' => null,
            'undetected' => null,
            'harmless' => null,
            'timeout' => null,
            'totalengines' => null,
            'errorcode' => null,
            'pollattempts' => 0,
            'timelastpoll' => 0,
            'timesubmitted' => 0,
            'timecompleted' => 0,
        ];
        $repo->insert((object) array_merge($base, [
            'status' => scan_status::CLEAN,
            'phase' => scan_phase::COMPLETED,
            'timecreated' => $now - 10000,
            'timemodified' => $now - 10000,
        ]));
        $staleid = $repo->insert((object) array_merge($base, [
            'pathnamehash' => str_repeat('8', 40),
            'filename' => 'active.bin',
            'status' => scan_status::PENDING,
            'phase' => scan_phase::QUEUED,
            'timecreated' => $now - 9000,
            'timemodified' => $now - 9000,
        ]));
        $found = $repo->find_stale_active($now - 100, 10);
        $ids = array_map(static fn($row) => (int) $row->id, $found);
        $this->assertContains($staleid, $ids);
        $this->assertSame([], $repo->find_stale_active($now - 100, 0));
    }

    /**
     * Invalid ids do not query unsafely.
     */
    public function test_get_by_id_rejects_non_positive(): void {
        $this->resetAfterTest();
        $this->assertNull((new scan_repository())->get_by_id(0));
        $this->assertNull((new scan_repository())->find_by_analysis_id(''));
    }
}
