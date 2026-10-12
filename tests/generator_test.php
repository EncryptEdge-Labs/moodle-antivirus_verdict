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
 * Tests for the Verdict data generator (Behat / PHPUnit fixtures).
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\scan_access;
use antivirus_verdict\local\scan_repository;

/**
 * Verdict plugin generator inserts deterministic scan rows.
 *
 * @covers \antivirus_verdict_generator
 */
final class generator_test extends \advanced_testcase {
    /**
     * Generator inserts rows visible to admins without provider calls.
     */
    public function test_create_scan_fixture(): void {
        $this->resetAfterTest();
        $gen = $this->getDataGenerator()->get_plugin_generator('antivirus_verdict');
        $scan = $gen->create_scan(['filename' => 'gen-test.bin', 'status' => scan_status::CLEAN]);
        $this->assertNotEmpty($scan->id);
        $loaded = (new scan_repository())->get_by_id((int) $scan->id);
        $this->assertSame('gen-test.bin', $loaded->filename);
        $this->assertSame(scan_status::CLEAN, $loaded->status);
        $this->setAdminUser();
        $this->assertTrue(scan_access::can_view_scan($loaded));
    }
}
