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

namespace antivirus_verdict;

use antivirus_verdict\local\private_files_sweep;

/**
 * Tests for private files sweep.
 *
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @covers \antivirus_verdict\local\private_files_sweep
 */
final class private_files_sweep_test extends \advanced_testcase {
    /**
     * Sweep does nothing when disabled.
     */
    public function test_sweep_skips_when_disabled(): void {
        $this->resetAfterTest();
        set_config('privatescan', 0, 'antivirus_verdict');
        $this->assertSame(0, private_files_sweep::from_site_config()->run_scheduled_batch());
    }
}
