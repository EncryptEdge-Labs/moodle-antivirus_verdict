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
 * Tests for product status normalisation.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\result_normaliser;


/**
 * Detection-count mapping.
 *
 * @covers \antivirus_verdict\local\result_normaliser
 */
final class result_normaliser_test extends \advanced_testcase {
    /**
     * Malicious outranks suspicious.
     */
    public function test_malicious_outranks_suspicious(): void {
        $normaliser = new result_normaliser();
        $this->assertSame(scan_status::MALICIOUS, $normaliser->status_from_stats([
            'malicious' => 1,
            'suspicious' => 9,
        ]));
        $this->assertSame(scan_status::SUSPICIOUS, $normaliser->status_from_stats([
            'malicious' => 0,
            'suspicious' => 1,
        ]));
        $this->assertSame(scan_status::CLEAN, $normaliser->status_from_stats([
            'malicious' => 0,
            'suspicious' => 0,
            'harmless' => 3,
        ]));
        $this->assertNull($normaliser->status_from_stats(null));
        $this->assertNull($normaliser->status_from_stats([]));
    }

    /**
     * Missing counts stay null rather than zero.
     */
    public function test_persistable_counts_preserve_null(): void {
        $counts = (new result_normaliser())->persistable_counts(['malicious' => 2]);
        $this->assertSame(2, $counts['malicious']);
        $this->assertNull($counts['suspicious']);
        $this->assertSame(2, $counts['totalengines']);
        $empty = (new result_normaliser())->persistable_counts(null);
        $this->assertNull($empty['totalengines']);
    }

    /**
     * GUI URLs are derived from a validated SHA-256 only.
     */
    public function test_public_report_url(): void {
        $hash = str_repeat('a', 64);
        $this->assertSame(
            'https://www.virustotal.com/gui/file/' . $hash,
            result_normaliser::public_report_url($hash)
        );
        $this->assertNull(result_normaliser::public_report_url('https://evil.example/x'));
        $this->assertNull(result_normaliser::public_report_url('not-a-hash'));
    }
}
