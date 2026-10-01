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

use antivirus_verdict\archive_outcome;
use antivirus_verdict\local\archive_aggregate;

/**
 * Tests for archive status aggregation.
 *
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @covers \antivirus_verdict\local\archive_aggregate
 */
final class archive_aggregate_test extends \advanced_testcase {
    /**
     * Malicious member wins over clean members.
     */
    public function test_malicious_precedence(): void {
        $children = [
            (object) ['status' => scan_status::CLEAN, 'phase' => scan_phase::COMPLETED],
            (object) ['status' => scan_status::MALICIOUS, 'phase' => scan_phase::COMPLETED],
        ];
        $this->assertSame(scan_status::MALICIOUS, archive_aggregate::aggregate_status($children));
    }

    /**
     * Precedence matches product order: malicious > suspicious > error > pending > clean.
     */
    public function test_status_precedence_order(): void {
        $this->assertGreaterThan(
            archive_aggregate::status_rank(scan_status::ERROR),
            archive_aggregate::status_rank(scan_status::SUSPICIOUS)
        );
        $this->assertGreaterThan(
            archive_aggregate::status_rank(scan_status::PENDING),
            archive_aggregate::status_rank(scan_status::ERROR)
        );
        $this->assertGreaterThan(
            archive_aggregate::status_rank(scan_status::CLEAN),
            archive_aggregate::status_rank(scan_status::PENDING)
        );
    }

    /**
     * Suspicious member elevates aggregate over clean peers.
     */
    public function test_suspicious_precedence(): void {
        $children = [
            (object) ['status' => scan_status::CLEAN, 'phase' => scan_phase::COMPLETED],
            (object) ['status' => scan_status::SUSPICIOUS, 'phase' => scan_phase::COMPLETED],
        ];
        $this->assertSame(scan_status::SUSPICIOUS, archive_aggregate::aggregate_status($children));
    }

    /**
     * Provider error on a member prevents a silent clean aggregate.
     */
    public function test_error_precedence_over_clean(): void {
        $children = [
            (object) ['status' => scan_status::CLEAN, 'phase' => scan_phase::COMPLETED],
            (object) ['status' => scan_status::ERROR, 'phase' => scan_phase::FAILED],
        ];
        $this->assertSame(scan_status::ERROR, archive_aggregate::aggregate_status($children));
    }

    /**
     * Empty member set with limits still yields incomplete, not complete/clean-only semantics.
     */
    public function test_no_members_with_limits_is_incomplete(): void {
        $outcome = archive_aggregate::resolve_outcome(true, false, []);
        $this->assertSame(archive_outcome::INCOMPLETE, $outcome);
    }

    /**
     * Uninspectable archives map to extract_error outcome.
     */
    public function test_uninspectable_outcome(): void {
        $outcome = archive_aggregate::resolve_outcome(false, true, []);
        $this->assertSame(archive_outcome::EXTRACT_ERROR, $outcome);
    }

    /**
     * Incomplete limits map to incomplete archive outcome.
     */
    public function test_incomplete_outcome_when_limits_exceeded(): void {
        $outcome = archive_aggregate::resolve_outcome(true, false, []);
        $this->assertSame(archive_outcome::INCOMPLETE, $outcome);
    }
}
