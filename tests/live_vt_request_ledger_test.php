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
 * Tests for the live VT request ledger (no network).
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\tests\live_vt_request_ledger;


/**
 * Rolling-window limiter for live VT certification (no network).
 *
 * @covers \antivirus_verdict\tests\live_vt_request_ledger
 */
final class live_vt_request_ledger_test extends \advanced_testcase {
    /**
     * A single acquire is recorded without storing secrets in the path.
     */
    public function test_acquire_records_entry(): void {
        $this->resetAfterTest();
        $url = 'https://www.virustotal.com/api/v3/files/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
        live_vt_request_ledger::acquire_slot('hash_lookup', 'GET', $url);
        live_vt_request_ledger::record_response_status(200);
        $snap = live_vt_request_ledger::snapshot();
        $this->assertGreaterThanOrEqual(1, $snap['recent']);
        $this->assertStringContainsString('{sha256}', $snap['entries'][0]['path']);
    }

    /**
     * URL categorization never includes query strings with secrets.
     */
    public function test_categorize_upload_and_lookup(): void {
        $this->assertSame(
            'hash_lookup',
            live_vt_request_ledger::categorize_url('GET', 'https://www.virustotal.com/api/v3/files/abc')
        );
        $this->assertSame(
            'upload',
            live_vt_request_ledger::categorize_url('POST', 'https://www.virustotal.com/api/v3/files')
        );
    }

    /**
     * Fifth request start in the same rolling window is rejected without waiting.
     */
    public function test_rolling_window_blocks_fifth_start(): void {
        $this->resetAfterTest();
        live_vt_request_ledger::reset_for_tests();
        $now = microtime(true);
        for ($i = 0; $i < live_vt_request_ledger::MAX_PER_WINDOW; $i++) {
            live_vt_request_ledger::append_entry_for_tests([
                'started_at' => $now,
                'category' => 'hash_lookup',
                'method' => 'GET',
                'path' => 'www.virustotal.com/api/v3/files/{sha256}',
                'status' => 200,
            ]);
        }
        $method = new \ReflectionMethod(live_vt_request_ledger::class, 'try_acquire_slot');
        $method->setAccessible(true);
        $allowed = $method->invoke(
            null,
            'hash_lookup',
            'GET',
            'https://www.virustotal.com/api/v3/files/test'
        );
        $this->assertFalse($allowed);
        $this->assertSame(live_vt_request_ledger::MAX_PER_WINDOW, live_vt_request_ledger::snapshot()['recent']);
    }

    /**
     * Entries older than the window are pruned before budget checks.
     */
    public function test_prune_drops_entries_outside_window(): void {
        $this->resetAfterTest();
        live_vt_request_ledger::reset_for_tests();
        live_vt_request_ledger::append_entry_for_tests([
            'started_at' => microtime(true) - live_vt_request_ledger::WINDOW_SECONDS - 1,
            'category' => 'hash_lookup',
            'method' => 'GET',
            'path' => 'old',
            'status' => 200,
        ]);
        $this->assertSame(0, live_vt_request_ledger::snapshot()['recent']);
    }

    /**
     * Minimum spacing applies to the most recent start timestamp.
     */
    public function test_spacing_blocks_immediate_second_start(): void {
        $this->resetAfterTest();
        live_vt_request_ledger::reset_for_tests();
        live_vt_request_ledger::append_entry_for_tests([
            'started_at' => microtime(true),
            'category' => 'upload',
            'method' => 'POST',
            'path' => 'www.virustotal.com/api/v3/files',
            'status' => 200,
        ]);
        $method = new \ReflectionMethod(live_vt_request_ledger::class, 'try_acquire_slot');
        $method->setAccessible(true);
        $this->assertFalse($method->invoke(null, 'upload', 'POST', 'https://www.virustotal.com/api/v3/files'));
    }
}
