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
 * Tests for retry classification and progressive backoff.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\retry_policy;


/**
 * Retry policy rules.
 *
 * @covers \antivirus_verdict\local\retry_policy
 */
final class retry_policy_test extends \advanced_testcase {
    /**
     * Transient codes retry; permanent codes do not.
     */
    public function test_retryable_and_permanent_codes(): void {
        $this->assertTrue(retry_policy::is_retryable('error_network'));
        $this->assertTrue(retry_policy::is_retryable('error_server'));
        $this->assertTrue(retry_policy::is_retryable('error_ratelimit'));
        $this->assertTrue(retry_policy::is_retryable('error_generic'));
        $this->assertTrue(retry_policy::is_retryable('error_providerunavailable'));
        $this->assertTrue(retry_policy::is_retryable('error_uploadinterrupted'));
        $this->assertTrue(retry_policy::is_transient_unavailability('error_ratelimit'));
        $this->assertTrue(retry_policy::is_transient_unavailability('error_providerunavailable'));
        $this->assertFalse(retry_policy::is_transient_unavailability('error_auth'));
        $this->assertFalse(retry_policy::is_transient_unavailability('error_malformed'));
        $this->assertFalse(retry_policy::is_retryable('error_forbidden'));
        $this->assertTrue(retry_policy::is_permanent('error_auth'));
        $this->assertTrue(retry_policy::is_permanent('error_forbidden'));
        $this->assertTrue(retry_policy::is_permanent('error_malformed'));
        $this->assertTrue(retry_policy::is_permanent('error_stale'));
        $this->assertTrue(retry_policy::is_permanent('error_maxattempts'));
        $this->assertTrue(retry_policy::is_permanent('error_invalidfile'));
        $this->assertSame(10, retry_policy::MAX_ATTEMPTS);
        $this->assertSame(2, retry_policy::MAX_LARGE_UPLOAD_ATTEMPTS);
    }

    /**
     * Backoff grows with attempts and honours Retry-After.
     */
    public function test_delay_uses_attempts_and_retry_after(): void {
        $this->assertSame(60, retry_policy::delay_seconds('error_network', null, 1));
        $this->assertSame(180, retry_policy::delay_seconds('error_network', null, 3));
        $this->assertSame(120, retry_policy::delay_seconds('error_server', null, 1));
        $this->assertSame(30, retry_policy::delay_seconds('pending', null, 1));
        $this->assertSame(90, retry_policy::delay_seconds('pending', null, 3));
        $this->assertSame(45, retry_policy::delay_seconds('error_ratelimit', 45, 9));
        $this->assertSame(3600, retry_policy::delay_seconds('error_ratelimit', 99999, 1));
        $this->assertSame(3600, retry_policy::delay_seconds('error_network', null, 100));
        $this->assertSame(60, retry_policy::delay_seconds('error_providerunavailable', null, 1));
        $this->assertSame(60, retry_policy::delay_seconds('error_uploadinterrupted', null, 1));
        $this->assertSame(60, retry_policy::delay_seconds('error_ratelimit', 0, 1));
        $this->assertSame(60, retry_policy::delay_seconds('error_ratelimit', -10, 1));
        $this->assertNull(retry_policy::cap_delay(null));
        $this->assertNull(retry_policy::cap_delay(0));
        $this->assertNull(retry_policy::cap_delay(-5));
        $this->assertSame(12, retry_policy::cap_delay(12));
        $this->assertSame(3600, retry_policy::cap_delay(99999));
    }
}
