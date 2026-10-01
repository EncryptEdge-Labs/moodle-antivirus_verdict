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
 * Tests for the site-wide VirusTotal availability circuit.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\provider_health;
use antivirus_verdict\provider\provider_exception;
use antivirus_verdict\tests\testable_provider_health;


/**
 * Circuit-breaker state machine.
 *
 * @covers \antivirus_verdict\local\provider_health
 */
final class provider_health_test extends \advanced_testcase {
    /**
     * Closed allows a request without taking a probe lock.
     */
    public function test_closed_allows_request(): void {
        $health = $this->make_health();
        $this->assertSame(provider_health::STATE_CLOSED, $health->state());
        $this->assertNull($health->before_request());
        $this->assertSame(0, $health->failure_count());
    }

    /**
     * A single transient failure does not open the circuit.
     */
    public function test_single_failure_stays_closed(): void {
        $health = $this->make_health();
        $health->record_failure();
        $this->assertSame(provider_health::STATE_CLOSED, $health->state());
        $this->assertSame(1, $health->failure_count());
        $this->assertNull($health->before_request());
    }

    /**
     * Reaching the failure threshold opens the circuit.
     */
    public function test_threshold_opens_circuit(): void {
        $health = $this->make_health();
        for ($i = 0; $i < provider_health::FAILURE_THRESHOLD; $i++) {
            $health->record_failure();
        }
        $this->assertSame(provider_health::STATE_OPEN, $health->state());
        $this->assertSame(
            $health->clock + provider_health::OPEN_SECONDS,
            $health->open_until()
        );
        try {
            $health->before_request();
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_providerunavailable', $e->errorcode);
        }
    }

    /**
     * Open state skips provider contact until cooldown expires.
     */
    public function test_open_skips_provider_until_cooldown(): void {
        $health = $this->make_health();
        $health->seed(provider_health::STATE_OPEN, 5, $health->clock + 60);
        try {
            $health->before_request();
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_providerunavailable', $e->errorcode);
        }
        $this->assertSame(provider_health::STATE_OPEN, $health->state());
    }

    /**
     * After cooldown a successful probe closes the circuit.
     */
    public function test_halfopen_success_closes(): void {
        $health = $this->make_health();
        $health->seed(provider_health::STATE_OPEN, 5, $health->clock - 1);
        $lock = $health->before_request();
        $this->assertNotNull($lock);
        $this->assertSame(provider_health::STATE_HALFOPEN, $health->state());
        $health->record_success();
        $lock->release();
        $this->assertSame(provider_health::STATE_CLOSED, $health->state());
        $this->assertSame(0, $health->failure_count());
        $this->assertNull($health->before_request());
    }

    /**
     * A failed half-open probe re-opens the circuit.
     */
    public function test_halfopen_failure_reopens(): void {
        $health = $this->make_health();
        $health->seed(provider_health::STATE_OPEN, 5, $health->clock - 1);
        $lock = $health->before_request();
        $this->assertNotNull($lock);
        $health->record_failure();
        $lock->release();
        $this->assertSame(provider_health::STATE_OPEN, $health->state());
        $this->assertSame($health->clock + provider_health::OPEN_SECONDS, $health->open_until());
        try {
            $health->before_request();
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_providerunavailable', $e->errorcode);
        }
    }

    /**
     * Concurrent half-open probes do not all contact the provider.
     *
     * Moodle's MySQL GET_LOCK is per connection, so two sequential calls in one
     * PHPUnit process cannot reproduce two workers. The second caller is denied
     * the probe lock the way a second connection would be.
     */
    public function test_concurrent_probes_do_not_storm(): void {
        $health = $this->make_health();
        $health->seed(provider_health::STATE_OPEN, 5, $health->clock - 1);
        $lock = $health->before_request();
        $this->assertNotNull($lock);
        $this->assertSame(provider_health::STATE_HALFOPEN, $health->state());
        $second = new testable_provider_health();
        $second->clock = $health->clock;
        $second->lockavailable = false;
        try {
            $second->before_request();
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_providerunavailable', $e->errorcode);
        } finally {
            $lock->release();
        }
        $this->assertSame(provider_health::STATE_HALFOPEN, $health->state());
    }

    /**
     * A denied probe lock is treated as unavailable, not as a second HTTP probe.
     */
    public function test_unavailable_probe_lock_fails_fast(): void {
        $health = $this->make_health();
        $health->seed(provider_health::STATE_OPEN, 5, $health->clock - 1);
        $health->lockavailable = false;
        try {
            $health->before_request();
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_providerunavailable', $e->errorcode);
        }
        $this->assertSame(provider_health::STATE_OPEN, $health->state());
    }

    /**
     * A successful answer resets the failure count while closed.
     */
    public function test_success_resets_failure_count(): void {
        $health = $this->make_health();
        $health->record_failure();
        $health->record_failure();
        $this->assertSame(2, $health->failure_count());
        $health->record_success();
        $this->assertSame(provider_health::STATE_CLOSED, $health->state());
        $this->assertSame(0, $health->failure_count());
    }

    /**
     * Missing cache data is closed so the next request probes rather than sticking open.
     */
    public function test_missing_cache_is_closed(): void {
        $health = $this->make_health();
        \cache::make('antivirus_verdict', provider_health::CACHE_AREA)->purge();
        $this->assertSame(provider_health::STATE_CLOSED, $health->state());
        $this->assertNull($health->before_request());
    }

    /**
     * Create a health object with a purged cache.
     *
     * @return testable_provider_health
     */
    private function make_health(): testable_provider_health {
        $this->resetAfterTest();
        \cache::make('antivirus_verdict', provider_health::CACHE_AREA)->purge();
        return new testable_provider_health();
    }
}
