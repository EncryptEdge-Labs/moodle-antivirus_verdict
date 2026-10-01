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
 * Testable VirusTotal availability circuit.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\tests;

use core\lock\lock;
use antivirus_verdict\local\provider_health;


/**
 * Overrides clock, threshold, cooldown, and probe-lock availability for PHPUnit.
 */
class testable_provider_health extends provider_health {
    /** @var int Frozen unix time. */
    public int $clock;

    /** @var int Consecutive failures required to open. */
    public int $threshold = provider_health::FAILURE_THRESHOLD;

    /** @var int Open cooldown in seconds. */
    public int $openseconds = provider_health::OPEN_SECONDS;

    /** @var bool Whether a half-open probe lock may be acquired. */
    public bool $lockavailable = true;

    /**
     * Start with a frozen clock.
     */
    public function __construct() {
        $this->clock = 1_700_000_000;
    }

    /**
     * Write circuit state without performing HTTP.
     *
     * @param string $state closed, open, or halfopen.
     * @param int $failures Failure count.
     * @param int $openuntil Cooldown expiry.
     */
    public function seed(string $state, int $failures = 0, int $openuntil = 0): void {
        $this->save([
            'state' => $state,
            'failures' => $failures,
            'openuntil' => $openuntil,
        ]);
    }

    /**
     * Frozen clock.
     *
     * @return int
     */
    protected function now(): int {
        return $this->clock;
    }

    /**
     * Overridable failure threshold.
     *
     * @return int
     */
    protected function failure_threshold(): int {
        return $this->threshold;
    }

    /**
     * Overridable open cooldown.
     *
     * @return int
     */
    protected function open_seconds(): int {
        return $this->openseconds;
    }

    /**
     * Optionally deny the probe lock without waiting.
     *
     * @return lock|null
     */
    protected function try_probe_lock(): ?lock {
        if (!$this->lockavailable) {
            return null;
        }
        return parent::try_probe_lock();
    }
}
