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
 * Site-wide VirusTotal availability circuit breaker.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

use core\lock\lock;
use core\lock\lock_config;
use antivirus_verdict\provider\provider_exception;


/**
 * Minimal closed / open / half-open circuit for VirusTotal availability.
 *
 * This is not a verdict. Clean, suspicious, and malicious results never
 * enter it. Authentication and malformed-response errors mean the provider
 * answered, so they close the circuit rather than opening it.
 *
 * State lives in the application cache. A missing cache is treated as closed,
 * which causes a real probe rather than a stuck outage.
 */
class provider_health {
    /** Provider requests proceed. */
    public const STATE_CLOSED = 'closed';

    /** Provider requests are skipped until cooldown expires. */
    public const STATE_OPEN = 'open';

    /** One probe request is in flight. */
    public const STATE_HALFOPEN = 'halfopen';

    /** Consecutive availability failures before opening. */
    public const FAILURE_THRESHOLD = 5;

    /** Seconds to stay open after the threshold is reached. */
    public const OPEN_SECONDS = 120;

    /** Cache area name from db/caches.php. */
    public const CACHE_AREA = 'providerhealth';

    /** Single site-wide cache key. VirusTotal is the only provider. */
    public const CACHE_KEY = 'virustotal';

    /** Lock name that serialises half-open probes. */
    public const PROBE_LOCK = 'provider_probe';

    /**
     * Allow one provider request, or fail fast while the circuit is open.
     *
     * Returns a held probe lock when this caller is the half-open probe.
     * The caller must release it after the HTTP round-trip.
     *
     * @param bool $forceprobe Whether an administrator connection test may probe.
     * @return lock|null
     * @throws provider_exception When the circuit is open or another probe is in flight.
     */
    public function before_request(bool $forceprobe = false): ?lock {
        $state = $this->load();
        if ($state['state'] === self::STATE_CLOSED) {
            return null;
        }

        $cooldownover = $this->now() >= (int) $state['openuntil'];
        if ($state['state'] === self::STATE_OPEN && !$cooldownover && !$forceprobe) {
            throw new provider_exception('error_providerunavailable');
        }

        $lock = $this->try_probe_lock();
        if (!$lock) {
            throw new provider_exception('error_providerunavailable');
        }

        $state['state'] = self::STATE_HALFOPEN;
        $this->save($state);
        return $lock;
    }

    /**
     * Record that VirusTotal answered, including 404 and 401/403.
     */
    public function record_success(): void {
        $this->save([
            'state' => self::STATE_CLOSED,
            'failures' => 0,
            'openuntil' => 0,
        ]);
    }

    /**
     * Record an availability failure (network, timeout, 429, 5xx).
     *
     * @param int|null $retryafter Provider Retry-After in seconds, already capped.
     */
    public function record_failure(?int $retryafter = null): void {
        $state = $this->load();
        if ($state['state'] === self::STATE_HALFOPEN) {
            $this->open($retryafter);
            return;
        }

        $failures = (int) $state['failures'] + 1;
        if ($failures >= $this->failure_threshold()) {
            $this->open($retryafter, $failures);
            return;
        }

        $state['failures'] = $failures;
        $state['state'] = self::STATE_CLOSED;
        $this->save($state);
    }

    /**
     * Current stored state name.
     *
     * @return string
     */
    public function state(): string {
        return $this->load()['state'];
    }

    /**
     * Consecutive recorded availability failures while closed.
     *
     * @return int
     */
    public function failure_count(): int {
        return (int) $this->load()['failures'];
    }

    /**
     * Unix time when an open circuit may probe again.
     *
     * @return int
     */
    public function open_until(): int {
        return (int) $this->load()['openuntil'];
    }

    /**
     * Non-sensitive circuit snapshot for administrator dashboards.
     *
     * @return array{
     *     state:string,
     *     failures:int,
     *     openuntil:int,
     *     isopen:bool,
     *     cooldownremaining:int,
     *     failurethreshold:int,
     *     openseconds:int
     * }
     */
    public function dashboard_snapshot(): array {
        $state = $this->load();
        $openuntil = (int) $state['openuntil'];
        $remaining = 0;
        if ((string) $state['state'] === self::STATE_OPEN) {
            $remaining = max(0, $openuntil - $this->now());
        }
        return [
            'state' => (string) $state['state'],
            'failures' => (int) $state['failures'],
            'openuntil' => $openuntil,
            'isopen' => (string) $state['state'] === self::STATE_OPEN,
            'cooldownremaining' => $remaining,
            'failurethreshold' => $this->failure_threshold(),
            'openseconds' => $this->open_seconds(),
        ];
    }

    /**
     * Open the circuit for the cooldown, honouring Retry-After when longer.
     *
     * @param int|null $retryafter Capped Retry-After seconds.
     * @param int $failures Failure count to persist.
     */
    private function open(?int $retryafter, int $failures = 0): void {
        $cooldown = $this->open_seconds();
        if ($retryafter !== null && $retryafter > $cooldown) {
            $cooldown = retry_policy::cap_delay($retryafter) ?? $cooldown;
        }
        $this->save([
            'state' => self::STATE_OPEN,
            'failures' => max($failures, $this->failure_threshold()),
            'openuntil' => $this->now() + $cooldown,
        ]);
    }

    /**
     * Load persisted state, defaulting to closed when the cache is empty.
     *
     * @return array{state:string,failures:int,openuntil:int}
     */
    protected function load(): array {
        $raw = $this->cache()->get(self::CACHE_KEY);
        if (!is_array($raw)) {
            return [
                'state' => self::STATE_CLOSED,
                'failures' => 0,
                'openuntil' => 0,
            ];
        }
        $state = (string) ($raw['state'] ?? self::STATE_CLOSED);
        if (!in_array($state, [self::STATE_CLOSED, self::STATE_OPEN, self::STATE_HALFOPEN], true)) {
            $state = self::STATE_CLOSED;
        }
        return [
            'state' => $state,
            'failures' => max(0, (int) ($raw['failures'] ?? 0)),
            'openuntil' => max(0, (int) ($raw['openuntil'] ?? 0)),
        ];
    }

    /**
     * Persist circuit state. Never stores credentials or file content.
     *
     * @param array $state State to store.
     */
    protected function save(array $state): void {
        $this->cache()->set(self::CACHE_KEY, [
            'state' => $state['state'],
            'failures' => (int) $state['failures'],
            'openuntil' => (int) $state['openuntil'],
        ]);
    }

    /**
     * Application cache for this plugin area.
     *
     * @return \cache
     */
    protected function cache() {
        return \cache::make('antivirus_verdict', self::CACHE_AREA);
    }

    /**
     * Non-blocking probe lock. Null when another request is already probing.
     *
     * @return lock|null
     */
    protected function try_probe_lock(): ?lock {
        $factory = lock_config::get_lock_factory('antivirus_verdict');
        $lock = $factory->get_lock(self::PROBE_LOCK, 0);
        return $lock ?: null;
    }

    /**
     * Failure threshold. Tests may override.
     *
     * @return int
     */
    protected function failure_threshold(): int {
        return self::FAILURE_THRESHOLD;
    }

    /**
     * Open cooldown in seconds. Tests may override.
     *
     * @return int
     */
    protected function open_seconds(): int {
        return self::OPEN_SECONDS;
    }

    /**
     * Current unix time. Tests may override.
     *
     * @return int
     */
    protected function now(): int {
        return time();
    }
}
