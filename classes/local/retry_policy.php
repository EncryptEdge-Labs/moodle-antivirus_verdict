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
 * Bounded retry policy for provider and polling failures.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;


/**
 * Central retry rules for the scan engine and adhoc task.
 */
class retry_policy {
    /**
     * Maximum provider-failure retries for one scan.
     *
     * An analysis that is still queued or in progress at the provider does not
     * consume this budget. Those scans stay pending until the provider finishes
     * or the stale-scan time limit closes them.
     */
    public const MAX_ATTEMPTS = 10;

    /** Delay when VirusTotal analysis is still queued. */
    public const DELAY_PENDING = 30;

    /** Delay after a network/timeout failure. */
    public const DELAY_NETWORK = 60;

    /** Delay after a VirusTotal 5xx. */
    public const DELAY_SERVER = 120;

    /** Fallback delay after HTTP 429 when Retry-After is absent. */
    public const DELAY_RATELIMIT = 60;

    /** Maximum delay applied to any retry, including Retry-After. */
    public const DELAY_MAX = 3600;

    /**
     * Large-file POST attempts before the scan fails.
     *
     * Obtaining an upload URL is cheap and uses the ordinary retry budget.
     * Restarting a transfer of up to ~650 MiB is not. VirusTotal does not
     * expose a resume API through this integration.
     */
    public const MAX_LARGE_UPLOAD_ATTEMPTS = 2;

    /** Fail still-active scans older than this many seconds. */
    public const STALE_FAIL_AFTER = 86400;

    /** Re-queue stuck active scans whose last update is older than this. */
    public const STALE_REQUEUE_AFTER = 7200;

    /** Maximum stale rows examined in one recovery run. */
    public const STALE_BATCH = 50;

    /**
     * Error codes that may be retried.
     *
     * @return string[]
     */
    public static function retryable_codes(): array {
        return [
            'error_network',
            'error_server',
            'error_ratelimit',
            'error_generic',
            'error_providerunavailable',
            'error_uploadinterrupted',
        ];
    }

    /**
     * Error codes that must not be retried.
     *
     * @return string[]
     */
    public static function permanent_codes(): array {
        return [
            'error_nokey',
            'error_auth',
            'error_forbidden',
            'error_invalidrequest',
            'error_filetoolarge',
            'error_malformed',
            'error_notfound',
            'error_invalidfile',
            'error_disabled',
            'error_stale',
            'error_maxattempts',
            'error_operationlimit',
            'error_guardunavailable',
        ];
    }

    /**
     * Whether the provider error can be retried.
     *
     * @param string $errorcode Language string id.
     * @return bool
     */
    public static function is_retryable(string $errorcode): bool {
        return in_array($errorcode, self::retryable_codes(), true);
    }

    /**
     * Whether the provider error is terminal.
     *
     * @param string $errorcode Language string id.
     * @return bool
     */
    public static function is_permanent(string $errorcode): bool {
        return in_array($errorcode, self::permanent_codes(), true);
    }

    /**
     * Temporary provider unavailability that must not block Moodle uploads.
     *
     * HTTP 429 and an open availability circuit are not malware, not clean,
     * and not a permanent configuration failure.
     *
     * @param string $errorcode Language string id.
     * @return bool
     */
    public static function is_transient_unavailability(string $errorcode): bool {
        return $errorcode === 'error_ratelimit' || $errorcode === 'error_providerunavailable';
    }

    /**
     * Seconds to wait before the next attempt.
     *
     * Provider Retry-After is honoured when present. Otherwise the base delay
     * for the error is multiplied by the current attempt count.
     *
     * @param string $errorcode Language string id or 'pending'.
     * @param int|null $retryafter Numeric Retry-After from the provider.
     * @param int $attempts Current poll/retry attempt count (1-based multiplier).
     * @return int
     */
    public static function delay_seconds(string $errorcode, ?int $retryafter = null, int $attempts = 1): int {
        $fromheader = self::cap_delay($retryafter);
        if ($fromheader !== null) {
            return $fromheader;
        }
        $attempts = max(1, $attempts);
        $base = match ($errorcode) {
            'pending' => self::DELAY_PENDING,
            'error_network' => self::DELAY_NETWORK,
            'error_server' => self::DELAY_SERVER,
            'error_ratelimit' => self::DELAY_RATELIMIT,
            'error_providerunavailable' => self::DELAY_NETWORK,
            'error_uploadinterrupted' => self::DELAY_NETWORK,
            default => self::DELAY_NETWORK,
        };
        return min($base * $attempts, self::DELAY_MAX);
    }

    /**
     * Bound a Retry-After value. Null, zero, and negative become null.
     *
     * @param int|null $seconds Candidate delay.
     * @return int|null
     */
    public static function cap_delay(?int $seconds): ?int {
        if ($seconds === null || $seconds <= 0) {
            return null;
        }
        return min($seconds, self::DELAY_MAX);
    }
}
