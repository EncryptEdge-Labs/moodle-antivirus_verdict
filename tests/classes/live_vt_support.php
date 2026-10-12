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
 * Live VirusTotal certification helpers (explicit opt-in only).
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\tests;

use antivirus_verdict\local\provider_health;
use antivirus_verdict\provider\virustotal\client;
use core\http_client;


/**
 * Bridges operator credentials (env or Behat DB) into PHPUnit without logging secrets.
 */
final class live_vt_support {
    /** Environment flag that must be set to send live requests. */
    public const OPT_IN_ENV = 'VERDICT_LVT_OPT_IN';

    /** Primary env var for explicit operator override. */
    public const KEY_ENV = 'VERDICT_LVT_API_KEY';

    /** Behat branch for DB-resolved credential (default 502). */
    public const BEHAT_BRANCH_ENV = 'VERDICT_LVT_BEHAT_BRANCH';

    /**
     * Skip unless operator opted in (prevents accidental CI runs).
     */
    public static function require_opt_in(): void {
        $flag = getenv(self::OPT_IN_ENV);
        if (!is_string($flag) || trim($flag) !== '1') {
            $message = 'Live VT certification requires ' . self::OPT_IN_ENV . '=1 (explicit operator opt-in).';
            if (class_exists(\PHPUnit\Framework\SkippedWithMessageException::class)) {
                throw new \PHPUnit\Framework\SkippedWithMessageException($message);
            }
            throw new \PHPUnit\Framework\SkippedTestError($message);
        }
    }

    /**
     * Resolve API key: VERDICT_LVT_API_KEY first, else Behat config_plugins for branch.
     *
     * @return string Non-empty key or empty when unavailable.
     */
    public static function resolve_api_key(): string {
        self::load_credential_resolver();
        return verdict_live_vt_resolve_api_key();
    }

    /**
     * Accounting VT client for live certification.
     *
     * @param string $apikey Resolved API key (applied via test_credentials pattern).
     * @return live_vt_accounting_client
     */
    public static function accounting_client(string $apikey): live_vt_accounting_client {
        return new live_vt_accounting_client(
            new test_credentials($apikey),
            new http_client(client::default_http_options()),
            new provider_health()
        );
    }

    /**
     * Load CLI credential resolver once (no output).
     */
    private static function load_credential_resolver(): void {
        static $loaded = false;
        if ($loaded) {
            return;
        }
        $path = dirname(__DIR__, 2) . '/scripts/live-vt-credential-resolver.php';
        if (!is_readable($path)) {
            return;
        }
        require_once($path);
        $loaded = true;
    }
}
