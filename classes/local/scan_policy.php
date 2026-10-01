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
 * Explicit antivirus gate policies.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;


/**
 * Allow/block/report choices for unknown, suspicious, and provider-error states.
 *
 * Unknown is never treated as clean. Provider errors never become SCAN_RESULT_OK.
 */
class scan_policy {
    /** Permit the Moodle upload to continue. */
    public const ALLOW = 'allow';

    /** Refuse the upload without claiming the file is malware. */
    public const BLOCK = 'block';

    /** Return SCAN_RESULT_ERROR so Moodle logs the failure and continues the upload. */
    public const REPORT = 'report';

    /** Capture the malicious content in Moodle's antivirus quarantine and remove the file. */
    public const QUARANTINE = 'quarantine';

    /** Default unknown-hash policy. */
    public const UNKNOWN_DEFAULT = self::ALLOW;

    /** Default known-suspicious policy. Compatible with ordinary Moodle uploads. */
    public const SUSPICIOUS_DEFAULT = self::ALLOW;

    /** Default provider-error policy. Fail closed. */
    public const PROVIDER_ERROR_DEFAULT = self::BLOCK;

    /** Default policy for a malicious verdict that arrives after upload. */
    public const ASYNC_ENFORCEMENT_DEFAULT = self::QUARANTINE;

    /**
     * Normalise an allow/block setting.
     *
     * @param string $value Stored value.
     * @param string $default Fallback.
     * @return string
     */
    public static function normalise_allow_block(string $value, string $default): string {
        $value = strtolower(trim($value));
        if ($value === self::ALLOW || $value === self::BLOCK) {
            return $value;
        }
        return $default;
    }

    /**
     * Normalise the provider-error setting.
     *
     * @param string $value Stored value.
     * @return string
     */
    public static function normalise_provider_error(string $value): string {
        $value = strtolower(trim($value));
        if ($value === self::BLOCK || $value === self::REPORT) {
            return $value;
        }
        return self::PROVIDER_ERROR_DEFAULT;
    }

    /**
     * Normalise the asynchronous malicious enforcement setting.
     *
     * @param string $value Stored value.
     * @return string
     */
    public static function normalise_async_enforcement(string $value): string {
        $value = strtolower(trim($value));
        if ($value === self::QUARANTINE || $value === self::REPORT) {
            return $value;
        }
        return self::ASYNC_ENFORCEMENT_DEFAULT;
    }

    /**
     * Human-readable label for a stored plugin_config policy value (UI only).
     *
     * @param string $setting Config key (scanscope, unknownpolicy, asyncenforcement, …).
     * @param string $value Stored value.
     * @return string
     */
    public static function config_value_label(string $setting, string $value): string {
        switch ($setting) {
            case 'scanscope':
                return scan_scope::normalise($value) === scan_scope::SELECTED_AREAS
                    ? get_string('scanscope_selectedareas', 'antivirus_verdict')
                    : get_string('scanscope_everyupload', 'antivirus_verdict');
            case 'asyncenforcement':
                return self::normalise_async_enforcement($value) === self::REPORT
                    ? get_string('policy_reportonly', 'antivirus_verdict')
                    : get_string('policy_quarantine', 'antivirus_verdict');
            case 'providererrorpolicy':
                return self::normalise_provider_error($value) === self::REPORT
                    ? get_string('policy_report', 'antivirus_verdict')
                    : get_string('policy_block', 'antivirus_verdict');
            case 'unknownpolicy':
                return self::normalise_allow_block($value, self::UNKNOWN_DEFAULT) === self::BLOCK
                    ? get_string('policy_block', 'antivirus_verdict')
                    : get_string('policy_allow', 'antivirus_verdict');
            case 'suspiciouspolicy':
                return self::normalise_allow_block($value, self::SUSPICIOUS_DEFAULT) === self::BLOCK
                    ? get_string('policy_block', 'antivirus_verdict')
                    : get_string('policy_allow', 'antivirus_verdict');
            default:
                return $value;
        }
    }
}
