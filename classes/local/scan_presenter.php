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
 * User-facing presentation helpers for scan records.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

use antivirus_verdict\archive_outcome;
use antivirus_verdict\enforcement_state;
use antivirus_verdict\scan_status;


/**
 * Maps stored scan rows to language strings and safe display values.
 *
 * Does not call VirusTotal or load file bytes.
 */
class scan_presenter {
    /**
     * Language string for a user-facing status.
     *
     * @param string $status Stored status.
     * @return string
     */
    public static function status_label(string $status): string {
        $key = 'status_' . $status;
        if (get_string_manager()->string_exists($key, 'antivirus_verdict')) {
            return get_string($key, 'antivirus_verdict');
        }
        return get_string('status_pending', 'antivirus_verdict');
    }

    /**
     * Language string for a scan source.
     *
     * @param string $source Stored source.
     * @return string
     */
    public static function source_label(string $source): string {
        $key = 'source_' . $source;
        if (get_string_manager()->string_exists($key, 'antivirus_verdict')) {
            return get_string($key, 'antivirus_verdict');
        }
        return get_string('source_manual', 'antivirus_verdict');
    }

    /**
     * Longer source line used under the detail heading.
     *
     * @param string $source Stored source.
     * @return string
     */
    public static function source_detail(string $source): string {
        $key = 'sourcedetail_' . $source;
        if (get_string_manager()->string_exists($key, 'antivirus_verdict')) {
            return get_string($key, 'antivirus_verdict');
        }
        return self::source_label($source);
    }

    /**
     * Language string for a recorded enforcement outcome, or empty when none.
     *
     * @param string $state Stored enforcement outcome.
     * @return string
     */
    public static function enforcement_label(string $state): string {
        $state = trim($state);
        if ($state === enforcement_state::NONE || !enforcement_state::is_valid($state)) {
            return '';
        }
        return get_string('enforcement_' . $state, 'antivirus_verdict');
    }

    /**
     * Compact timestamp matching the product UI.
     *
     * @param int $timestamp Unix time.
     * @param bool $withyear Whether to include the year (detail page).
     * @return string
     */
    public static function format_time(int $timestamp, bool $withyear = false): string {
        if ($timestamp <= 0) {
            return get_string('valueempty', 'antivirus_verdict');
        }
        $dateformat = $withyear
            ? get_string('strftimedetaildate', 'antivirus_verdict')
            : get_string('strftimeshortdate', 'antivirus_verdict');
        $date = trim(userdate($timestamp, $dateformat));
        $timezone = \core_date::get_user_timezone_object();
        $clock = (new \DateTime('@' . $timestamp))->setTimezone($timezone)->format('g:i A');
        return $date . ', ' . $clock;
    }

    /**
     * Bootstrap-compatible badge class for a status. Always used with the label.
     *
     * @param string $status Stored status.
     * @return string
     */
    public static function status_css_class(string $status): string {
        return match ($status) {
            scan_status::CLEAN => 'antivirus-verdict-badge antivirus-verdict-badge--clean',
            scan_status::SUSPICIOUS => 'antivirus-verdict-badge antivirus-verdict-badge--suspicious',
            scan_status::MALICIOUS => 'antivirus-verdict-badge antivirus-verdict-badge--malicious',
            scan_status::ERROR => 'antivirus-verdict-badge antivirus-verdict-badge--error',
            scan_status::NOTSCANNED => 'antivirus-verdict-badge antivirus-verdict-badge--notscanned',
            default => 'antivirus-verdict-badge antivirus-verdict-badge--pending',
        };
    }

    /**
     * Detection summary, or empty when counts are unknown.
     *
     * Null counts are not displayed as zero.
     *
     * @param \stdClass $scan Scan row.
     * @return string
     */
    public static function detection_label(\stdClass $scan): string {
        if ($scan->malicious === null && $scan->totalengines === null) {
            return '';
        }
        if ($scan->totalengines === null) {
            return '';
        }
        $malicious = $scan->malicious === null ? null : (int) $scan->malicious;
        if ($malicious === null) {
            return '';
        }
        $a = (object) [
            'malicious' => $malicious,
            'total' => (int) $scan->totalengines,
        ];
        $stringid = self::has_archive_outcome($scan) ? 'providerreport' : 'detectioncounts';
        return get_string($stringid, 'antivirus_verdict', $a);
    }

    /**
     * Compact detection counts for tables, or empty when unknown.
     *
     * @param \stdClass $scan Scan row.
     * @return string
     */
    public static function detection_compact(\stdClass $scan): string {
        if (self::detection_label($scan) === '') {
            return '';
        }
        $stringid = self::has_archive_outcome($scan) ? 'providerreportcompact' : 'detectioncompact';
        return get_string($stringid, 'antivirus_verdict', (object) [
            'malicious' => (int) $scan->malicious,
            'total' => (int) $scan->totalengines,
        ]);
    }

    /**
     * Whether the row is an archive container with an inspection outcome.
     *
     * Provider counts stay visible, but they are labelled as the provider
     * report rather than the container verdict.
     *
     * @param \stdClass $scan Scan row.
     * @return bool
     */
    private static function has_archive_outcome(\stdClass $scan): bool {
        $outcome = (string) ($scan->archiveoutcome ?? '');
        return $outcome !== '' && $outcome !== archive_outcome::NONE;
    }

    /**
     * Public VirusTotal GUI URL when a SHA-256 is stored.
     *
     * @param \stdClass $scan Scan row.
     * @return string|null
     */
    public static function report_url(\stdClass $scan): ?string {
        $sha256 = strtolower(trim((string) $scan->sha256));
        return result_normaliser::public_report_url($sha256);
    }

    /**
     * Safe user-facing explanation for error or skipped scans.
     *
     * @param \stdClass $scan Scan row.
     * @return string
     */
    public static function outcome_message(\stdClass $scan): string {
        if ($scan->status === scan_status::PENDING) {
            if (self::archive_inspection_open($scan)) {
                return get_string('archiveinspectionqueued', 'antivirus_verdict');
            }
            if (retry_policy::is_transient_unavailability((string) $scan->errorcode)) {
                $queued = $scan->errorcode === 'error_ratelimit'
                    ? 'error_ratelimit_queued'
                    : 'error_providerunavailable_queued';
                return get_string($queued, 'antivirus_verdict');
            }
            return get_string('pendingdetail', 'antivirus_verdict');
        }
        if ($scan->status === scan_status::NOTSCANNED) {
            return self::lang_message((string) $scan->errorcode, 'notscanneddetail');
        }
        if ($scan->status === scan_status::ERROR) {
            return self::lang_message((string) $scan->errorcode, 'errordetail');
        }
        return '';
    }

    /**
     * User-facing text for a plugin language string id.
     *
     * Unknown codes fall back to a safe plugin string. Raw provider text is
     * never returned.
     *
     * @param string $code Language string id.
     * @param string $fallback Fallback language string id.
     * @return string
     */
    public static function lang_message(string $code, string $fallback = 'error_generic'): string {
        if ($code !== '' && get_string_manager()->string_exists($code, 'antivirus_verdict')) {
            return get_string($code, 'antivirus_verdict');
        }
        return get_string($fallback, 'antivirus_verdict');
    }

    /**
     * Safe user-facing text for a caught plugin exception.
     *
     * @param \Throwable $exception Caught exception.
     * @return string
     */
    public static function exception_message(\Throwable $exception): string {
        if ($exception instanceof \moodle_exception && $exception->module === 'antivirus_verdict') {
            return self::lang_message($exception->errorcode);
        }
        if ($exception instanceof \invalid_parameter_exception && is_string($exception->debuginfo)) {
            return self::lang_message($exception->debuginfo, 'error_invalidfile');
        }
        return get_string('error_generic', 'antivirus_verdict');
    }

    /**
     * Redirect copy and notification level after a manual scan submit.
     *
     * Uses the persisted scan row so a completed or failed kickoff is not
     * described as still queued.
     *
     * @param \stdClass $scan Scan row after enqueue/kickoff.
     * @return array{0:string,1:string} Message and \core\output\notification level.
     */
    public static function manual_submit_notification(\stdClass $scan): array {
        $status = (string) $scan->status;
        if ($status === scan_status::CLEAN) {
            return [
                get_string('scanclean', 'antivirus_verdict'),
                \core\output\notification::NOTIFY_SUCCESS,
            ];
        }
        if ($status === scan_status::MALICIOUS) {
            return [
                get_string('scanmalicious', 'antivirus_verdict', (object) [
                    'filename' => (string) $scan->filename,
                ]),
                \core\output\notification::NOTIFY_ERROR,
            ];
        }
        if ($status === scan_status::SUSPICIOUS) {
            return [
                get_string('scansuspicious', 'antivirus_verdict'),
                \core\output\notification::NOTIFY_WARNING,
            ];
        }
        if ($status === scan_status::ERROR) {
            $detail = self::outcome_message($scan);
            return [
                $detail !== '' ? $detail : get_string('scanprovidererror', 'antivirus_verdict'),
                \core\output\notification::NOTIFY_ERROR,
            ];
        }
        if ($status === scan_status::NOTSCANNED) {
            return [
                self::outcome_message($scan),
                \core\output\notification::NOTIFY_INFO,
            ];
        }
        if (retry_policy::is_transient_unavailability((string) $scan->errorcode)) {
            return [
                self::outcome_message($scan),
                \core\output\notification::NOTIFY_INFO,
            ];
        }
        if ($status === scan_status::PENDING && self::archive_inspection_open($scan)) {
            return [
                get_string('archiveinspectionqueued', 'antivirus_verdict'),
                \core\output\notification::NOTIFY_INFO,
            ];
        }
        return [
            get_string('scanqueued', 'antivirus_verdict'),
            \core\output\notification::NOTIFY_SUCCESS,
        ];
    }

    /**
     * Whether archive member inspection is still open.
     *
     * @param \stdClass $scan Scan row.
     * @return bool
     */
    private static function archive_inspection_open(\stdClass $scan): bool {
        $outcome = (string) ($scan->archiveoutcome ?? '');
        return $outcome === archive_outcome::PROCESSING || $outcome === archive_outcome::INCOMPLETE;
    }
}
