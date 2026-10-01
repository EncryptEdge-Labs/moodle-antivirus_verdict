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
 * Site operational settings for scanning (not API credentials).
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

use antivirus_verdict\provider\virustotal\client;


/**
 * Moodle antivirus enablement, assignment backfill, size limit, and gate policies.
 *
 * There is no plugin-owned master enable switch. Moodle's $CFG->antiviruses
 * controls whether the native scanner runs.
 */
class plugin_config {
    /** Default and maximum administrator size limit in megabytes. */
    public const DEFAULT_MAX_MB = 100;

    /** @var bool Whether Verdict is enabled in $CFG->antiviruses. */
    public readonly bool $enabled;
    /** @var int Maximum file size in bytes. */
    public readonly int $maxbytes;
    /** @var bool Whether assignment submissions are queued automatically. */
    public readonly bool $assignscan;
    /** @var string Unknown-hash policy (allow|block). */
    public readonly string $unknownpolicy;
    /** @var string Suspicious-hash policy (allow|block). */
    public readonly string $suspiciouspolicy;
    /** @var string Provider-error policy (block|report). */
    public readonly string $providererrorpolicy;
    /** @var string Asynchronous malicious enforcement policy (quarantine|report). */
    public readonly string $asyncenforcement;
    /** @var bool Whether forum attachments are queued after post. */
    public readonly bool $forumscan;
    /** @var bool Whether workshop submission files are queued. */
    public readonly bool $workshopscan;
    /** @var bool Whether glossary entry attachments are queued. */
    public readonly bool $glossaryscan;
    /** @var bool Whether restored courses are swept asynchronously. */
    public readonly bool $restorescan;
    /** @var bool Whether archive containers trigger nested member scans. */
    public readonly bool $archivescan;
    /** @var int Maximum archive members to extract per container tree. */
    public readonly int $archivemaxmembers;
    /** @var int Maximum nested archive depth. */
    public readonly int $archivemaxdepth;
    /** @var int Maximum aggregate extracted size in megabytes. */
    public readonly int $archivemaxextractedmb;
    /** @var bool Notify administrators when a scan completes malicious. */
    public readonly bool $notifymalicious;
    /** @var bool Notify administrators when a scan completes suspicious. */
    public readonly bool $notifysuspicious;
    /** @var bool Notify administrators when a scan ends in error. */
    public readonly bool $notifyerror;
    /** @var bool Database activity record files. */
    public readonly bool $datascan;
    /** @var bool Wiki attachment backfill. */
    public readonly bool $wikiscan;
    /** @var bool SCORM package backfill. */
    public readonly bool $scormscan;
    /** @var bool Question bank asset backfill. */
    public readonly bool $questionscan;
    /** @var bool Scheduled private files sweep. */
    public readonly bool $privatescan;
    /** @var string Native-upload scope: everyupload or selectedareas. */
    public readonly string $scanscope;
    /** @var int Local hash-lookup ceiling. 0 means no local limit. */
    public readonly int $lookupceiling;
    /** @var int Local file-upload ceiling. 0 means no local limit. */
    public readonly int $uploadceiling;
    /** @var int Local analysis-poll ceiling. 0 means no local limit. */
    public readonly int $pollceiling;

    /**
     * Create operational settings.
     *
     * @param bool $enabled Whether Moodle has enabled this antivirus plugin.
     * @param int $maxbytes Maximum file size in bytes.
     * @param bool $assignscan Whether assignment auto-scan is enabled.
     * @param string $unknownpolicy Unknown-hash policy.
     * @param string $suspiciouspolicy Suspicious-hash policy.
     * @param string $providererrorpolicy Provider-error policy.
     * @param string $asyncenforcement Asynchronous malicious enforcement policy.
     * @param bool $forumscan Forum attachment backfill.
     * @param bool $workshopscan Workshop submission backfill.
     * @param bool $glossaryscan Glossary attachment backfill.
     * @param bool $restorescan Post-restore course sweep.
     * @param bool $archivescan Nested archive scanning.
     * @param int $archivemaxmembers Archive member cap.
     * @param int $archivemaxdepth Nested archive depth cap.
     * @param int $archivemaxextractedmb Aggregate extraction cap in MB.
     * @param bool $notifymalicious Malicious completion notifications.
     * @param bool $notifysuspicious Suspicious completion notifications.
     * @param bool $notifyerror Scan error notifications.
     * @param bool $datascan Database activity backfill.
     * @param bool $wikiscan Wiki attachment backfill.
     * @param bool $scormscan SCORM package backfill.
     * @param bool $questionscan Question bank backfill.
     * @param bool $privatescan Private files scheduled sweep.
     * @param string $scanscope Native-upload scope.
     * @param int $lookupceiling Local hash-lookup ceiling. 0 means unlimited.
     * @param int $uploadceiling Local file-upload ceiling. 0 means unlimited.
     * @param int $pollceiling Local analysis-poll ceiling. 0 means unlimited.
     */
    public function __construct(
        bool $enabled,
        int $maxbytes,
        bool $assignscan = false,
        string $unknownpolicy = scan_policy::UNKNOWN_DEFAULT,
        string $suspiciouspolicy = scan_policy::SUSPICIOUS_DEFAULT,
        string $providererrorpolicy = scan_policy::PROVIDER_ERROR_DEFAULT,
        string $asyncenforcement = scan_policy::ASYNC_ENFORCEMENT_DEFAULT,
        bool $forumscan = false,
        bool $workshopscan = false,
        bool $glossaryscan = false,
        bool $restorescan = true,
        bool $archivescan = true,
        int $archivemaxmembers = archive_limits::DEFAULT_MAX_MEMBERS,
        int $archivemaxdepth = archive_limits::DEFAULT_MAX_DEPTH,
        int $archivemaxextractedmb = archive_limits::DEFAULT_MAX_EXTRACTED_MB,
        bool $notifymalicious = true,
        bool $notifysuspicious = false,
        bool $notifyerror = false,
        bool $datascan = false,
        bool $wikiscan = false,
        bool $scormscan = false,
        bool $questionscan = false,
        bool $privatescan = false,
        string $scanscope = scan_scope::EVERY_UPLOAD,
        int $lookupceiling = 0,
        int $uploadceiling = 0,
        int $pollceiling = 0
    ) {
        $this->enabled = $enabled;
        $this->maxbytes = max(0, $maxbytes);
        $this->assignscan = $assignscan;
        $this->unknownpolicy = scan_policy::normalise_allow_block($unknownpolicy, scan_policy::UNKNOWN_DEFAULT);
        $this->suspiciouspolicy = scan_policy::normalise_allow_block(
            $suspiciouspolicy,
            scan_policy::SUSPICIOUS_DEFAULT
        );
        $this->providererrorpolicy = scan_policy::normalise_provider_error($providererrorpolicy);
        $this->asyncenforcement = scan_policy::normalise_async_enforcement($asyncenforcement);
        $this->forumscan = $forumscan;
        $this->workshopscan = $workshopscan;
        $this->glossaryscan = $glossaryscan;
        $this->restorescan = $restorescan;
        $this->archivescan = $archivescan;
        $this->archivemaxmembers = archive_limits::normalise_max_members($archivemaxmembers);
        $this->archivemaxdepth = archive_limits::normalise_max_depth($archivemaxdepth);
        $this->archivemaxextractedmb = archive_limits::normalise_max_extracted_mb($archivemaxextractedmb);
        $this->notifymalicious = $notifymalicious;
        $this->notifysuspicious = $notifysuspicious;
        $this->notifyerror = $notifyerror;
        $this->datascan = $datascan;
        $this->wikiscan = $wikiscan;
        $this->scormscan = $scormscan;
        $this->questionscan = $questionscan;
        $this->privatescan = $privatescan;
        $this->scanscope = scan_scope::normalise($scanscope);
        $this->lookupceiling = self::normalise_ceiling($lookupceiling);
        $this->uploadceiling = self::normalise_ceiling($uploadceiling);
        $this->pollceiling = self::normalise_ceiling($pollceiling);
    }

    /**
     * A negative ceiling is treated as no local limit.
     *
     * @param int $value Configured ceiling.
     * @return int
     */
    public static function normalise_ceiling(int $value): int {
        return max(0, $value);
    }

    /**
     * Load from Moodle plugin configuration and $CFG->antiviruses.
     *
     * @return self
     */
    public static function from_site_config(): self {
        return new self(
            self::is_antivirus_enabled(),
            self::max_mb_from_config() * 1024 * 1024,
            (int) get_config('antivirus_verdict', 'assignscan') === 1,
            (string) get_config('antivirus_verdict', 'unknownpolicy'),
            (string) get_config('antivirus_verdict', 'suspiciouspolicy'),
            (string) get_config('antivirus_verdict', 'providererrorpolicy'),
            (string) get_config('antivirus_verdict', 'asyncenforcement'),
            (int) get_config('antivirus_verdict', 'forumscan') === 1,
            (int) get_config('antivirus_verdict', 'workshopscan') === 1,
            (int) get_config('antivirus_verdict', 'glossaryscan') === 1,
            self::config_enabled_default('restorescan', 1),
            self::config_enabled_default('archivescan', 1),
            archive_limits::normalise_max_members((int) get_config('antivirus_verdict', 'archivemaxmembers')),
            archive_limits::normalise_max_depth((int) get_config('antivirus_verdict', 'archivemaxdepth')),
            archive_limits::normalise_max_extracted_mb((int) get_config('antivirus_verdict', 'archivemaxextractedmb')),
            self::config_enabled_default('notifymalicious', 1),
            (int) get_config('antivirus_verdict', 'notifysuspicious') === 1,
            (int) get_config('antivirus_verdict', 'notifyerror') === 1,
            (int) get_config('antivirus_verdict', 'datascan') === 1,
            (int) get_config('antivirus_verdict', 'wikiscan') === 1,
            (int) get_config('antivirus_verdict', 'scormscan') === 1,
            (int) get_config('antivirus_verdict', 'questionscan') === 1,
            self::config_enabled_default('privatescan', 0),
            scan_scope::normalise((string) get_config('antivirus_verdict', 'scanscope')),
            self::normalise_ceiling((int) get_config('antivirus_verdict', 'lookupceiling')),
            self::normalise_ceiling((int) get_config('antivirus_verdict', 'uploadceiling')),
            self::normalise_ceiling((int) get_config('antivirus_verdict', 'pollceiling'))
        );
    }

    /**
     * Whether a native upload may enter the existing provider path.
     *
     * @return bool
     */
    public function admits_native_upload(): bool {
        return $this->scanscope === scan_scope::EVERY_UPLOAD;
    }

    /**
     * Read a checkbox config with a default when unset.
     *
     * @param string $name Config key without plugin prefix.
     * @param int $defaultdefault 1 or 0 default.
     * @return bool
     */
    private static function config_enabled_default(string $name, int $defaultdefault): bool {
        $raw = get_config('antivirus_verdict', $name);
        if ($raw === false || $raw === null || $raw === '') {
            return $defaultdefault === 1;
        }
        return (int) $raw === 1;
    }

    /**
     * Whether Moodle has enabled this antivirus plugin.
     *
     * @return bool
     */
    public static function is_antivirus_enabled(): bool {
        global $CFG;
        if (empty($CFG->antiviruses)) {
            return false;
        }
        return in_array('verdict', explode(',', $CFG->antiviruses), true);
    }

    /**
     * Configured maximum size in megabytes, with the default and upload cap applied.
     *
     * @return int
     */
    public static function max_mb_from_config(): int {
        return self::normalise_max_mb((int) get_config('antivirus_verdict', 'maxfilesize'));
    }

    /**
     * Clamp a posted or stored megabyte limit.
     *
     * @param int $mb Requested limit in megabytes.
     * @return int
     */
    public static function normalise_max_mb(int $mb): int {
        if ($mb <= 0) {
            $mb = self::DEFAULT_MAX_MB;
        }
        $vtcapmb = (int) floor(client::LARGE_UPLOAD_MAX_BYTES / 1024 / 1024);
        $sitecap = min(self::DEFAULT_MAX_MB, $vtcapmb);
        if ($mb > $sitecap) {
            $mb = $sitecap;
        }
        return $mb;
    }

    /**
     * Whether assignment submissions should be queued as a backfill.
     *
     * Independent of $CFG->antiviruses. The native upload gate uses $CFG->antiviruses.
     *
     * @return bool
     */
    public function assignment_auto_scan_enabled(): bool {
        return $this->assignscan;
    }

    /**
     * Whether a named file-area consumer checkbox is on.
     *
     * @param string $configkey Plugin config name (assignscan, forumscan, ...).
     * @return bool
     */
    public function consumer_enabled(string $configkey): bool {
        return match ($configkey) {
            'assignscan' => $this->assignscan,
            'forumscan' => $this->forumscan,
            'workshopscan' => $this->workshopscan,
            'glossaryscan' => $this->glossaryscan,
            'restorescan' => $this->restorescan,
            'archivescan' => $this->archivescan,
            'datascan' => $this->datascan,
            'wikiscan' => $this->wikiscan,
            'scormscan' => $this->scormscan,
            'questionscan' => $this->questionscan,
            'privatescan' => $this->privatescan,
            default => false,
        };
    }

    /**
     * Whether retrospective consumers may queue work (credentials required).
     *
     * @return bool
     */
    public function backfill_operational(): bool {
        return (new config_credentials())->has_api_key();
    }

    /**
     * Whether forum attachments should be queued.
     *
     * @return bool
     */
    public function forum_auto_scan_enabled(): bool {
        return $this->forumscan && $this->backfill_operational();
    }

    /**
     * Whether workshop submissions should be queued.
     *
     * @return bool
     */
    public function workshop_auto_scan_enabled(): bool {
        return $this->workshopscan && $this->backfill_operational();
    }

    /**
     * Whether glossary attachments should be queued.
     *
     * @return bool
     */
    public function glossary_auto_scan_enabled(): bool {
        return $this->glossaryscan && $this->backfill_operational();
    }

    /**
     * Whether restore sweeps should run.
     *
     * @return bool
     */
    public function restore_auto_scan_enabled(): bool {
        return $this->restorescan && $this->backfill_operational();
    }

    /**
     * Whether archive member scans are enabled.
     *
     * @return bool
     */
    public function archive_scan_enabled(): bool {
        return $this->archivescan && $this->backfill_operational();
    }

    /**
     * Internal helper.
     *
     * @return bool
     */
    public function data_auto_scan_enabled(): bool {
        return $this->datascan && $this->backfill_operational();
    }

    /**
     * Internal helper.
     *
     * @return bool
     */
    public function wiki_auto_scan_enabled(): bool {
        return $this->wikiscan && $this->backfill_operational();
    }

    /**
     * Internal helper.
     *
     * @return bool
     */
    public function scorm_auto_scan_enabled(): bool {
        return $this->scormscan && $this->backfill_operational();
    }

    /**
     * Internal helper.
     *
     * @return bool
     */
    public function question_auto_scan_enabled(): bool {
        return $this->questionscan && $this->backfill_operational();
    }

    /**
     * Internal helper.
     *
     * @return bool
     */
    public function private_auto_scan_enabled(): bool {
        return $this->privatescan && $this->backfill_operational();
    }
}
