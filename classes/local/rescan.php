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
 * Queue a deliberate new scan from an existing history row.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

use antivirus_verdict\scan_status;


/**
 * Rescan adapter. Creates a new scan record through the existing engine.
 *
 * Does not overwrite historical results. Does not call VirusTotal.
 */
class rescan {
    /** @var scan_service Scan engine. */
    private scan_service $scanservice;

    /** @var scan_repository Persistence. */
    private scan_repository $repository;

    /** @var plugin_config Operational settings. */
    private plugin_config $config;

    /** @var credential_provider Credential presence check. */
    private credential_provider $credentials;

    /**
     * Create a rescan adapter.
     *
     * @param scan_service $scanservice Scan engine.
     * @param plugin_config $config Operational settings.
     * @param scan_repository|null $repository Persistence.
     * @param credential_provider|null $credentials Credential presence check.
     */
    public function __construct(
        scan_service $scanservice,
        plugin_config $config,
        ?scan_repository $repository = null,
        ?credential_provider $credentials = null
    ) {
        $this->scanservice = $scanservice;
        $this->config = $config;
        $this->repository = $repository ?? new scan_repository();
        $this->credentials = $credentials ?? new config_credentials();
    }

    /**
     * Production adapter using site configuration.
     *
     * @return self
     */
    public static function from_site_config(): self {
        return new self(scan_service::from_site_config(), plugin_config::from_site_config());
    }

    /**
     * Whether the scanner can currently queue a rescan.
     *
     * @return bool
     */
    public function can_queue(): bool {
        return $this->credentials->has_api_key();
    }

    /**
     * Whether the original Moodle file is still available through the File API.
     *
     * @param \stdClass $scan Existing scan row.
     * @return bool
     */
    public function file_available(\stdClass $scan): bool {
        $file = $this->scanservice->stored_file_from_record($scan);
        if (!$file) {
            return false;
        }
        try {
            $this->scanservice->assert_scanable_file($file);
        } catch (\invalid_parameter_exception $e) {
            return false;
        }
        return true;
    }

    /**
     * Whether a Rescan action may be offered for this record.
     *
     * @param \stdClass $scan Existing scan row.
     * @return bool
     */
    public function is_eligible(\stdClass $scan): bool {
        return $this->can_queue()
            && scan_status::is_terminal((string) $scan->status)
            && $this->file_available($scan);
    }

    /**
     * Queue a rescan from a stored scan id.
     *
     * @param int $scanid Existing scan id.
     * @param int $userid Acting user.
     * @return \stdClass New or reused in-flight scan.
     */
    public function queue_by_id(int $scanid, int $userid): \stdClass {
        $scan = $this->repository->get_by_id($scanid);
        if (!$scan) {
            throw new \moodle_exception('error_invalidrequest', 'antivirus_verdict');
        }
        return $this->queue($scan, $userid);
    }

    /**
     * Authorise and queue a new scan of the same Moodle file.
     *
     * Reuses an in-flight scan of the same pathnamehash so a rescan cannot
     * duplicate concurrent provider work. Otherwise inserts a new
     * pending/queued row that is marked as a forced rescan, so background
     * processing queries VirusTotal again instead of reusing the stored
     * verdict for this content. The original row is not updated. A rescan is
     * refused when the original Moodle file is no longer available.
     *
     * @param \stdClass $scan Existing scan row.
     * @param int $userid Acting user.
     * @return \stdClass New or reused in-flight scan.
     */
    public function queue(\stdClass $scan, int $userid): \stdClass {
        if (!scan_access::can_rescan($scan, $userid)) {
            throw new \required_capability_exception(
                scan_access::context_for_scan($scan),
                'antivirus/verdict:rescan',
                'nopermissions',
                ''
            );
        }
        if (!$this->can_queue()) {
            throw new \moodle_exception('scanningincomplete', 'antivirus_verdict');
        }
        $file = $this->scanservice->stored_file_from_record($scan);
        if (!$file) {
            throw new \moodle_exception('error_filenotavailable', 'antivirus_verdict');
        }
        $this->scanservice->assert_scanable_file($file);

        $actor = $userid;
        if ($actor <= 0 || !\core_user::is_real_user($actor, true)) {
            $actor = 0;
        }
        return $this->scanservice->enqueue_file_scan(
            $file,
            (string) $scan->source,
            (int) $scan->userid,
            true,
            0,
            null,
            (int) ($scan->submissionid ?? 0),
            $actor
        );
    }
}
