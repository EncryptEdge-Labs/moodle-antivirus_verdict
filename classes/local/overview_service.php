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
 * Read-only administrator overview data.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

use antivirus_verdict\scan_phase;
use antivirus_verdict\scan_status;


/**
 * Combines plugin configuration and scan-table aggregates.
 *
 * Does not call VirusTotal. Does not load API key values.
 */
class overview_service {
    /** Number of recent rows shown on the overview. */
    public const RECENT_LIMIT = 10;

    /** @var scan_repository Scan persistence. */
    private scan_repository $repository;

    /** @var plugin_config Operational settings. */
    private plugin_config $config;

    /** @var credential_provider Credential presence only. */
    private credential_provider $credentials;

    /**
     * Create an overview service.
     *
     * @param scan_repository $repository Scan persistence.
     * @param plugin_config $config Operational settings.
     * @param credential_provider $credentials Credential presence check.
     */
    public function __construct(
        scan_repository $repository,
        plugin_config $config,
        credential_provider $credentials
    ) {
        $this->repository = $repository;
        $this->config = $config;
        $this->credentials = $credentials;
    }

    /**
     * Production service using site configuration.
     *
     * @return self
     */
    public static function from_site_config(): self {
        return new self(
            new scan_repository(),
            plugin_config::from_site_config(),
            new config_credentials()
        );
    }

    /**
     * Limit scan aggregates to the history this user is allowed to see.
     *
     * Site managers stay unscoped. Configuration cards are unchanged.
     *
     * @param int $userid Viewer user id.
     * @return self
     */
    public function for_viewer(int $userid): self {
        if (scan_access::can_manage_site($userid)) {
            return $this;
        }
        $copy = clone $this;
        $copy->repository = $this->repository->limited_to_viewer($userid);
        return $copy;
    }

    /**
     * Whether the master scanner setting is on.
     *
     * @return bool
     */
    public function is_enabled(): bool {
        return $this->config->enabled;
    }

    /**
     * Whether a non-empty API key is configured. Never returns the key.
     *
     * @return bool
     */
    public function has_api_key(): bool {
        return $this->credentials->has_api_key();
    }

    /**
     * Whether scanning can actually run (enabled and credentials present).
     *
     * @return bool
     */
    public function is_operational(): bool {
        return $this->config->enabled && $this->credentials->has_api_key();
    }

    /**
     * Whether the Overview scanner radar should animate.
     *
     * True only when the scanner is enabled and credentials are present.
     * Disabled, missing-key, and other non-operational states are false.
     *
     * @return bool
     */
    public function scanner_radar_active(): bool {
        return $this->is_operational();
    }

    /**
     * Whether the Overview VirusTotal radar should animate.
     *
     * True only while the availability circuit is closed. Open, half-open,
     * and provider-unavailable states are false. A lone 429 that has not
     * opened the circuit still leaves the provider Available on the card,
     * so the radar stays in motion to match that label.
     *
     * @return bool
     */
    public function provider_radar_active(): bool {
        $health = $this->provider_health_snapshot();
        return ($health['state'] ?? '') === provider_health::STATE_CLOSED;
    }

    /**
     * Whether the Assignment auto-scan setting is on.
     *
     * @return bool
     */
    public function is_assignscan_setting_on(): bool {
        return $this->config->assignscan;
    }

    /**
     * Whether Assignment auto-scan can currently queue work.
     *
     * @return bool
     */
    public function is_assignscan_effective(): bool {
        return $this->config->assignment_auto_scan_enabled() && $this->credentials->has_api_key();
    }

    /**
     * Stable scanner-state key for presentation.
     *
     * @return string disabled, configrequired, or enabled
     */
    public function scanner_state(): string {
        if ($this->config->enabled && !$this->credentials->has_api_key()) {
            return 'configrequired';
        }
        if (!$this->config->enabled) {
            return 'disabled';
        }
        return 'enabled';
    }

    /**
     * Dashboard protection headline key (operational, configrequired, disabled, provideropen).
     *
     * @return string
     */
    public function protection_state(): string {
        if (!$this->credentials->has_api_key()) {
            return 'configrequired';
        }
        if (!$this->config->enabled) {
            return 'disabled';
        }
        $health = $this->provider_health_snapshot();
        if (!empty($health['isopen'])) {
            return 'provideropen';
        }
        return 'operational';
    }

    /**
     * Stable assignment-state key for presentation.
     *
     * @return string disabled, blockedmaster, blockedcredentials, or enabled
     */
    public function assignment_state(): string {
        if (!$this->config->assignscan) {
            return 'disabled';
        }
        if (!$this->credentials->has_api_key()) {
            return 'blockedcredentials';
        }
        return 'enabled';
    }

    /**
     * Site-wide status counts including total.
     *
     * @return array<string,int>
     */
    public function get_status_counts(): array {
        return $this->repository->get_overview_status_counts();
    }

    /**
     * Scans created in the last 24 hours.
     *
     * @return int
     */
    public function count_last_24_hours(): int {
        return $this->repository->count_created_since(time() - DAYSECS);
    }

    /**
     * Scans created in the last 7 days.
     *
     * @return int
     */
    public function count_last_7_days(): int {
        return $this->repository->count_created_since(time() - WEEKSECS);
    }

    /**
     * Newest scan rows for the overview table.
     *
     * @param int $limit Maximum rows.
     * @return \stdClass[]
     */
    public function get_recent_scans(int $limit = self::RECENT_LIMIT): array {
        return $this->repository->get_recent_scans($limit);
    }

    /**
     * Active async scans awaiting provider work.
     *
     * @return int
     */
    public function count_active_scans(): int {
        return $this->repository->count_active_scans();
    }

    /**
     * VirusTotal circuit snapshot for the overview dashboard.
     *
     * @return array{state:string,failures:int,openuntil:int,isopen:bool}
     */
    public function provider_health_snapshot(): array {
        return (new provider_health())->dashboard_snapshot();
    }

    /**
     * File coverage registry summary counts.
     *
     * @return array<string,int>
     */
    public function coverage_state_counts(): array {
        return file_coverage_registry::state_counts();
    }

    /**
     * Malicious scans with quarantine or enforcement outcomes (dashboard).
     *
     * @return int
     */
    public function count_quarantine_related(): int {
        return $this->repository->count_quarantine_inventory();
    }

    /**
     * Active processing-phase counts (not invented statuses).
     *
     * @return array<string,int>
     */
    public function phase_counts(): array {
        return [
            scan_phase::QUEUED => $this->repository->count_by_phase(scan_phase::QUEUED),
            scan_phase::HASHLOOKUP => $this->repository->count_by_phase(scan_phase::HASHLOOKUP),
            scan_phase::UPLOADREQUIRED => $this->repository->count_by_phase(scan_phase::UPLOADREQUIRED),
            scan_phase::SUBMITTED => $this->repository->count_by_phase(scan_phase::SUBMITTED),
            scan_phase::POLLING => $this->repository->count_by_phase(scan_phase::POLLING),
        ];
    }

    /**
     * SHA-256 reuse among completed verdicts with a stored hash.
     *
     * @return array{completed:int,uniquehashes:int,reused:int}
     */
    public function deduplication_snapshot(): array {
        $completed = $this->repository->count_completed_verdicts();
        $unique = $this->repository->count_distinct_completed_hashes();
        return [
            'completed' => $completed,
            'uniquehashes' => $unique,
            'reused' => max(0, $completed - $unique),
        ];
    }

    /**
     * Archive inspection aggregates and configured limits.
     *
     * @return array<string,int>
     */
    public function archive_snapshot(): array {
        $counts = $this->repository->archive_depth_counts();
        $counts['maxmembers'] = $this->config->archivemaxmembers;
        $counts['maxdepth'] = $this->config->archivemaxdepth;
        $counts['maxextractedmb'] = $this->config->archivemaxextractedmb;
        $counts['archivescan'] = $this->config->archivescan ? 1 : 0;
        return $counts;
    }

    /**
     * Daily scan volume for a trailing window.
     *
     * @param int $days Days including today.
     * @return array<int,int>
     */
    public function volume_by_day(int $days = 7): array {
        return $this->repository->count_created_by_day($days);
    }

    /**
     * Recent enforcement rows.
     *
     * @param int $limit Maximum rows.
     * @return \stdClass[]
     */
    public function get_enforcement_events(int $limit = 8): array {
        return $this->repository->get_enforcement_events($limit);
    }

    /**
     * Latest stored error code for system health.
     *
     * @return string
     */
    public function latest_error_code(): string {
        return $this->repository->latest_error_code();
    }

    /**
     * Error-status counts grouped by stored error code.
     *
     * @param int $limit Maximum distinct codes.
     * @return array<int,array{errorcode:string,count:int}>
     */
    public function error_code_counts(int $limit = 5): array {
        return $this->repository->error_code_counts($limit);
    }

    /**
     * Live gate policies currently consumed by runtime.
     *
     * @return array{unknownpolicy:string,suspiciouspolicy:string,providererrorpolicy:string}
     */
    public function live_policies(): array {
        return [
            'unknownpolicy' => $this->config->unknownpolicy,
            'suspiciouspolicy' => $this->config->suspiciouspolicy,
            'providererrorpolicy' => $this->config->providererrorpolicy,
        ];
    }
}
