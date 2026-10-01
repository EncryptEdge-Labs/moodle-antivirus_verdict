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
 * Finalise archive container scans when member scans complete.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

use antivirus_verdict\archive_outcome;
use antivirus_verdict\enforcement_state;
use antivirus_verdict\scan_phase;
use antivirus_verdict\scan_status;
use core\lock\lock_config;


/**
 * Applies aggregate member verdicts back to the parent container scan row.
 */
class archive_orchestrator {
    /** @var scan_repository Persistence. */
    private scan_repository $repository;

    /** @var malicious_enforcer Post-upload enforcement. */
    private malicious_enforcer $enforcer;

    /** @var scan_notifications|null Injected notifier; production uses site config. */
    private ?scan_notifications $notifications;

    /**
     * Create an archive orchestrator.
     *
     * @param scan_repository|null $repository Persistence.
     * @param malicious_enforcer|null $enforcer Enforcement.
     * @param scan_notifications|null $notifications Terminal-scan notifier.
     */
    public function __construct(
        ?scan_repository $repository = null,
        ?malicious_enforcer $enforcer = null,
        ?scan_notifications $notifications = null
    ) {
        $this->repository = $repository ?? new scan_repository();
        $config = plugin_config::from_site_config();
        $this->enforcer = $enforcer ?? new malicious_enforcer($this->repository, $config, new file_hasher());
        $this->notifications = $notifications;
    }

    /**
     * Production orchestrator.
     *
     * @return self
     */
    public static function from_site_config(): self {
        return new self();
    }

    /**
     * Called when a member scan reaches a terminal phase.
     *
     * @param \stdClass $child Member scan row.
     */
    public function member_finished(\stdClass $child): void {
        $parentid = (int) ($child->parentscanid ?? 0);
        if ($parentid <= 0) {
            return;
        }
        $this->maybe_finalize_parent($parentid);
    }

    /**
     * Apply aggregate results when all member scans have finished.
     *
     * @param int $parentid Container scan id.
     * @param bool $lockheld True when the caller already holds scan_{parentid}.
     */
    public function maybe_finalize_parent(int $parentid, bool $lockheld = false): void {
        $this->with_parent_lock($parentid, $lockheld, function () use ($parentid): void {
            $parent = $this->repository->get_by_id($parentid);
            if (!$parent) {
                return;
            }
            $this->apply_finalize($parent);
        });
    }

    /**
     * Mark a container when extraction could not proceed.
     *
     * @param \stdClass $parent Container scan row.
     * @param string $outcome archive_outcome value.
     * @param string $errorcode Stable error code.
     * @param bool $lockheld True when the caller already holds scan_{parentid}.
     */
    public function mark_uninspectable(
        \stdClass $parent,
        string $outcome,
        string $errorcode,
        bool $lockheld = false
    ): void {
        $this->with_parent_lock((int) $parent->id, $lockheld, function () use ($parent, $outcome, $errorcode): void {
            if (!$this->refresh($parent)) {
                return;
            }
            if ($this->archive_inspection_closed((string) ($parent->archiveoutcome ?? ''))) {
                return;
            }
            $previous = (string) $parent->status;
            $parent->archiveoutcome = $outcome;
            if (archive_aggregate::status_rank($previous) < archive_aggregate::status_rank(scan_status::ERROR)) {
                $parent->status = scan_status::ERROR;
            }
            $parent->errorcode = $errorcode;
            $parent->phase = scan_phase::COMPLETED;
            if ((int) ($parent->timecompleted ?? 0) <= 0) {
                $parent->timecompleted = time();
            }
            $this->repository->update($parent);
            $this->release_container_copy($parent);
            if (
                $previous !== scan_status::MALICIOUS && (string) $parent->status === scan_status::ERROR
                && $previous !== scan_status::ERROR
            ) {
                $this->notify_parent($parent);
            }
        });
    }

    /**
     * Begin member-scan phase on a container row.
     *
     * @param \stdClass $parent Container scan row.
     * @param string $outcome Initial outcome (processing or incomplete).
     * @param bool $lockheld True when the caller already holds scan_{parentid}.
     * @param string|null $errorcode Optional code recorded while inspection stays open.
     */
    public function mark_processing(
        \stdClass $parent,
        string $outcome = archive_outcome::PROCESSING,
        bool $lockheld = false,
        ?string $errorcode = null
    ): void {
        $this->with_parent_lock((int) $parent->id, $lockheld, function () use ($parent, $outcome, $errorcode): void {
            if (!$this->refresh($parent)) {
                return;
            }
            if ($this->archive_inspection_closed((string) ($parent->archiveoutcome ?? ''))) {
                return;
            }
            $parent->archiveoutcome = $outcome;
            if ($errorcode !== null && trim((string) ($parent->errorcode ?? '')) === '') {
                $parent->errorcode = $errorcode;
            }
            $this->repository->update($parent);
        });
    }

    /**
     * Publish the container verdict once every member scan is terminal.
     *
     * Caller holds scan_{parentid}. Provider counts are reconstructed when
     * status is still the pending placeholder. Malicious is never weakened.
     *
     * @param \stdClass $parent Container scan row.
     */
    private function apply_finalize(\stdClass $parent): void {
        $outcome = (string) ($parent->archiveoutcome ?? '');
        if ($outcome === '' || $this->archive_inspection_closed($outcome)) {
            return;
        }

        $parentid = (int) $parent->id;
        $children = $this->repository->find_children_by_parent($parentid);
        if (archive_aggregate::has_active_children($children)) {
            return;
        }

        if ($outcome === archive_outcome::PROCESSING && $children !== []) {
            $file = $this->container_file($parent);
            if ($file && archive_member_scanner::archive_has_uncovered_entries($file, $children) === true) {
                $parent->archiveoutcome = archive_outcome::INCOMPLETE;
                $outcome = archive_outcome::INCOMPLETE;
                if (trim((string) ($parent->errorcode ?? '')) === '') {
                    $parent->errorcode = 'error_archive_member';
                }
            }
        }

        $previous = (string) $parent->status;
        $providerstatus = $this->provider_status($parent);
        $aggregate = archive_aggregate::aggregate_status($children);
        $merged = archive_aggregate::merge_container_status($providerstatus, $aggregate);

        $limitflag = ($outcome === archive_outcome::INCOMPLETE);
        if ($limitflag && archive_aggregate::status_rank($merged) < archive_aggregate::status_rank(scan_status::ERROR)) {
            $merged = scan_status::ERROR;
            if (trim((string) ($parent->errorcode ?? '')) === '') {
                $parent->errorcode = 'error_archive_limits';
            }
        }

        if ($merged !== scan_status::ERROR) {
            $parent->errorcode = null;
        } else if (trim((string) ($parent->errorcode ?? '')) === '') {
            $childcode = archive_aggregate::winning_errorcode($children);
            if ($childcode !== null) {
                $parent->errorcode = $childcode;
            }
        }

        $parent->status = $merged;
        if ($merged !== scan_status::PENDING) {
            $parent->phase = scan_phase::COMPLETED;
            if ((int) ($parent->timecompleted ?? 0) <= 0) {
                $parent->timecompleted = time();
            }
        }
        if ($outcome !== archive_outcome::INCOMPLETE) {
            $parent->archiveoutcome = archive_outcome::COMPLETE;
        }
        $this->repository->update($parent);

        if ($merged === scan_status::MALICIOUS) {
            try {
                $this->enforcer->enforce($parent);
            } catch (\Throwable $e) {
                debugging(
                    'antivirus_verdict archive parent enforcement failed for scan ' . $parentid,
                    \DEBUG_DEVELOPER
                );
            }
            $fresh = $this->repository->get_by_id($parentid);
            if ($fresh) {
                $parent->enforcement = $fresh->enforcement;
            }
        }
        $this->release_container_copy($parent);

        $published = (string) $parent->status;
        $notify = scan_status::is_terminal($published)
            && $previous !== scan_status::MALICIOUS
            && ($previous === scan_status::PENDING || $previous !== $published);
        if ($notify) {
            $this->notify_parent($parent);
        }
    }

    /**
     * Provider verdict stored in the count columns.
     *
     * Pending is a placeholder while archive inspection is open. It is not
     * provider evidence and must not be passed to the aggregate ranking.
     *
     * @param \stdClass $parent Container scan row.
     * @return string
     */
    private function provider_status(\stdClass $parent): string {
        $status = (string) $parent->status;
        if ($status !== '' && $status !== scan_status::PENDING) {
            return $status;
        }
        $inferred = (new result_normaliser())->status_from_stats([
            'malicious' => $parent->malicious ?? null,
            'suspicious' => $parent->suspicious ?? null,
            'undetected' => $parent->undetected ?? null,
            'harmless' => $parent->harmless ?? null,
            'timeout' => $parent->timeout ?? null,
        ]);
        if ($inferred === null) {
            if (trim((string) ($parent->errorcode ?? '')) === '') {
                $parent->errorcode = 'error_malformed';
            }
            return scan_status::ERROR;
        }
        return $inferred;
    }

    /**
     * Delete the plugin copy after a terminal archive outcome.
     *
     * A malicious container keeps its copy until enforcement has stored an
     * outcome other than the empty or in-progress states.
     *
     * @param \stdClass $parent Container scan row.
     */
    private function release_container_copy(\stdClass $parent): void {
        if ((string) $parent->status === scan_status::MALICIOUS) {
            $enforcement = (string) ($parent->enforcement ?? '');
            if (
                $enforcement === '' || $enforcement === enforcement_state::NONE
                || $enforcement === enforcement_state::PENDING
            ) {
                return;
            }
        }
        try {
            plugin_file_lifecycle::delete_copy_for_scan($parent);
        } catch (\Throwable $e) {
            debugging(
                'antivirus_verdict archive copy cleanup failed for scan ' . (int) $parent->id,
                \DEBUG_DEVELOPER
            );
        }
    }

    /**
     * Plugin copy for a container row, when it is still stored.
     *
     * @param \stdClass $parent Container scan row.
     * @return \stored_file|null
     */
    private function container_file(\stdClass $parent): ?\stored_file {
        $fs = get_file_storage();
        if (!empty($parent->fileid)) {
            $file = $fs->get_file_by_id((int) $parent->fileid);
            if ($file) {
                return $file;
            }
        }
        if (!empty($parent->pathnamehash)) {
            $file = $fs->get_file_by_hash((string) $parent->pathnamehash);
            if ($file) {
                return $file;
            }
        }
        return null;
    }

    /**
     * Notify after the container verdict is already persisted.
     *
     * @param \stdClass $parent Container scan row.
     */
    private function notify_parent(\stdClass $parent): void {
        try {
            $notifier = $this->notifications ?? scan_notifications::from_site_config();
            $notifier->scan_finished($parent);
        } catch (\Throwable $e) {
            debugging('antivirus_verdict archive notification hook failed', \DEBUG_DEVELOPER);
        }
    }

    /**
     * Whether archive inspection has already published a terminal outcome.
     *
     * @param string $outcome Stored archiveoutcome.
     * @return bool
     */
    private function archive_inspection_closed(string $outcome): bool {
        return in_array($outcome, [
            archive_outcome::COMPLETE,
            archive_outcome::UNSUPPORTED,
            archive_outcome::EXTRACT_ERROR,
        ], true);
    }

    /**
     * Copy a freshly loaded row onto the caller's object.
     *
     * @param \stdClass $parent Container scan row.
     * @return bool
     */
    private function refresh(\stdClass $parent): bool {
        $fresh = $this->repository->get_by_id((int) $parent->id);
        if (!$fresh) {
            return false;
        }
        foreach (get_object_vars($fresh) as $key => $value) {
            $parent->$key = $value;
        }
        return true;
    }

    /**
     * Run a short state update under scan_{parentid}.
     *
     * Lock failure leaves the row unchanged so recovery can retry. The lock is
     * not taken when the caller already holds it, because Moodle locks are not
     * re-entrant and process_scan already holds this key.
     *
     * @param int $parentid Container scan id.
     * @param bool $lockheld True when scan_{parentid} is already held.
     * @param callable $callback Critical section.
     */
    private function with_parent_lock(int $parentid, bool $lockheld, callable $callback): void {
        if ($parentid <= 0) {
            return;
        }
        if ($lockheld) {
            $callback();
            return;
        }
        $factory = lock_config::get_lock_factory('antivirus_verdict');
        $lock = $factory->get_lock('scan_' . $parentid, 30);
        if (!$lock) {
            debugging(
                'antivirus_verdict could not lock archive parent ' . $parentid,
                \DEBUG_DEVELOPER
            );
            return;
        }
        try {
            $callback();
        } finally {
            $lock->release();
        }
    }
}
