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
 * Application service for hash-first VirusTotal scanning of Moodle files.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

use core\lock\lock;
use core\lock\lock_config;
use core\task\adhoc_task;
use antivirus_verdict\provider\file_lookup_result;
use antivirus_verdict\provider\file_payload;
use antivirus_verdict\provider\malware_provider;
use antivirus_verdict\provider\provider_exception;
use antivirus_verdict\provider\virustotal\client;
use antivirus_verdict\archive_outcome;
use antivirus_verdict\enforcement_state;
use antivirus_verdict\scan_phase;
use antivirus_verdict\scan_source;
use antivirus_verdict\scan_status;


/**
 * Orchestrates stored_file validation, SHA-256, persistence, and provider calls.
 *
 * Does not render HTML or accept request parameters. Request-time consumers
 * such as assignment events must call {@see enqueue_file_scan()} so VirusTotal
 * HTTP work runs in the existing process_scan adhoc task.
 */
class scan_service {
    /** @var malware_provider Provider client. */
    private malware_provider $provider;
    /** @var scan_repository Persistence. */
    private scan_repository $repository;
    /** @var file_hasher SHA-256 calculator. */
    private file_hasher $hasher;
    /** @var plugin_config Operational settings. */
    private plugin_config $config;
    /** @var adhoc_scan_scheduler Background queue. */
    private adhoc_scan_scheduler $scheduler;
    /** @var result_normaliser Status mapping. */
    private result_normaliser $normaliser;
    /** @var malicious_enforcer Post-upload response to a malicious verdict. */
    private malicious_enforcer $enforcer;
    /** @var scan_notifications|null Injected notifier; production uses site config. */
    private ?scan_notifications $notifications;
    /** @var operation_counts Site-wide provider operation totals. */
    private operation_counts $operations;
    /** @var operation_reservation Local provider-operation ceilings. */
    private operation_reservation $reservations;

    /** @var bool True while manual web kickoff is running synchronous process_scan steps. */
    private bool $inmanualkickoff = false;

    /** @var bool True while {@see process_scan()} is running (scan already has an adhoc task). */
    private bool $inprocessscan = false;

    /**
     * Create a scan service.
     *
     * @param malware_provider $provider Provider client.
     * @param scan_repository $repository Persistence.
     * @param file_hasher $hasher SHA-256 calculator.
     * @param plugin_config $config Operational settings.
     * @param adhoc_scan_scheduler $scheduler Background queue.
     * @param result_normaliser|null $normaliser Status mapping.
     * @param malicious_enforcer|null $enforcer Post-upload enforcement.
     * @param scan_notifications|null $notifications Terminal-scan notifier.
     * @param operation_counts|null $operations Site-wide operation totals.
     * @param operation_reservation|null $reservations Local operation ceilings.
     */
    public function __construct(
        malware_provider $provider,
        scan_repository $repository,
        file_hasher $hasher,
        plugin_config $config,
        adhoc_scan_scheduler $scheduler,
        ?result_normaliser $normaliser = null,
        ?malicious_enforcer $enforcer = null,
        ?scan_notifications $notifications = null,
        ?operation_counts $operations = null,
        ?operation_reservation $reservations = null
    ) {
        $this->provider = $provider;
        $this->repository = $repository;
        $this->hasher = $hasher;
        $this->config = $config;
        $this->scheduler = $scheduler;
        $this->normaliser = $normaliser ?? new result_normaliser();
        $this->enforcer = $enforcer ?? new malicious_enforcer($repository, $config, $hasher);
        $this->notifications = $notifications;
        $this->operations = $operations ?? new operation_counts();
        $this->reservations = $reservations ?? new operation_reservation();
    }

    /**
     * Production service using site configuration.
     *
     * @return self
     */
    public static function from_site_config(): self {
        return new self(
            client::from_site_config(),
            new scan_repository(),
            new file_hasher(),
            plugin_config::from_site_config(),
            new adhoc_scan_scheduler()
        );
    }

    /**
     * Create or reuse an in-flight scan and start hash lookup immediately.
     *
     * Intended for explicit callers such as tests. The Manual Scan page uses
     * {@see enqueue_file_scan()} so the browser does not wait for VirusTotal.
     * Assignment event handlers must use {@see enqueue_file_scan()} instead.
     *
     * @param \stored_file $file Moodle-managed file.
     * @param string $source Scan consumer (manual, assign).
     * @param int $userid Associated user id, or 0 for system.
     * @param bool $forcerescan Whether to skip reuse of a stored verdict for this content.
     * @param int $parentscanid Container scan id for archive members.
     * @param string|null $auditfilepath Member path inside a container for audit.
     * @return \stdClass Scan record.
     */
    public function queue_file_scan(
        \stored_file $file,
        string $source,
        int $userid = 0,
        bool $forcerescan = false,
        int $parentscanid = 0,
        ?string $auditfilepath = null,
        int $submissionid = 0,
        int $initiatedby = 0
    ): \stdClass {
        return $this->create_or_reuse_scan(
            $file,
            $source,
            $userid,
            true,
            $forcerescan,
            $parentscanid,
            $auditfilepath,
            $submissionid,
            $initiatedby
        );
    }

    /**
     * Create or reuse an in-flight scan and queue background processing.
     *
     * Does not hash the file or call VirusTotal. The process_scan task runs
     * {@see advance_new_scan()} later using the persisted scan id.
     *
     * @param \stored_file $file Moodle-managed file.
     * @param string $source Scan consumer (manual, assign).
     * @param int $userid Associated user id, or 0 for system.
     * @param bool $forcerescan Whether to skip reuse of a stored verdict for this content.
     * @return \stdClass Scan record.
     */
    public function enqueue_file_scan(
        \stored_file $file,
        string $source,
        int $userid = 0,
        bool $forcerescan = false,
        int $parentscanid = 0,
        ?string $auditfilepath = null,
        int $submissionid = 0,
        int $initiatedby = 0
    ): \stdClass {
        return $this->create_or_reuse_scan(
            $file,
            $source,
            $userid,
            false,
            $forcerescan,
            $parentscanid,
            $auditfilepath,
            $submissionid,
            $initiatedby
        );
    }

    /**
     * Persist a queued scan, optionally advancing it in the current request.
     *
     * An in-flight scan of the same file is still reused even when a rescan was
     * requested, so an explicit rescan cannot duplicate concurrent provider work.
     *
     * @param \stored_file $file Moodle-managed file.
     * @param string $source Scan consumer (manual, assign).
     * @param int $userid Associated user id, or 0 for system.
     * @param bool $advanceimmediately Whether to run hash lookup/upload now.
     * @param bool $forcerescan Whether to skip reuse of a stored verdict for this content.
     * @return \stdClass Scan record.
     */
    private function create_or_reuse_scan(
        \stored_file $file,
        string $source,
        int $userid,
        bool $advanceimmediately,
        bool $forcerescan = false,
        int $parentscanid = 0,
        ?string $auditfilepath = null,
        int $submissionid = 0,
        int $initiatedby = 0
    ): \stdClass {
        $this->assert_scanable_file($file);
        if (!scan_source::is_valid($source)) {
            throw new \invalid_parameter_exception('error_invalidrequest');
        }
        $userid = max(0, $userid);

        $lock = $this->acquire_lock('file_' . $file->get_pathnamehash());
        try {
            $existing = $this->repository->find_active_by_pathnamehash($file->get_pathnamehash());
            if ($existing) {
                return $existing;
            }
            if ($parentscanid === 0) {
                $open = $this->open_processing_container($file);
                if ($open) {
                    return $open;
                }
            }
            $record = $this->new_record(
                $file,
                $source,
                $userid,
                $parentscanid,
                $auditfilepath,
                $submissionid,
                $initiatedby
            );
            if ($source === scan_source::MANUAL) {
                $record->sha256 = $this->hasher->hash_stored_file($file);
            }
            $record->id = $this->repository->insert($record);
            if ($source === scan_source::MANUAL) {
                $this->repository->discard_gate_preflight_for_manual($record);
            }
            if ($advanceimmediately) {
                $this->advance_new_scan($record, $file, null, $forcerescan);
            } else {
                $this->scheduler->queue_scan((int) $record->id, $forcerescan);
                if ($source === scan_source::MANUAL && $this->manual_kickoff_enabled()) {
                    $this->kickoff_manual_processing((int) $record->id, $forcerescan);
                }
            }
            return $this->repository->get_by_id((int) $record->id) ?? $record;
        } finally {
            $lock->release();
        }
    }

    /**
     * Open container inspection for the same SHA-256, if one exists.
     *
     * Pathname reuse still wins first. This only attaches a different Moodle
     * file to an inspection that is already processing. It does not treat that
     * row as a finished clean verdict and it does not call the provider.
     *
     * @param \stored_file $file Candidate file.
     * @return \stdClass|null
     */
    private function open_processing_container(\stored_file $file): ?\stdClass {
        $name = \core_text::strtolower($file->get_filename());
        $container = str_ends_with($name, '.zip')
            || str_ends_with($name, '.mbz')
            || str_ends_with($name, '.7z')
            || str_ends_with($name, '.rar')
            || (bool) preg_match('/\.r\d{2}$/', $name);
        if (!$container) {
            return null;
        }
        try {
            $sha = $this->hasher->hash_stored_file($file);
        } catch (\Throwable $e) {
            return null;
        }
        if ($sha === '') {
            return null;
        }
        foreach ($this->repository->find_by_sha256($sha) as $row) {
            if ((int) ($row->parentscanid ?? 0) !== 0) {
                continue;
            }
            if ((string) ($row->archiveoutcome ?? '') === archive_outcome::PROCESSING) {
                return $row;
            }
        }
        return null;
    }

    /**
     * Continue lookup, upload, or analysis retrieval for an existing scan.
     *
     * Safe for cron: does not use $USER. Reloads state after taking a per-scan
     * lock so duplicate task execution cannot upload twice. Returns whether a
     * later retry is needed.
     *
     * @param int $scanid Scan id from task custom data.
     * @param adhoc_task|null $task Current adhoc task, when running in cron.
     * @param bool $forcerescan Whether to skip reuse of a stored verdict for this content.
     * @return bool True when the caller should delay and retry.
     */
    public function process_scan(int $scanid, ?adhoc_task $task = null, bool $forcerescan = false): bool {
        if ($scanid <= 0) {
            return false;
        }

        $lock = $this->acquire_lock('scan_' . $scanid);
        $this->inprocessscan = true;
        try {
            $record = $this->repository->get_by_id($scanid);
            if (!$record) {
                return false;
            }
            if (!scan_phase::is_active($record->phase)) {
                return false;
            }
            if ($this->is_stale($record)) {
                $this->fail($record, 'error_stale');
                return false;
            }
            // Failure retries are capped. An analysis that is already submitted
            // and still running at the provider is not one of those retries.
            $awaitingprovider = $record->phase === scan_phase::POLLING
                || ($record->phase === scan_phase::UPLOADREQUIRED && trim((string) $record->vtanalysisid) !== '');
            if ((int) $record->pollattempts >= retry_policy::MAX_ATTEMPTS && !$awaitingprovider) {
                $this->fail($record, 'error_maxattempts');
                return false;
            }

            try {
                if ($record->phase === scan_phase::QUEUED || $record->phase === scan_phase::HASHLOOKUP) {
                    $file = $this->stored_file_from_record($record);
                    if (!$file) {
                        $this->fail($record, 'error_invalidfile');
                        return false;
                    }
                    return $this->advance_new_scan($record, $file, $task, $forcerescan);
                }
                if ($record->phase === scan_phase::UPLOADREQUIRED) {
                    if (trim((string) $record->vtanalysisid) !== '') {
                        return $this->poll_analysis($record, $task);
                    }
                    $file = $this->stored_file_from_record($record);
                    if (!$file) {
                        $this->fail($record, 'error_invalidfile');
                        return false;
                    }
                    return $this->upload_unknown($record, $file, $task);
                }
                return $this->poll_analysis($record, $task);
            } catch (provider_exception $e) {
                return $this->handle_provider_exception($record, $e, $task);
            }
        } finally {
            $this->inprocessscan = false;
            $lock->release();
        }
    }

    /**
     * Re-queue stuck active scans or fail those that have been pending too long.
     *
     * Does not call VirusTotal. Intended for the recover_stale_scans scheduled
     * task when an adhoc worker was lost.
     *
     * @param int|null $now Unix timestamp, or null for time().
     * @return int Number of scans failed or re-queued.
     */
    public function recover_stale_scans(?int $now = null): int {
        $now = $now ?? time();
        $modifiedbefore = $now - retry_policy::STALE_REQUEUE_AFTER;
        $createdfail = $now - retry_policy::STALE_FAIL_AFTER;
        $handled = 0;

        foreach ($this->repository->find_stale_active($modifiedbefore, retry_policy::STALE_BATCH) as $row) {
            $lock = $this->try_lock('scan_' . (int) $row->id);
            if (!$lock) {
                continue;
            }
            try {
                $record = $this->repository->get_by_id((int) $row->id);
                if (!$record || !scan_phase::is_active($record->phase)) {
                    continue;
                }
                if (
                    (int) $record->pollattempts >= retry_policy::MAX_ATTEMPTS
                    || ((int) $record->timecreated > 0 && (int) $record->timecreated <= $createdfail)
                ) {
                    $this->fail($record, 'error_stale');
                    $handled++;
                    continue;
                }
                $this->scheduler->queue_scan((int) $record->id);
                $handled++;
            } finally {
                $lock->release();
            }
        }

        $handled += $this->recover_stale_archives($modifiedbefore);
        return $handled;
    }

    /**
     * Resume or fail containers whose archive task was lost.
     *
     * Does not call VirusTotal and does not send the parent through process_scan.
     * The parent lock is held only around the state decision.
     *
     * @param int $modifiedbefore Inclusive Unix timestamp.
     * @return int Number of containers requeued or closed.
     */
    private function recover_stale_archives(int $modifiedbefore): int {
        $handled = 0;
        foreach ($this->repository->find_stale_archives($modifiedbefore, retry_policy::STALE_BATCH) as $row) {
            $lock = $this->try_lock('scan_' . (int) $row->id);
            if (!$lock) {
                continue;
            }
            try {
                $record = $this->repository->get_by_id((int) $row->id);
                if (!$record || (string) ($record->archiveoutcome ?? '') !== archive_outcome::PROCESSING) {
                    continue;
                }
                $children = $this->repository->find_children_by_parent((int) $record->id);
                $file = $this->stored_file_from_record($record);
                if ($children === []) {
                    if ($file) {
                        archive_scanner::from_site_config()->requeue_container((int) $record->id);
                    } else {
                        archive_orchestrator::from_site_config()->mark_uninspectable(
                            $record,
                            archive_outcome::EXTRACT_ERROR,
                            'error_invalidfile',
                            true
                        );
                    }
                    $handled++;
                    continue;
                }
                if (!$file) {
                    // Any child set without the container copy is partial.
                    // Finalising it as clean would hide members that were never queued.
                    archive_orchestrator::from_site_config()->mark_processing(
                        $record,
                        archive_outcome::INCOMPLETE,
                        true,
                        'error_invalidfile'
                    );
                    if (!archive_aggregate::has_active_children($children)) {
                        archive_orchestrator::from_site_config()->maybe_finalize_parent((int) $record->id, true);
                    }
                    $handled++;
                    continue;
                }
                if (archive_aggregate::has_active_children($children)) {
                    continue;
                }
                archive_orchestrator::from_site_config()->maybe_finalize_parent((int) $record->id, true);
                $handled++;
            } finally {
                $lock->release();
            }
        }
        return $handled;
    }

    /**
     * Validate that the argument is a real Moodle file, not a directory.
     *
     * @param \stored_file $file Moodle file.
     */
    public function assert_scanable_file(\stored_file $file): void {
        if ($file->is_directory()) {
            throw new \invalid_parameter_exception('error_invalidfile');
        }
        if ($file->get_filename() === '' || $file->get_filename() === '.') {
            throw new \invalid_parameter_exception('error_invalidfile');
        }
    }

    /**
     * Run hash lookup and optional upload for a newly created record.
     *
     * With $forcerescan the stored verdict for this SHA-256 is not reused, so
     * VirusTotal is queried again. Attaching to another in-flight analysis of
     * the same content is still allowed: that deduplicates concurrent work
     * rather than returning a previously stored verdict.
     *
     * @param \stdClass $record Scan record.
     * @param \stored_file $file Moodle file.
     * @param adhoc_task|null $task Current adhoc task, when running in cron.
     * @param bool $forcerescan Whether to skip reuse of a stored verdict for this content.
     * @return bool True when the caller should delay and retry.
     */
    private function advance_new_scan(
        \stdClass $record,
        \stored_file $file,
        ?adhoc_task $task = null,
        bool $forcerescan = false
    ): bool {
        $record->phase = scan_phase::HASHLOOKUP;
        $record->status = scan_status::PENDING;
        $record->sha256 = $this->hasher->hash_stored_file($file);
        $this->repository->update($record);

        $hashlock = $this->acquire_lock('hash_' . $record->sha256);
        try {
            if (!$forcerescan && $this->reuse_completed_hash($record)) {
                $this->note_completed_reuse();
                return false;
            }
            // A forced rescan still joins work that is already at the provider.
            if ($this->join_inflight_analysis($record)) {
                $this->note_inflight_join();
                return $this->schedule_retry($record, $task, 'pending', null);
            }
            $this->require_reservation($this->reservations->reserve_lookup($this->config->lookupceiling));
            try {
                $lookup = $this->provider->lookup_file_hash($record->sha256);
            } finally {
                $this->note_hash_lookup();
            }
            if ($lookup->found) {
                $this->complete_from_lookup($record, $lookup);
                return false;
            }
            if ($file->get_filesize() > $this->config->maxbytes) {
                $this->skip($record, 'error_filetoolarge');
                return false;
            }
            return $this->upload_unknown($record, $file, $task);
        } catch (provider_exception $e) {
            return $this->handle_provider_exception($record, $e, $task);
        } finally {
            $hashlock->release();
        }
    }

    /**
     * Resolve an admitted SHA before any new provider submission.
     *
     * Owns the hash_{sha256} lock. Callers must not already hold it.
     * A completed reusable verdict or an in-flight analysis returns without
     * a provider call. Otherwise this performs the hash lookup only.
     *
     * @param string $sha256 Lowercase hex SHA-256.
     * @return admitted_hash_resolution
     */
    public function resolve_admitted_hash(string $sha256): admitted_hash_resolution {
        $hashlock = $this->acquire_lock('hash_' . $sha256);
        try {
            $known = $this->repository->find_completed_verdict_by_sha256($sha256);
            if ($known) {
                $this->note_completed_reuse();
                return new admitted_hash_resolution(admitted_hash_resolution::REUSED, $known);
            }
            $existing = $this->repository->find_active_by_sha256($sha256);
            if ($existing) {
                if (trim((string) ($existing->vtanalysisid ?? '')) !== '') {
                    $this->note_inflight_join();
                }
                return new admitted_hash_resolution(admitted_hash_resolution::JOINED, $existing);
            }
            $this->require_reservation($this->reservations->reserve_lookup($this->config->lookupceiling));
            try {
                $lookup = $this->provider->lookup_file_hash($sha256);
            } finally {
                $this->note_hash_lookup();
            }
            return new admitted_hash_resolution(admitted_hash_resolution::LOOKUP, null, $lookup);
        } finally {
            $hashlock->release();
        }
    }

    /**
     * Attach this row to an in-flight analysis of the same SHA-256.
     *
     * Does not look up or upload. Returns false when no analysis id exists yet.
     *
     * @param \stdClass $record Current scan.
     * @return bool
     */
    private function join_inflight_analysis(\stdClass $record): bool {
        $sibling = $this->find_inflight_analysis($record);
        if (!$sibling) {
            return false;
        }
        $record->vtanalysisid = $sibling->vtanalysisid;
        $record->vtfileid = $sibling->vtfileid;
        $record->phase = scan_phase::POLLING;
        $record->status = scan_status::PENDING;
        $record->timesubmitted = time();
        $this->repository->update($record);
        return true;
    }

    /**
     * Persist a known-file lookup as a completed scan when stats exist.
     *
     * @param \stdClass $record Scan record.
     * @param file_lookup_result $lookup Provider lookup.
     */
    private function complete_from_lookup(\stdClass $record, file_lookup_result $lookup): void {
        $record->vtfileid = $lookup->sha256;
        $status = $this->normaliser->status_from_stats($lookup->lastanalysisstats);
        if ($status === null) {
            $this->fail($record, 'error_malformed');
            return;
        }
        $this->complete($record, $status, $lookup->lastanalysisstats);
    }

    /**
     * Upload an unknown file and schedule analysis polling.
     *
     * When this runs inside process_scan, the current adhoc task must be
     * delayed through {@see adhoc_scan_scheduler::schedule_retry()}. Direct
     * queue_adhoc_task(..., true) would skip a duplicate of the still-running
     * task. On Moodle 4.5 and 5.0 the running row is then deleted and the scan
     * would stay pending with no worker.
     *
     * @param \stdClass $record Scan record.
     * @param \stored_file $file Moodle file.
     * @param adhoc_task|null $task Current adhoc task, when running in cron.
     * @return bool True when the caller should delay and retry.
     */
    private function upload_unknown(\stdClass $record, \stored_file $file, ?adhoc_task $task = null): bool {
        if (trim((string) $record->vtanalysisid) !== '') {
            $record->phase = scan_phase::POLLING;
            $record->status = scan_status::PENDING;
            $this->repository->update($record);
            return $this->schedule_retry($record, $task, 'pending', null);
        }
        if ($file->get_filesize() > $this->config->maxbytes) {
            $this->skip($record, 'error_filetoolarge');
            return false;
        }
        $record->phase = scan_phase::UPLOADREQUIRED;
        $record->status = scan_status::PENDING;
        $this->repository->update($record);

        $payload = $this->payload_from_stored_file($file);
        try {
            $this->require_reservation($this->reservations->reserve_upload($this->config->uploadceiling));
            try {
                $submission = $this->provider->upload_file($payload);
            } finally {
                $this->note_upload();
            }
        } finally {
            $payload->close();
        }

        $record->vtanalysisid = $submission->analysisid;
        $record->phase = scan_phase::POLLING;
        $record->status = scan_status::PENDING;
        $record->timesubmitted = time();
        $record->errorcode = null;
        $this->repository->update($record);
        return $this->schedule_retry($record, $task, 'pending', null);
    }

    /**
     * Fetch one shared analysis and apply it to every row waiting on it.
     *
     * The analysis lock is not the file hash lock. A worker that loses it
     * does not call the provider; the worker that holds it polls once and
     * fans the result out. The lock is released before this method returns.
     * It is not the hash_{sha256} lock, so hash lookup and upload stay free.
     *
     * @param \stdClass $record Scan record.
     * @param adhoc_task|null $task Current task.
     * @return bool Whether to retry later.
     */
    private function poll_analysis(\stdClass $record, ?adhoc_task $task): bool {
        $analysisid = trim((string) $record->vtanalysisid);
        if ($analysisid === '') {
            $this->fail($record, 'error_malformed');
            return false;
        }
        $sha256 = (string) $record->sha256;
        $analysislock = $this->try_lock($this->analysis_lock_key($analysisid));
        if (!$analysislock) {
            // Another worker is already polling this analysis.
            return $this->schedule_pending_poll($record, $task);
        }
        try {
            $current = $this->repository->get_by_id((int) $record->id);
            if (!$current || !$this->awaits_analysis($current, $analysisid, $sha256)) {
                return false;
            }
            $current->phase = scan_phase::POLLING;
            $current->timelastpoll = time();
            $this->repository->update($current);

            $this->require_reservation($this->reservations->reserve_poll($this->config->pollceiling));
            $failed = null;
            try {
                $analysis = $this->provider->get_analysis($analysisid);
            } catch (provider_exception $e) {
                $failed = $e;
            } finally {
                $this->note_poll();
            }
            if ($failed) {
                return $this->apply_analysis_exception($current, $analysisid, $sha256, $failed, $task);
            }
            return $this->apply_analysis_result($current, $analysisid, $sha256, $analysis, $task);
        } finally {
            $analysislock->release();
        }
    }

    /**
     * Apply one provider poll to each active row sharing this analysis and SHA-256.
     *
     * Rows are finalised by the existing complete/fail/pending paths. A row
     * with a different hash, or a finished archive parent, is not selected.
     *
     * @param \stdClass $current Scan that owns this worker.
     * @param string $analysisid Provider analysis id.
     * @param string $sha256 Hex SHA-256.
     * @param \antivirus_verdict\provider\analysis_result $analysis Provider poll.
     * @param adhoc_task|null $task Current task.
     * @return bool Whether the current scan should retry.
     */
    private function apply_analysis_result(
        \stdClass $current,
        string $analysisid,
        string $sha256,
        \antivirus_verdict\provider\analysis_result $analysis,
        ?adhoc_task $task
    ): bool {
        $vtstatus = strtolower($analysis->status);
        $waiting = $this->repository->find_waiting_by_analysis($analysisid, $sha256);
        if (in_array($vtstatus, ['queued', 'in-progress', 'pending'], true)) {
            $now = time();
            foreach ($waiting as $row) {
                if (!$this->awaits_analysis($row, $analysisid, $sha256)) {
                    continue;
                }
                $row->phase = scan_phase::POLLING;
                $row->status = scan_status::PENDING;
                $row->timelastpoll = $now;
                $this->repository->update($row);
            }
            return $this->schedule_pending_poll($current, $task);
        }
        if ($vtstatus !== 'completed') {
            $this->fail_waiting($waiting, $analysisid, $sha256, 'error_malformed');
            return false;
        }
        $status = $this->normaliser->status_from_stats($analysis->stats);
        if ($status === null) {
            $this->fail_waiting($waiting, $analysisid, $sha256, 'error_malformed');
            return false;
        }
        foreach ($waiting as $row) {
            $fresh = $this->repository->get_by_id((int) $row->id);
            if (!$fresh || !$this->awaits_analysis($fresh, $analysisid, $sha256)) {
                continue;
            }
            $this->complete($fresh, $status, $analysis->stats);
        }
        return false;
    }

    /**
     * Apply one provider failure to each row waiting on this analysis.
     *
     * @param \stdClass $current Scan that owns this worker.
     * @param string $analysisid Provider analysis id.
     * @param string $sha256 Hex SHA-256.
     * @param provider_exception $exception Provider error.
     * @param adhoc_task|null $task Current task.
     * @return bool Whether the current scan should retry.
     */
    private function apply_analysis_exception(
        \stdClass $current,
        string $analysisid,
        string $sha256,
        provider_exception $exception,
        ?adhoc_task $task
    ): bool {
        $retry = false;
        $seen = false;
        foreach ($this->repository->find_waiting_by_analysis($analysisid, $sha256) as $row) {
            $fresh = $this->repository->get_by_id((int) $row->id);
            if (!$fresh || !$this->awaits_analysis($fresh, $analysisid, $sha256)) {
                continue;
            }
            $rowtask = ((int) $fresh->id === (int) $current->id) ? $task : null;
            $rowretry = $this->handle_provider_exception($fresh, $exception, $rowtask);
            if ((int) $fresh->id === (int) $current->id) {
                $retry = $rowretry;
                $seen = true;
            }
        }
        return $seen ? $retry : false;
    }

    /**
     * Fail each row that is still waiting on this analysis.
     *
     * @param \stdClass[] $waiting Candidate rows.
     * @param string $analysisid Provider analysis id.
     * @param string $sha256 Hex SHA-256.
     * @param string $errorcode Stable error code.
     */
    private function fail_waiting(array $waiting, string $analysisid, string $sha256, string $errorcode): void {
        foreach ($waiting as $row) {
            $fresh = $this->repository->get_by_id((int) $row->id);
            if (!$fresh || !$this->awaits_analysis($fresh, $analysisid, $sha256)) {
                continue;
            }
            $this->fail($fresh, $errorcode);
        }
    }

    /**
     * Whether this row is still an active consumer of one provider analysis.
     *
     * @param \stdClass $record Scan row.
     * @param string $analysisid Provider analysis id.
     * @param string $sha256 Hex SHA-256.
     * @return bool
     */
    private function awaits_analysis(\stdClass $record, string $analysisid, string $sha256): bool {
        return scan_phase::is_active((string) $record->phase)
            && trim((string) $record->vtanalysisid) === $analysisid
            && (string) $record->sha256 === $sha256;
    }

    /**
     * Lock key for one provider analysis. Not the file hash lock.
     *
     * @param string $analysisid Provider analysis id.
     * @return string
     */
    private function analysis_lock_key(string $analysisid): string {
        return 'analysis_' . hash('sha256', $analysisid);
    }

    /**
     * Apply a provider failure to the scan record.
     *
     * @param \stdClass $record Scan record.
     * @param provider_exception $exception Provider error.
     * @param adhoc_task|null $task Current task.
     * @return bool Whether to retry later.
     */
    private function handle_provider_exception(
        \stdClass $record,
        provider_exception $exception,
        ?adhoc_task $task
    ): bool {
        $code = $exception->errorcode;
        if (retry_policy::is_permanent($code)) {
            if ($code === 'error_filetoolarge' || $code === 'error_disabled') {
                $this->skip($record, $code);
            } else {
                $this->fail($record, $code);
            }
            return false;
        }
        if (
            $code === 'error_uploadinterrupted'
            && ((int) $record->pollattempts + 1) >= retry_policy::MAX_LARGE_UPLOAD_ATTEMPTS
        ) {
            $this->fail($record, $code);
            return false;
        }
        if (retry_policy::is_retryable($code)) {
            $record->errorcode = $code;
            $record->status = scan_status::PENDING;
            $record->pollattempts = (int) $record->pollattempts + 1;
            $this->repository->update($record);
            return $this->schedule_retry($record, $task, $code, $exception->retryafter);
        }
        $this->fail($record, $code !== '' ? $code : 'error_generic');
        return false;
    }

    /**
     * Increment attempts and request a delayed retry when allowed.
     *
     * @param \stdClass $record Scan record.
     * @param adhoc_task|null $task Current task.
     * @param string $reason Retry reason code.
     * @param int|null $retryafter Provider Retry-After.
     * @return bool
     */
    private function schedule_retry(
        \stdClass $record,
        ?adhoc_task $task,
        string $reason,
        ?int $retryafter
    ): bool {
        if ((int) $record->pollattempts >= retry_policy::MAX_ATTEMPTS) {
            $this->fail($record, 'error_maxattempts');
            return false;
        }
        if ($task) {
            $this->scheduler->schedule_retry(
                $task,
                retry_policy::delay_seconds($reason, $retryafter, (int) $record->pollattempts)
            );
        } else if (!$this->inmanualkickoff && !$this->inprocessscan) {
            $this->scheduler->queue_scan((int) $record->id);
        }
        return true;
    }

    /**
     * Reschedule a poll while the provider analysis is still running.
     *
     * Does not increment pollattempts and does not apply the failure cap.
     * The stale-scan time limit is what closes an analysis that never finishes.
     *
     * @param \stdClass $record Scan record.
     * @param adhoc_task|null $task Current task.
     * @return bool
     */
    private function schedule_pending_poll(\stdClass $record, ?adhoc_task $task): bool {
        if ($task) {
            $this->scheduler->schedule_retry(
                $task,
                retry_policy::delay_seconds('pending', null, 1)
            );
        } else if (!$this->inmanualkickoff && !$this->inprocessscan) {
            $this->scheduler->queue_scan((int) $record->id);
        }
        return true;
    }

    /**
     * Mark the scan complete with detection counts.
     *
     * A malicious verdict reached here was not available when the file was
     * accepted, so the file is still live in Moodle. Enforcement runs before
     * the plugin copy is cleaned up, because for gate and manual scans that
     * copy is the only content Verdict can quarantine.
     *
     * @param \stdClass $record Scan record.
     * @param string $status Product status.
     * @param array|null $stats Provider stats.
     */
    private function complete(\stdClass $record, string $status, ?array $stats): void {
        $counts = $this->normaliser->persistable_counts($stats);
        $record->phase = scan_phase::COMPLETED;
        $record->malicious = $counts['malicious'];
        $record->suspicious = $counts['suspicious'];
        $record->undetected = $counts['undetected'];
        $record->harmless = $counts['harmless'];
        $record->timeout = $counts['timeout'];
        $record->totalengines = $counts['totalengines'];
        $record->errorcode = null;

        $file = $this->stored_file_from_record($record);
        $inspect = false;
        $archives = null;
        if ((int) ($record->parentscanid ?? 0) === 0) {
            try {
                $archives = new archive_scanner($this, $this->config);
                $inspect = $archives->will_inspect_container($record, $file);
            } catch (\Throwable $e) {
                debugging('antivirus_verdict archive hook failed', \DEBUG_DEVELOPER);
                $archives = null;
                $inspect = false;
            }
        }

        // A clean or suspicious container stays pending until member inspection
        // finishes. A malicious provider verdict is final and cannot be weakened.
        $publishnow = !$inspect || $status === scan_status::MALICIOUS;
        if ($publishnow) {
            $record->status = $status;
            $record->timecompleted = time();
        } else {
            $record->status = scan_status::PENDING;
            $record->timecompleted = 0;
        }
        $this->repository->update($record);
        if ($publishnow) {
            $this->enforce_if_malicious($record);
            $this->notify_scan_finished($record);
        }

        $keepcopy = false;
        if ((int) ($record->parentscanid ?? 0) > 0) {
            try {
                archive_orchestrator::from_site_config()->member_finished($record);
            } catch (\Throwable $e) {
                debugging('antivirus_verdict archive aggregate hook failed', \DEBUG_DEVELOPER);
            }
        } else if ($inspect && $archives) {
            try {
                $keepcopy = $archives->maybe_scan_container($record, $file, $this->inprocessscan);
            } catch (\Throwable $e) {
                debugging('antivirus_verdict archive hook failed', \DEBUG_DEVELOPER);
            }
        }
        if (!$keepcopy) {
            $this->cleanup_plugin_copy($record);
        }
    }

    /**
     * Apply post-upload enforcement to a malicious verdict.
     *
     * Runs inside the caller's per-scan lock. Enforcement never throws back
     * into the scan engine: a scan that produced a verdict has succeeded even
     * if the security response did not, and the outcome is recorded either way.
     *
     * @param \stdClass $record Scan record with a persisted verdict.
     */
    private function enforce_if_malicious(\stdClass $record): void {
        if ((string) $record->status !== scan_status::MALICIOUS) {
            return;
        }
        // Archive members are short-lived gate copies; parent enforcement runs via archive_orchestrator.
        if ((int) ($record->parentscanid ?? 0) > 0) {
            return;
        }
        try {
            $this->enforcer->enforce($record);
        } catch (\Throwable $e) {
            debugging(
                'antivirus_verdict malicious enforcement failed for scan ' . (int) $record->id,
                \DEBUG_DEVELOPER
            );
        }
    }

    /**
     * Mark the scan as a terminal provider or processing failure.
     *
     * @param \stdClass $record Scan record.
     * @param string $errorcode Stable error code.
     */
    private function fail(\stdClass $record, string $errorcode): void {
        $record->status = scan_status::ERROR;
        $record->phase = scan_phase::FAILED;
        $record->errorcode = $errorcode;
        $record->timecompleted = time();
        $this->repository->update($record);
        $this->notify_scan_finished($record);
        if ((int) ($record->parentscanid ?? 0) > 0) {
            try {
                archive_orchestrator::from_site_config()->member_finished($record);
            } catch (\Throwable $e) {
                debugging('antivirus_verdict archive aggregate hook failed', \DEBUG_DEVELOPER);
            }
        }
        $this->cleanup_plugin_copy($record);
    }

    /**
     * Attempt administrator messaging after the scan row is already persisted.
     *
     * Notification delivery is a secondary side effect. Failures here must not
     * change status, phase, errorcode, pollattempts, or schedule another
     * VirusTotal poll.
     *
     * @param \stdClass $record Scan row after persistence.
     */
    private function notify_scan_finished(\stdClass $record): void {
        if ((int) ($record->parentscanid ?? 0) > 0) {
            return;
        }
        try {
            $notifier = $this->notifications ?? scan_notifications::from_site_config();
            $notifier->scan_finished($record);
        } catch (\Throwable $e) {
            debugging('antivirus_verdict notification hook failed', \DEBUG_DEVELOPER);
        }
    }

    /**
     * Mark the scan as intentionally not submitted.
     *
     * @param \stdClass $record Scan record.
     * @param string $errorcode Stable skip reason.
     */
    private function skip(\stdClass $record, string $errorcode): void {
        $record->status = scan_status::NOTSCANNED;
        $record->phase = scan_phase::SKIPPED;
        $record->errorcode = $errorcode;
        $record->timecompleted = time();
        $this->repository->update($record);
        if ((int) ($record->parentscanid ?? 0) > 0) {
            try {
                archive_orchestrator::from_site_config()->member_finished($record);
            } catch (\Throwable $e) {
                debugging('antivirus_verdict archive aggregate hook failed', \DEBUG_DEVELOPER);
            }
        }
        $this->cleanup_plugin_copy($record);
    }

    /**
     * Delete a plugin-owned manual copy after a terminal scan.
     *
     * Assignment and other Moodle files are never deleted. Missing copies are
     * not fatal.
     *
     * @param \stdClass $record Scan record.
     */
    private function cleanup_plugin_copy(\stdClass $record): void {
        try {
            plugin_file_lifecycle::delete_copy_for_scan($record);
        } catch (\Throwable $e) {
            debugging(
                'antivirus_verdict plugin copy cleanup failed for scan ' . (int) $record->id,
                \DEBUG_DEVELOPER
            );
        }
    }

    /**
     * Build a provider payload from a stored file without Moodle domain objects.
     *
     * @param \stored_file $file Moodle file.
     * @return file_payload
     */
    private function payload_from_stored_file(\stored_file $file): file_payload {
        $filename = $file->get_filename();
        if ($filename === '' || $filename === '.') {
            $filename = 'file';
        }
        $handle = $file->get_content_file_handle();
        if ($handle === false) {
            throw new provider_exception('error_invalidrequest');
        }
        return new file_payload($handle, $filename, $file->get_filesize());
    }

    /**
     * Reload the Moodle file for a scan. Missing files are not fatal to history.
     *
     * @param \stdClass $record Scan record.
     * @return \stored_file|null
     */
    public function stored_file_from_record(\stdClass $record): ?\stored_file {
        $fs = get_file_storage();
        if (!empty($record->fileid)) {
            $file = $fs->get_file_by_id((int) $record->fileid);
            if ($file) {
                return $file;
            }
        }
        if (!empty($record->pathnamehash)) {
            $file = $fs->get_file_by_hash($record->pathnamehash);
            if ($file) {
                return $file;
            }
        }
        return null;
    }

    /**
     * Initialise a pending scan row from File API metadata.
     *
     * @param \stored_file $file Moodle file.
     * @param string $source Scan source.
     * @param int $userid Associated user.
     * @return \stdClass
     */
    private function new_record(
        \stored_file $file,
        string $source,
        int $userid,
        int $parentscanid = 0,
        ?string $auditfilepath = null,
        int $submissionid = 0,
        int $initiatedby = 0
    ): \stdClass {
        $now = time();
        $record = new \stdClass();
        $record->fileid = $file->get_id();
        $record->contenthash = $file->get_contenthash();
        $record->pathnamehash = $file->get_pathnamehash();
        $record->contextid = $file->get_contextid();
        $record->courseid = $this->courseid_from_contextid($file->get_contextid());
        $record->component = $file->get_component();
        $record->filearea = $file->get_filearea();
        $record->itemid = $file->get_itemid();
        // Ordinary rows store the File API directory. Archive members store the
        // directory inside the container so a/file.jpg and b/file.jpg stay
        // distinct. The copy itself is always stored at "/". The scan screen
        // reads component and filearea for the file location, not this field.
        $record->filepath = ($auditfilepath !== null && $auditfilepath !== '')
            ? $auditfilepath
            : $file->get_filepath();
        $record->filename = $file->get_filename();
        $record->userid = $userid;
        $record->initiatedby = max(0, $initiatedby);
        $record->submissionid = max(0, $submissionid);
        $record->source = $source;
        $record->parentscanid = max(0, $parentscanid);
        $record->archiveoutcome = \antivirus_verdict\archive_outcome::NONE;
        $record->sha256 = '';
        $record->filesize = $file->get_filesize();
        $record->mimetype = $file->get_mimetype();
        $record->status = scan_status::PENDING;
        $record->phase = scan_phase::QUEUED;
        $record->vtanalysisid = null;
        $record->vtfileid = null;
        $record->malicious = null;
        $record->suspicious = null;
        $record->undetected = null;
        $record->harmless = null;
        $record->timeout = null;
        $record->totalengines = null;
        $record->errorcode = null;
        $record->enforcement = enforcement_state::NONE;
        $record->pollattempts = 0;
        $record->timelastpoll = 0;
        $record->timesubmitted = 0;
        $record->timecreated = $now;
        $record->timemodified = $now;
        $record->timecompleted = 0;
        return $record;
    }

    /**
     * Reuse a completed clean/suspicious/malicious verdict for the same SHA-256.
     *
     * Error and notscanned rows are not reused as a security decision.
     *
     * @param \stdClass $record Current scan.
     * @return bool
     */
    private function reuse_completed_hash(\stdClass $record): bool {
        $known = $this->repository->find_completed_verdict_by_sha256((string) $record->sha256);
        if (!$known || (int) $known->id === (int) $record->id) {
            return false;
        }
        $outcome = (string) ($known->archiveoutcome ?? '');
        $finishedcontainer = in_array($outcome, [
            archive_outcome::COMPLETE,
            archive_outcome::UNSUPPORTED,
            archive_outcome::EXTRACT_ERROR,
            archive_outcome::INCOMPLETE,
        ], true);
        $maliciousopen = $outcome === archive_outcome::PROCESSING
            && (string) $known->status === scan_status::MALICIOUS;
        if ($finishedcontainer || $maliciousopen) {
            $this->publish_reused_verdict($record, $known, $finishedcontainer);
            return true;
        }
        $record->vtfileid = $known->vtfileid;
        $record->vtanalysisid = $known->vtanalysisid;
        $this->complete($record, (string) $known->status, [
            'malicious' => $known->malicious,
            'suspicious' => $known->suspicious,
            'undetected' => $known->undetected,
            'harmless' => $known->harmless,
            'timeout' => $known->timeout,
        ]);
        return true;
    }

    /**
     * Copy a reusable container verdict without starting another extraction.
     *
     * An open malicious container is copied as a terminal malicious verdict.
     * Its processing outcome is not copied, because this row is not the open
     * inspection.
     *
     * @param \stdClass $record Current scan.
     * @param \stdClass $known Reusable verdict.
     * @param bool $copyoutcome True when the source archive inspection is finished.
     */
    private function publish_reused_verdict(\stdClass $record, \stdClass $known, bool $copyoutcome): void {
        $record->vtfileid = $known->vtfileid;
        $record->vtanalysisid = $known->vtanalysisid;
        $record->malicious = $known->malicious;
        $record->suspicious = $known->suspicious;
        $record->undetected = $known->undetected;
        $record->harmless = $known->harmless;
        $record->timeout = $known->timeout;
        $record->totalengines = $known->totalengines;
        $record->status = (string) $known->status;
        $record->phase = scan_phase::COMPLETED;
        $record->errorcode = $copyoutcome ? $known->errorcode : null;
        $record->archiveoutcome = $copyoutcome
            ? (string) ($known->archiveoutcome ?? '')
            : archive_outcome::NONE;
        $record->timecompleted = time();
        $this->repository->update($record);
        $this->enforce_if_malicious($record);
        $this->notify_scan_finished($record);
        $this->cleanup_plugin_copy($record);
    }

    /**
     * Another in-flight scan of the same content that already has an analysis id.
     *
     * @param \stdClass $record Current scan.
     * @return \stdClass|null
     */
    private function find_inflight_analysis(\stdClass $record): ?\stdClass {
        foreach ($this->repository->find_by_sha256($record->sha256) as $other) {
            if ((int) $other->id === (int) $record->id) {
                continue;
            }
            if (scan_phase::is_active($other->phase) && !empty($other->vtanalysisid)) {
                return $other;
            }
        }
        return null;
    }

    /**
     * Course id for history scoping, or 0 when the context is not in a course.
     *
     * @param int $contextid Context id.
     * @return int
     */
    private function courseid_from_contextid(int $contextid): int {
        $context = \context::instance_by_id($contextid, \IGNORE_MISSING);
        if (!$context) {
            return 0;
        }
        $coursecontext = $context->get_course_context(false);
        return $coursecontext ? (int) $coursecontext->instanceid : 0;
    }

    /**
     * Whether an active scan has been pending longer than the stale threshold.
     *
     * @param \stdClass $record Scan record.
     * @param int|null $now Unix timestamp, or null for time().
     * @return bool
     */
    private function is_stale(\stdClass $record, ?int $now = null): bool {
        $now = $now ?? time();
        return scan_phase::is_active($record->phase)
            && (int) $record->timecreated > 0
            && (int) $record->timecreated <= ($now - retry_policy::STALE_FAIL_AFTER);
    }

    /**
     * Whether in-request manual kickoff should run (web manual scan only).
     *
     * @return bool
     */
    private function manual_kickoff_enabled(): bool {
        if (defined('PHPUNIT_TEST') && PHPUNIT_TEST) {
            return false;
        }
        if (defined('CLI_SCRIPT') && CLI_SCRIPT) {
            return false;
        }
        if (defined('AJAX_SCRIPT') && AJAX_SCRIPT) {
            return true;
        }
        return !empty($_SERVER['REQUEST_METHOD']);
    }

    /**
     * Run process_scan immediately for a manual scan (best-effort).
     *
     * Manual scans are queued for cron, but many staging sites do not run the
     * adhoc worker promptly. This advances hash lookup and upload within the
     * same web request. It must not busy-poll a still-queued VirusTotal analysis.
     * Kickoff stops when the phase is polling and leaves that wait to cron.
     *
     * @param int $scanid Scan id.
     * @param bool $forcerescan Whether to skip stored verdict reuse.
     */
    private function kickoff_manual_processing(int $scanid, bool $forcerescan = false): void {
        if ($scanid <= 0) {
            return;
        }
        $this->inmanualkickoff = true;
        try {
            $steps = 0;
            while ($steps < 12) {
                $steps++;
                try {
                    $retry = $this->process_scan($scanid, null, $forcerescan);
                } catch (\Throwable $e) {
                    debugging('antivirus_verdict manual kickoff stopped: ' . $e->getMessage(), DEBUG_DEVELOPER);
                    break;
                }
                if (!$retry) {
                    break;
                }
                $record = $this->repository->get_by_id($scanid);
                if (!$record || !scan_phase::is_active($record->phase)) {
                    break;
                }
                if ($this->kickoff_must_wait($record)) {
                    break;
                }
            }
        } finally {
            $this->inmanualkickoff = false;
        }
    }

    /**
     * Whether manual kickoff should stop and leave work for cron/adhoc.
     *
     * Pending analysis, rate limits, and other delayed retries are not
     * completed by looping process_scan in the current HTTP request.
     *
     * @param \stdClass $record Scan row after a retryable process_scan step.
     * @return bool
     */
    private function kickoff_must_wait(\stdClass $record): bool {
        $errorcode = (string) $record->errorcode;
        if ((string) $record->phase === scan_phase::POLLING) {
            return true;
        }
        if (retry_policy::is_retryable($errorcode) || retry_policy::is_transient_unavailability($errorcode)) {
            return true;
        }
        return $errorcode === 'pending';
    }

    /**
     * Stop before provider HTTP when the local ceiling or its storage refuses the slot.
     *
     * Denial and storage failure are both non-clean and are not malware.
     *
     * @param reservation_result $result Reservation outcome.
     */
    private function require_reservation(reservation_result $result): void {
        if ($result->outcome === reservation_result::ALLOWED) {
            return;
        }
        $code = $result->outcome === reservation_result::DENIED
            ? 'error_operationlimit'
            : 'error_guardunavailable';
        throw new provider_exception($code);
    }

    /**
     * Record one hash lookup. Accounting failure must not change the scan.
     */
    private function note_hash_lookup(): void {
        $this->note(function (): void {
            $this->operations->record_hash_lookup();
        });
    }

    /**
     * Record one upload. Accounting failure must not change the scan.
     */
    private function note_upload(): void {
        $this->note(function (): void {
            $this->operations->record_upload();
        });
    }

    /**
     * Record one analysis poll. Accounting failure must not change the scan.
     */
    private function note_poll(): void {
        $this->note(function (): void {
            $this->operations->record_poll();
        });
    }

    /**
     * Record one completed-result reuse. Accounting failure must not change the scan.
     */
    private function note_completed_reuse(): void {
        $this->note(function (): void {
            $this->operations->record_completed_reuse();
        });
    }

    /**
     * Record one in-flight join. Accounting failure must not change the scan.
     */
    private function note_inflight_join(): void {
        $this->note(function (): void {
            $this->operations->record_inflight_join();
        });
    }

    /**
     * Run an accounting write and discard its failure.
     *
     * @param callable $write Totals update.
     */
    private function note(callable $write): void {
        try {
            $write();
        } catch (\Throwable $e) {
            debugging('antivirus_verdict operation accounting failed', \DEBUG_DEVELOPER);
        }
    }

    /**
     * Exclusive lock used to prevent duplicate active submissions.
     *
     * @param string $key Lock key within the plugin namespace.
     * @param int $timeout Seconds to wait.
     * @return lock
     */
    private function acquire_lock(string $key, int $timeout = 30): lock {
        $factory = lock_config::get_lock_factory('antivirus_verdict');
        $lock = $factory->get_lock($key, $timeout);
        if (!$lock) {
            throw new \moodle_exception('error_scanbusy', 'antivirus_verdict');
        }
        return $lock;
    }

    /**
     * Non-blocking lock. Null when another worker already holds it.
     *
     * @param string $key Lock key within the plugin namespace.
     * @return lock|null
     */
    private function try_lock(string $key): ?lock {
        $factory = lock_config::get_lock_factory('antivirus_verdict');
        $lock = $factory->get_lock($key, 0);
        return $lock ?: null;
    }
}
