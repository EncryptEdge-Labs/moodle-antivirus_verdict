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
 * Archive container orchestration (ZIP/MBZ via ZipArchive).
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

use antivirus_verdict\archive_outcome;
use antivirus_verdict\scan_phase;
use antivirus_verdict\scan_source;
use antivirus_verdict\scan_status;
use antivirus_verdict\task\process_archive;
use core\task\manager;


/**
 * Queues adhoc extraction for supported containers; never stores members in a
 * permanent plugin archive file area.
 */
class archive_scanner {
    /** @var scan_service Scan engine. */
    private scan_service $scanservice;

    /** @var plugin_config Operational settings. */
    private plugin_config $config;

    /** @var archive_extractor Extractor. */
    private archive_extractor $extractor;

    /** @var archive_member_scanner Member queue. */
    private archive_member_scanner $memberscanner;

    /** @var archive_orchestrator Parent finalisation. */
    private archive_orchestrator $orchestrator;

    /** @var scan_repository Persistence. */
    private scan_repository $repository;

    /**
     * Create an archive scanner orchestrator.
     *
     * @param scan_service $scanservice Scan engine.
     * @param plugin_config $config Operational settings.
     * @param archive_extractor|null $extractor Extractor.
     * @param archive_member_scanner|null $memberscanner Member queue.
     * @param archive_orchestrator|null $orchestrator Parent finalisation.
     * @param scan_repository|null $repository Persistence.
     */
    public function __construct(
        scan_service $scanservice,
        plugin_config $config,
        ?archive_extractor $extractor = null,
        ?archive_member_scanner $memberscanner = null,
        ?archive_orchestrator $orchestrator = null,
        ?scan_repository $repository = null
    ) {
        $limits = archive_limits::from_site_config($config);
        $this->scanservice = $scanservice;
        $this->config = $config;
        $this->extractor = $extractor ?? new archive_extractor($limits);
        $this->memberscanner = $memberscanner ?? new archive_member_scanner($scanservice);
        $this->orchestrator = $orchestrator ?? archive_orchestrator::from_site_config();
        $this->repository = $repository ?? new scan_repository();
    }

    /**
     * Production scanner using site configuration.
     *
     * @return self
     */
    public static function from_site_config(): self {
        $service = scan_service::from_site_config();
        return new self($service, plugin_config::from_site_config());
    }

    /**
     * Whether this row should stay open for archive inspection.
     *
     * Detection only. Does not write status or queue work.
     *
     * @param \stdClass $record Scan row.
     * @param \stored_file|null $file Container file when still available.
     * @return bool
     */
    public function will_inspect_container(\stdClass $record, ?\stored_file $file): bool {
        if (!$this->config->archive_scan_enabled() || !$file) {
            return false;
        }
        if ((string) ($record->source ?? '') === scan_source::ARCHIVE) {
            return false;
        }
        if ((int) ($record->parentscanid ?? 0) > 0) {
            return false;
        }
        $format = $this->extractor->detect_format($file);
        return $format === 'zip'
            || $format === 'mbz'
            || $format === 'unsupported_7z'
            || $format === 'unsupported_rar';
    }

    /**
     * When the container is a supported archive, queue member extraction.
     *
     * @param \stdClass $record Completed container scan row.
     * @param \stored_file|null $file Container file when still available.
     * @param bool $parentlockheld True when the caller already holds scan_{id}.
     * @return bool True when the plugin copy must be kept for process_archive.
     */
    public function maybe_scan_container(
        \stdClass $record,
        ?\stored_file $file,
        bool $parentlockheld = false
    ): bool {
        if (!$file || !$this->will_inspect_container($record, $file)) {
            return false;
        }

        $format = $this->extractor->detect_format($file);
        if ($format === 'unsupported_7z' || $format === 'unsupported_rar') {
            $this->orchestrator->mark_uninspectable(
                $record,
                archive_outcome::UNSUPPORTED,
                'error_archive_unsupported',
                $parentlockheld
            );
            return false;
        }
        if (!class_exists('ZipArchive')) {
            $this->orchestrator->mark_uninspectable(
                $record,
                archive_outcome::EXTRACT_ERROR,
                'error_archive_unavailable',
                $parentlockheld
            );
            return false;
        }

        $this->orchestrator->mark_processing($record, archive_outcome::PROCESSING, $parentlockheld);
        $this->queue_archive_task((int) $record->id);
        return true;
    }

    /**
     * Adhoc worker entry: extract members and enqueue scans.
     *
     * Safe to run more than once. A terminal archive outcome is left unchanged.
     * The plugin copy is not deleted here; finalisation deletes it after the
     * container verdict and any required enforcement are stored.
     *
     * @param int $scanid Container scan id.
     */
    public function process_container(int $scanid): void {
        $record = $this->repository->get_by_id($scanid);
        if (!$record) {
            return;
        }
        if (!$this->config->archivescan) {
            $this->release_disabled_container($record);
            return;
        }
        $outcome = (string) ($record->archiveoutcome ?? '');
        if (
            $outcome === archive_outcome::COMPLETE
            || $outcome === archive_outcome::UNSUPPORTED
            || $outcome === archive_outcome::EXTRACT_ERROR
        ) {
            return;
        }
        $this->extract_and_queue_members($record);
        $fresh = $this->repository->get_by_id($scanid);
        if (!$fresh) {
            return;
        }
        $done = (string) ($fresh->archiveoutcome ?? '');
        if (
            $done === archive_outcome::COMPLETE
            || $done === archive_outcome::UNSUPPORTED
            || $done === archive_outcome::EXTRACT_ERROR
        ) {
            return;
        }
        $children = $this->repository->find_children_by_parent($scanid);
        if ($children !== [] && !archive_aggregate::has_active_children($children)) {
            $this->orchestrator->maybe_finalize_parent($scanid);
        }
    }

    /**
     * Queue another archive task for a container that is already processing.
     *
     * Does not call the provider and does not extract in this request.
     *
     * @param int $scanid Container scan id.
     */
    public function requeue_container(int $scanid): void {
        if ($scanid <= 0) {
            return;
        }
        if (!$this->config->archivescan) {
            $record = $this->repository->get_by_id($scanid);
            if ($record) {
                $this->release_disabled_container($record);
            }
            return;
        }
        $this->queue_archive_task($scanid);
    }

    /**
     * Extract members from the still-present container copy and enqueue scans.
     *
     * @param \stdClass $record Container scan row.
     */
    private function extract_and_queue_members(\stdClass $record): void {
        $scanid = (int) $record->id;
        $children = $this->repository->find_children_by_parent($scanid);
        if ($children !== []) {
            // Do not inflate the archive again. Compare the central directory
            // with the children already stored. Partial coverage cannot be clean.
            $file = $this->scanservice->stored_file_from_record($record);
            if (!$file) {
                $this->orchestrator->mark_processing(
                    $record,
                    archive_outcome::INCOMPLETE,
                    false,
                    'error_invalidfile'
                );
                return;
            }
            if (archive_member_scanner::archive_has_uncovered_entries($file, $children) === true) {
                $this->orchestrator->mark_processing(
                    $record,
                    archive_outcome::INCOMPLETE,
                    false,
                    'error_archive_member'
                );
            }
            return;
        }
        $supplement = false;
        $file = $this->scanservice->stored_file_from_record($record);
        if (!$file) {
            if (!$supplement) {
                $this->orchestrator->mark_uninspectable(
                    $record,
                    archive_outcome::EXTRACT_ERROR,
                    'error_invalidfile'
                );
                return;
            }
            if (archive_aggregate::has_active_children($children)) {
                $this->orchestrator->mark_processing(
                    $record,
                    archive_outcome::INCOMPLETE,
                    false,
                    'error_invalidfile'
                );
            }
            return;
        }

        if (!$supplement && $file->get_filesize() > $this->config->maxbytes) {
            $this->orchestrator->mark_uninspectable(
                $record,
                archive_outcome::EXTRACT_ERROR,
                'error_toolarge'
            );
            return;
        }

        $temppath = $this->materialise_temp($file);
        if ($temppath === '') {
            $this->fail_extract($record, $supplement, 'error_archive_corrupt');
            return;
        }

        $workdir = $this->make_workdir();
        if ($workdir === '') {
            @unlink($temppath);
            $this->fail_extract($record, $supplement, 'error_archive_corrupt');
            return;
        }

        try {
            $deadline = time() + archive_limits::MAX_WORK_SECONDS;
            $result = $this->extractor->extract_zip_path($temppath, $workdir, $deadline);

            if ($result->uninspectable) {
                $reason = $result->reason !== '' ? $result->reason : 'error_archive_corrupt';
                $this->fail_extract($record, $supplement, $reason);
                return;
            }

            if ($result->limitsexceeded) {
                $this->orchestrator->mark_processing($record, archive_outcome::INCOMPLETE);
            }

            $queued = $this->memberscanner->queue_members($record, $result);
            $this->record_skipped_members($record, $result);
            if ($this->extractor->skipped_real_members($result->skipped)) {
                $this->orchestrator->mark_processing(
                    $record,
                    archive_outcome::INCOMPLETE,
                    false,
                    'error_archive_member'
                );
            }
            if ($queued === 0 && !$result->limitsexceeded && !$result->hasscanmembers && !$supplement) {
                $this->orchestrator->mark_uninspectable(
                    $record,
                    archive_outcome::EXTRACT_ERROR,
                    'error_archive_empty'
                );
                return;
            }
            if ($queued === 0 && !$result->limitsexceeded && $result->hasscanmembers && !$supplement) {
                $existing = $this->repository->find_children_by_parent($scanid);
                if ($existing === []) {
                    $this->orchestrator->mark_uninspectable(
                        $record,
                        archive_outcome::EXTRACT_ERROR,
                        'error_archive_corrupt'
                    );
                }
                return;
            }
            if (
                $result->limitsexceeded && !archive_aggregate::has_active_children(
                    $this->repository->find_children_by_parent($scanid)
                )
            ) {
                $this->orchestrator->maybe_finalize_parent($scanid);
            }
        } finally {
            $this->remove_workdir($workdir);
            @unlink($temppath);
        }
    }

    /**
     * Persist an auditable error row for each real member that was not extracted.
     *
     * @param \stdClass $record Container scan row.
     * @param archive_extract_result $result Extraction result.
     */
    private function record_skipped_members(\stdClass $record, archive_extract_result $result): void {
        foreach ($result->skipped as $skip) {
            if ((string) ($skip['reason'] ?? '') !== 'error_archive_member') {
                continue;
            }
            $relpath = (string) ($skip['relpath'] ?? '');
            if ($relpath === '') {
                continue;
            }
            $this->memberscanner->record_member_error($record, $relpath, 'error_archive_member');
        }
    }

    /**
     * Record an extraction failure.
     *
     * A first attempt with no children is terminal. A retry that already has
     * children must not discard that partial inspection.
     *
     * @param \stdClass $record Container scan row.
     * @param bool $supplement True when child rows already exist.
     * @param string $errorcode Stable error code.
     */
    private function fail_extract(\stdClass $record, bool $supplement, string $errorcode): void {
        if ($supplement) {
            $this->orchestrator->mark_processing(
                $record,
                archive_outcome::INCOMPLETE,
                false,
                $errorcode
            );
            return;
        }
        $this->orchestrator->mark_uninspectable(
            $record,
            archive_outcome::EXTRACT_ERROR,
            $errorcode
        );
    }

    /**
     * Stop an open container after archive scanning was turned off.
     *
     * Does not call the provider and does not extract. A parent that already
     * has engine counts keeps that verdict. A parent with no provider result
     * is closed as not scanned. Children that already exist are left alone.
     *
     * @param \stdClass $record Container scan row.
     */
    private function release_disabled_container(\stdClass $record): void {
        if ($this->config->archivescan) {
            return;
        }
        if ((string) ($record->archiveoutcome ?? '') !== archive_outcome::PROCESSING) {
            return;
        }
        if ($this->repository->find_children_by_parent((int) $record->id) !== []) {
            return;
        }
        $record->archiveoutcome = archive_outcome::NONE;
        if ((string) $record->status === scan_status::PENDING) {
            $engines = (int) ($record->totalengines ?? 0);
            if ($engines > 0) {
                $status = (new result_normaliser())->status_from_stats([
                    'malicious' => $record->malicious,
                    'suspicious' => $record->suspicious,
                    'undetected' => $record->undetected,
                    'harmless' => $record->harmless,
                    'timeout' => $record->timeout,
                ]);
                if ($status !== null) {
                    $record->status = $status;
                    $record->phase = scan_phase::COMPLETED;
                    $record->timecompleted = time();
                }
            } else {
                $record->status = scan_status::NOTSCANNED;
                $record->phase = scan_phase::SKIPPED;
                $record->timecompleted = time();
            }
        }
        $this->repository->update($record);
    }

    /**
     * Whether the stored file is a ZIP-style container (legacy helper for tests).
     *
     * @param \stored_file $file Moodle file.
     * @return bool
     */
    public function is_zip_container(\stored_file $file): bool {
        $format = $this->extractor->detect_format($file);
        return $format === 'zip' || $format === 'mbz';
    }

    /**
     * Queue background archive extraction for a container scan.
     *
     * @param int $scanid Container scan id.
     */
    private function queue_archive_task(int $scanid): void {
        $task = new process_archive();
        $task->set_custom_data((object) ['scanid' => $scanid]);
        manager::queue_adhoc_task($task, true);
    }

    /**
     * Copy a container stored file to a temp zip path.
     *
     * @param \stored_file $file Container file.
     * @return string Temp zip path or empty string.
     */
    private function materialise_temp(\stored_file $file): string {
        $path = tempnam(sys_get_temp_dir(), 'avvzip');
        if ($path === false) {
            return '';
        }
        if (!$file->copy_content_to($path)) {
            @unlink($path);
            return '';
        }
        return $path;
    }

    /**
     * Create a private temp directory for extraction.
     *
     * @return string Empty work directory path or empty string.
     */
    private function make_workdir(): string {
        $base = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'avvarch_' . bin2hex(random_bytes(8));
        if (@mkdir($base, 0700, true) || is_dir($base)) {
            return $base;
        }
        return '';
    }

    /**
     * Recursively delete an extraction work directory.
     *
     * @param string $workdir Directory to remove.
     */
    private function remove_workdir(string $workdir): void {
        if ($workdir === '' || !is_dir($workdir)) {
            return;
        }
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($workdir, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($iterator as $path) {
            if ($path->isDir()) {
                @rmdir($path->getPathname());
            } else {
                @unlink($path->getPathname());
            }
        }
        @rmdir($workdir);
    }
}
