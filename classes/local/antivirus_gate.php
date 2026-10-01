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
 * Synchronous antivirus decision gate.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

use antivirus_verdict\archive_outcome;
use antivirus_verdict\enforcement_state;
use antivirus_verdict\provider\file_lookup_result;
use antivirus_verdict\provider\malware_provider;
use antivirus_verdict\provider\provider_exception;
use antivirus_verdict\provider\virustotal\client;
use antivirus_verdict\scan_phase;
use antivirus_verdict\scan_source;
use antivirus_verdict\scan_status;
use antivirus_verdict\scanner;


/**
 * Hash-first VirusTotal lookup with explicit unknown/suspicious/error policies.
 *
 * Does not wait for full VirusTotal analysis. Unknown files stay pending.
 */
class antivirus_gate {
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
    /** @var scan_service|null Central analysis path. Built from this gate's dependencies. */
    private ?scan_service $analysisservice = null;

    /**
     * Create a gate.
     *
     * @param malware_provider $provider Provider client.
     * @param scan_repository $repository Persistence.
     * @param file_hasher $hasher SHA-256 calculator.
     * @param plugin_config $config Operational settings.
     * @param adhoc_scan_scheduler $scheduler Background queue.
     * @param result_normaliser|null $normaliser Status mapping.
     */
    public function __construct(
        malware_provider $provider,
        scan_repository $repository,
        file_hasher $hasher,
        plugin_config $config,
        adhoc_scan_scheduler $scheduler,
        ?result_normaliser $normaliser = null
    ) {
        $this->provider = $provider;
        $this->repository = $repository;
        $this->hasher = $hasher;
        $this->config = $config;
        $this->scheduler = $scheduler;
        $this->normaliser = $normaliser ?? new result_normaliser();
    }

    /**
     * Production gate using site configuration.
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
     * Decide whether Moodle may accept this upload.
     *
     * @param string $filepath Temporary filesystem path from Moodle core.
     * @param string $filename Original filename.
     * @param scanner|null $scanner Scanner used to publish a notice.
     * @return int SCAN_RESULT_* constant.
     */
    public function scan_file(string $filepath, string $filename, ?scanner $scanner = null): int {
        $filename = $this->safe_filename($filename);
        $sha256 = '';
        $filesize = 0;

        try {
            if (!is_file($filepath) || !is_readable($filepath)) {
                $this->persist_error($filename, '', 'error_invalidfile');
                return $this->fail_closed($scanner, $filename, 'error_invalidfile');
            }

            $filesize = filesize($filepath);
            if ($filesize === false) {
                $this->persist_error($filename, '', 'error_invalidfile');
                return $this->fail_closed($scanner, $filename, 'error_invalidfile');
            }
            $filesize = (int) $filesize;

            $sha256 = $this->hasher->hash_path($filepath);
            // Member inspection is off. A completed local blocking verdict for
            // this exact container SHA still blocks. An unknown container is
            // allowed with no scan row and no provider call.
            if (!$this->config->archivescan && $this->is_container_filename($filename)) {
                return $this->decide_selected_areas($filename, $sha256, $filesize, $scanner);
            }
            if (!$this->config->admits_native_upload()) {
                return $this->decide_selected_areas($filename, $sha256, $filesize, $scanner);
            }
            return $this->decide($filepath, $filename, $sha256, $filesize, $scanner);
        } catch (\core\antivirus\scanner_exception $e) {
            throw $e;
        } catch (provider_exception $e) {
            if (retry_policy::is_transient_unavailability($e->errorcode)) {
                return $this->queue_transient($filepath, $filename, $sha256, $filesize, $scanner, $e);
            }
            $this->persist_error($filename, $sha256, $e->errorcode);
            return $this->apply_provider_error($scanner, $filename, $e->errorcode);
        } catch (\Throwable $e) {
            debugging('antivirus_verdict gate failed without a provider result', \DEBUG_DEVELOPER);
            $this->persist_error($filename, $sha256, 'error_generic');
            return $this->fail_closed($scanner, $filename, 'error_generic');
        }
    }

    /**
     * Hash lookup, reuse, persist, and policy decision.
     *
     * @param string $filepath Temporary path.
     * @param string $filename Original filename.
     * @param string $sha256 SHA-256.
     * @param int $filesize Size in bytes.
     * @param scanner|null $scanner Scanner.
     * @return int
     */
    private function decide(
        string $filepath,
        string $filename,
        string $sha256,
        int $filesize,
        ?scanner $scanner
    ): int {
        // The scan_service owns hash_{sha256}. The gate must not hold that lock.
        $resolution = $this->analysis()->resolve_admitted_hash($sha256);
        if ($resolution->kind === admitted_hash_resolution::REUSED && $resolution->row) {
            $record = $this->new_record($filename, $sha256, $filesize);
            $this->copy_verdict($record, $resolution->row);
            $record->id = $this->repository->insert($record);
            $this->repository->update($record);
            return $this->apply_status($scanner, $filename, (string) $record->status);
        }

        if ($resolution->kind === admitted_hash_resolution::JOINED && $resolution->row) {
            $existing = $resolution->row;
            if ($this->is_open_container($existing)) {
                return $this->accept_open_archive($scanner);
            }
            $record = $this->new_record($filename, $sha256, $filesize);
            $record->status = scan_status::PENDING;
            $record->phase = $existing->phase;
            $record->vtanalysisid = $existing->vtanalysisid;
            $record->vtfileid = $existing->vtfileid;
            $record->id = $this->repository->insert($record);
            return $this->apply_unknown($scanner, $filename);
        }

        $lookup = $resolution->lookup;
        if ($lookup && $lookup->found) {
            return $this->complete_known($filepath, $filename, $sha256, $filesize, $lookup, $scanner);
        }

        return $this->queue_unknown($filepath, $filename, $sha256, $filesize, $scanner);
    }

    /**
     * Central analysis path using this gate's provider and repository.
     *
     * @return scan_service
     */
    private function analysis(): scan_service {
        if ($this->analysisservice === null) {
            $this->analysisservice = new scan_service(
                $this->provider,
                $this->repository,
                $this->hasher,
                $this->config,
                $this->scheduler,
                $this->normaliser
            );
        }
        return $this->analysisservice;
    }

    /**
     * Selected-areas admission for a native upload.
     *
     * Reads a completed local verdict only. An unknown hash is allowed with no
     * scan row and no provider work. A database failure propagates so the
     * caller can fail closed. Unknown-file policy does not apply here: the
     * file has not been analysed.
     *
     * @param string $filename Filename.
     * @param string $sha256 SHA-256.
     * @param int $filesize Size.
     * @param scanner|null $scanner Scanner.
     * @return int
     */
    private function decide_selected_areas(
        string $filename,
        string $sha256,
        int $filesize,
        ?scanner $scanner
    ): int {
        $known = $this->repository->find_completed_verdict_by_sha256($sha256);
        if (!$known || !$this->local_verdict_blocks((string) $known->status)) {
            return scanner::SCAN_RESULT_OK;
        }
        $record = $this->new_record($filename, $sha256, $filesize);
        $this->copy_verdict($record, $known);
        $record->id = $this->repository->insert($record);
        $this->repository->update($record);
        return $this->apply_status($scanner, $filename, (string) $record->status);
    }

    /**
     * Whether a completed local verdict must refuse the upload.
     *
     * Malicious always blocks. Suspicious blocks only when that policy is block.
     * Errors, incomplete archives, and unknown hashes are not blocking.
     *
     * @param string $status Product status.
     * @return bool
     */
    private function local_verdict_blocks(string $status): bool {
        if ($status === scan_status::MALICIOUS) {
            return true;
        }
        return $status === scan_status::SUSPICIOUS
            && $this->config->suspiciouspolicy === scan_policy::BLOCK;
    }

    /**
     * Persist a known hash result and apply policy.
     *
     * @param string $filepath Temporary path.
     * @param string $filename Filename.
     * @param string $sha256 SHA-256.
     * @param int $filesize Size.
     * @param file_lookup_result $lookup Provider lookup.
     * @param scanner|null $scanner Scanner.
     * @return int
     */
    private function complete_known(
        string $filepath,
        string $filename,
        string $sha256,
        int $filesize,
        file_lookup_result $lookup,
        ?scanner $scanner
    ): int {
        $status = $this->normaliser->status_from_stats($lookup->lastanalysisstats);
        if ($status === null) {
            $this->persist_error($filename, $sha256, 'error_malformed', $filesize);
            return $this->apply_provider_error($scanner, $filename, 'error_malformed');
        }
        if ($this->defer_archive_inspection($filename, $status)) {
            return $this->queue_known_archive(
                $filepath,
                $filename,
                $sha256,
                $filesize,
                $lookup,
                $status,
                $scanner
            );
        }

        $record = $this->new_record($filename, $sha256, $filesize);
        $record->vtfileid = $lookup->sha256;
        $this->apply_counts($record, $lookup->lastanalysisstats);
        $record->status = $status;
        $record->phase = scan_phase::COMPLETED;
        $record->enforcement = $this->synchronous_enforcement($status);
        $record->timecompleted = time();
        $record->id = $this->repository->insert($record);
        $this->repository->update($record);
        return $this->apply_status($scanner, $filename, $status);
    }

    /**
     * Whether a known non-malicious container must wait for member inspection.
     *
     * Malicious containers stay on the synchronous block path. Suspicious
     * containers stay on the synchronous block path when policy is block.
     * SCAN_RESULT_OK from this path means Moodle may store the file. It does
     * not mean archive members are clean.
     *
     * @param string $filename Filename.
     * @param string $status Provider status.
     * @return bool
     */
    private function defer_archive_inspection(string $filename, string $status): bool {
        if (!$this->config->archive_scan_enabled()) {
            return false;
        }
        if ($status !== scan_status::CLEAN && $status !== scan_status::SUSPICIOUS) {
            return false;
        }
        if ($status === scan_status::SUSPICIOUS && $this->config->suspiciouspolicy === scan_policy::BLOCK) {
            return false;
        }
        return $this->is_container_filename($filename);
    }

    /**
     * Store a known container as pending and queue archive inspection.
     *
     * @param string $filepath Temporary path.
     * @param string $filename Filename.
     * @param string $sha256 SHA-256.
     * @param int $filesize Size.
     * @param file_lookup_result $lookup Provider lookup.
     * @param string $status Provider status.
     * @param scanner|null $scanner Scanner.
     * @return int
     */
    private function queue_known_archive(
        string $filepath,
        string $filename,
        string $sha256,
        int $filesize,
        file_lookup_result $lookup,
        string $status,
        ?scanner $scanner
    ): int {
        $record = $this->new_record($filename, $sha256, $filesize);
        $record->vtfileid = $lookup->sha256;
        $this->apply_counts($record, $lookup->lastanalysisstats);
        $record->status = scan_status::PENDING;
        $record->phase = scan_phase::COMPLETED;
        $record->timecompleted = 0;
        $record->archiveoutcome = archive_outcome::NONE;

        $copy = $this->try_store_copy($filepath, $filename);
        if (!$copy) {
            $record->status = scan_status::ERROR;
            $record->phase = scan_phase::FAILED;
            $record->errorcode = 'error_invalidfile';
            $record->timecompleted = time();
            $record->id = $this->repository->insert($record);
            $this->repository->update($record);
            return $this->apply_provider_error($scanner, $filename, 'error_invalidfile');
        }

        $record->fileid = $copy->get_id();
        $record->contenthash = $copy->get_contenthash();
        $record->pathnamehash = $copy->get_pathnamehash();
        $record->contextid = $copy->get_contextid();
        $record->component = $copy->get_component();
        $record->filearea = $copy->get_filearea();
        $record->itemid = $copy->get_itemid();
        $record->mimetype = $copy->get_mimetype();
        $record->id = $this->repository->insert($record);
        $this->repository->update($record);

        archive_scanner::from_site_config()->maybe_scan_container($record, $copy, false);
        $stored = $this->repository->get_by_id((int) $record->id) ?? $record;
        if ((string) $stored->status === scan_status::ERROR) {
            $code = trim((string) ($stored->errorcode ?? ''));
            return $this->apply_provider_error(
                $scanner,
                $filename,
                $code !== '' ? $code : 'error_archive_unsupported'
            );
        }
        $outcome = (string) ($stored->archiveoutcome ?? '');
        if ($outcome !== archive_outcome::PROCESSING && $outcome !== archive_outcome::INCOMPLETE) {
            // The name looked like an archive, but the bytes are not one.
            $stored->status = $status;
            $stored->phase = scan_phase::COMPLETED;
            $stored->timecompleted = time();
            $this->repository->update($stored);
            plugin_file_lifecycle::delete_copy_for_scan($stored);
            return $this->apply_status($scanner, $filename, $status);
        }

        $this->notice($scanner, get_string('archiveinspectionqueued', 'antivirus_verdict'));
        return scanner::SCAN_RESULT_OK;
    }

    /**
     * Filename extensions that enter archive inspection.
     *
     * @param string $filename Filename.
     * @return bool
     */
    private function is_container_filename(string $filename): bool {
        $name = \core_text::strtolower($filename);
        if (
            str_ends_with($name, '.zip') || str_ends_with($name, '.mbz')
            || str_ends_with($name, '.7z') || str_ends_with($name, '.rar')
        ) {
            return true;
        }
        return (bool) preg_match('/\.r\d{2}$/', $name);
    }

    /**
     * Persist pending and optionally queue asynchronous analysis.
     *
     * @param string $filepath Temporary path.
     * @param string $filename Filename.
     * @param string $sha256 SHA-256.
     * @param int $filesize Size.
     * @param scanner|null $scanner Scanner.
     * @return int
     */
    private function queue_unknown(
        string $filepath,
        string $filename,
        string $sha256,
        int $filesize,
        ?scanner $scanner
    ): int {
        $record = $this->new_record($filename, $sha256, $filesize);
        $record->status = scan_status::PENDING;
        $record->phase = scan_phase::QUEUED;

        if ($filesize > $this->config->maxbytes) {
            $record->status = scan_status::NOTSCANNED;
            $record->phase = scan_phase::SKIPPED;
            $record->errorcode = 'error_filetoolarge';
            $record->timecompleted = time();
            $record->id = $this->repository->insert($record);
            $this->repository->update($record);
            return $this->apply_unknown($scanner, $filename);
        }

        $copy = $this->try_store_copy($filepath, $filename);
        if ($copy) {
            $record->fileid = $copy->get_id();
            $record->contenthash = $copy->get_contenthash();
            $record->pathnamehash = $copy->get_pathnamehash();
            $record->contextid = $copy->get_contextid();
            $record->component = $copy->get_component();
            $record->filearea = $copy->get_filearea();
            $record->itemid = $copy->get_itemid();
            $record->mimetype = $copy->get_mimetype();
        }

        $record->id = $this->repository->insert($record);
        if ($copy) {
            $this->scheduler->queue_scan((int) $record->id);
        }
        return $this->apply_unknown($scanner, $filename);
    }

    /**
     * Persist a pending scan when VirusTotal is only temporarily unavailable.
     *
     * The Moodle upload is accepted. The file is not treated as clean or
     * malicious. Background processing retries after the existing delay policy.
     *
     * @param string $filepath Temporary path.
     * @param string $filename Original filename.
     * @param string $sha256 SHA-256.
     * @param int $filesize Size in bytes.
     * @param scanner|null $scanner Scanner.
     * @param provider_exception $exception Transient provider failure.
     * @return int
     */
    private function queue_transient(
        string $filepath,
        string $filename,
        string $sha256,
        int $filesize,
        ?scanner $scanner,
        provider_exception $exception
    ): int {
        $existing = $this->repository->find_active_by_sha256($sha256);
        if ($existing) {
            if ($this->is_open_container($existing)) {
                return $this->accept_open_archive($scanner);
            }
            $record = $this->new_record($filename, $sha256, $filesize);
            $record->status = scan_status::PENDING;
            $record->phase = $existing->phase;
            $record->errorcode = $exception->errorcode;
            $record->vtanalysisid = $existing->vtanalysisid;
            $record->vtfileid = $existing->vtfileid;
            $record->id = $this->repository->insert($record);
            return $this->apply_transient_pending($scanner, $exception->errorcode);
        }

        $record = $this->new_record($filename, $sha256, $filesize);
        $record->status = scan_status::PENDING;
        $record->phase = scan_phase::QUEUED;
        $record->errorcode = $exception->errorcode;

        if ($filesize > $this->config->maxbytes) {
            $record->status = scan_status::NOTSCANNED;
            $record->phase = scan_phase::SKIPPED;
            $record->errorcode = 'error_filetoolarge';
            $record->timecompleted = time();
            $record->id = $this->repository->insert($record);
            $this->repository->update($record);
            return $this->apply_unknown($scanner, $filename);
        }

        $copy = $this->try_store_copy($filepath, $filename);
        if ($copy) {
            $record->fileid = $copy->get_id();
            $record->contenthash = $copy->get_contenthash();
            $record->pathnamehash = $copy->get_pathnamehash();
            $record->contextid = $copy->get_contextid();
            $record->component = $copy->get_component();
            $record->filearea = $copy->get_filearea();
            $record->itemid = $copy->get_itemid();
            $record->mimetype = $copy->get_mimetype();
        }

        $record->id = $this->repository->insert($record);
        if ($copy) {
            $this->scheduler->queue_scan((int) $record->id);
        }
        return $this->apply_transient_pending($scanner, $exception->errorcode);
    }

    /**
     * Translate a normalised Verdict status into a Moodle scanner result.
     *
     * @param scanner|null $scanner Scanner.
     * @param string $filename Filename.
     * @param string $status Product status.
     * @return int
     */
    private function apply_status(?scanner $scanner, string $filename, string $status): int {
        if ($status === scan_status::MALICIOUS) {
            $this->notice($scanner, get_string('status_malicious', 'antivirus_verdict'));
            return scanner::SCAN_RESULT_FOUND;
        }
        if ($status === scan_status::SUSPICIOUS) {
            if ($this->config->suspiciouspolicy === scan_policy::BLOCK) {
                $this->block($scanner, $filename, 'error_suspiciousblocked');
            }
            $this->notice($scanner, get_string('status_suspicious', 'antivirus_verdict'));
            return scanner::SCAN_RESULT_OK;
        }
        if ($status === scan_status::CLEAN) {
            return scanner::SCAN_RESULT_OK;
        }
        if ($status === scan_status::PENDING || $status === scan_status::NOTSCANNED) {
            return $this->apply_unknown($scanner, $filename);
        }
        return $this->apply_provider_error($scanner, $filename, 'error_generic');
    }

    /**
     * Whether this row is a container whose member inspection is still open.
     *
     * @param \stdClass $existing Scan row.
     * @return bool
     */
    private function is_open_container(\stdClass $existing): bool {
        return (string) ($existing->archiveoutcome ?? '') === archive_outcome::PROCESSING
            && (int) ($existing->parentscanid ?? 0) === 0;
    }

    /**
     * Accept the upload while an existing container inspection is still open.
     *
     * Does not insert another processing parent and does not describe the file
     * as an unknown hash.
     *
     * @param scanner|null $scanner Scanner.
     * @return int
     */
    private function accept_open_archive(?scanner $scanner): int {
        $this->notice($scanner, get_string('archiveinspectionqueued', 'antivirus_verdict'));
        return scanner::SCAN_RESULT_OK;
    }

    /**
     * Unknown is never clean. Allow returns OK with pending/notscanned persisted.
     *
     * @param scanner|null $scanner Scanner.
     * @param string $filename Filename.
     * @return int
     */
    private function apply_unknown(?scanner $scanner, string $filename): int {
        $this->notice($scanner, get_string('error_unknownunverified', 'antivirus_verdict'));
        if ($this->config->unknownpolicy === scan_policy::BLOCK) {
            $this->block($scanner, $filename, 'error_unknownblocked');
        }
        return scanner::SCAN_RESULT_OK;
    }

    /**
     * Rate-limit and circuit-open never become clean or malicious, and never
     * refuse the Moodle upload.
     *
     * @param scanner|null $scanner Scanner.
     * @param string $errorcode Transient error code.
     * @return int
     */
    private function apply_transient_pending(?scanner $scanner, string $errorcode): int {
        $noticeid = $errorcode === 'error_ratelimit'
            ? 'error_ratelimit_queued'
            : 'error_providerunavailable_queued';
        $this->notice($scanner, get_string($noticeid, 'antivirus_verdict'));
        return scanner::SCAN_RESULT_OK;
    }

    /**
     * Provider failures never become SCAN_RESULT_OK.
     *
     * @param scanner|null $scanner Scanner.
     * @param string $filename Filename.
     * @param string $errorcode Stable error code.
     * @return int
     */
    private function apply_provider_error(?scanner $scanner, string $filename, string $errorcode): int {
        $notice = get_string_manager()->string_exists($errorcode, 'antivirus_verdict')
            ? get_string($errorcode, 'antivirus_verdict')
            : get_string('error_generic', 'antivirus_verdict');
        $this->notice($scanner, $notice);
        if ($this->config->providererrorpolicy === scan_policy::REPORT) {
            return scanner::SCAN_RESULT_ERROR;
        }
        $blockcode = get_string_manager()->string_exists($errorcode, 'antivirus_verdict')
            ? $errorcode
            : 'error_providerblocked';
        $this->block($scanner, $filename, $blockcode);
        return scanner::SCAN_RESULT_ERROR;
    }

    /**
     * Unreadable or unexpected local failures fail closed.
     *
     * @param scanner|null $scanner Scanner.
     * @param string $filename Filename.
     * @param string $errorcode Stable error code.
     * @return int
     */
    private function fail_closed(?scanner $scanner, string $filename, string $errorcode): int {
        return $this->apply_provider_error($scanner, $filename, $errorcode);
    }

    /**
     * Block the upload without claiming the file is malware.
     *
     * @param scanner|null $scanner Scanner.
     * @param string $filename Filename.
     * @param string $stringid Language string.
     */
    private function block(?scanner $scanner, string $filename, string $stringid): void {
        $this->notice($scanner, get_string($stringid, 'antivirus_verdict', (object) ['item' => $filename]));
        throw new \core\antivirus\scanner_exception(
            $stringid,
            '',
            ['item' => $filename],
            null,
            'antivirus_verdict'
        );
    }

    /**
     * Publish a manager-visible notice. Never include secrets.
     *
     * @param scanner|null $scanner Scanner.
     * @param string $notice Notice.
     */
    private function notice(?scanner $scanner, string $notice): void {
        if ($scanner) {
            $scanner->publish_notice($notice);
        }
    }

    /**
     * Persist a terminal error row for diagnostics.
     *
     * @param string $filename Filename.
     * @param string $sha256 SHA-256 when known.
     * @param string $errorcode Error code.
     * @param int $filesize Size when known.
     */
    private function persist_error(string $filename, string $sha256, string $errorcode, int $filesize = 0): void {
        $record = $this->new_record($filename, $sha256, $filesize);
        $record->status = scan_status::ERROR;
        $record->phase = scan_phase::FAILED;
        $record->errorcode = $errorcode;
        $record->timecompleted = time();
        $record->id = $this->repository->insert($record);
        $this->repository->update($record);
    }

    /**
     * Copy a completed verdict onto a new antivirus-source row.
     *
     * @param \stdClass $record Destination.
     * @param \stdClass $known Source verdict.
     */
    private function copy_verdict(\stdClass $record, \stdClass $known): void {
        $record->status = $known->status;
        $record->phase = scan_phase::COMPLETED;
        $record->enforcement = $this->synchronous_enforcement((string) $known->status);
        $record->vtanalysisid = $known->vtanalysisid;
        $record->vtfileid = $known->vtfileid;
        $outcome = (string) ($known->archiveoutcome ?? '');
        // An open malicious container is reusable as malicious. Do not copy
        // the processing outcome onto this new upload.
        $record->archiveoutcome = $outcome === archive_outcome::PROCESSING
            ? archive_outcome::NONE
            : $outcome;
        $record->malicious = $known->malicious;
        $record->suspicious = $known->suspicious;
        $record->undetected = $known->undetected;
        $record->harmless = $known->harmless;
        $record->timeout = $known->timeout;
        $record->totalengines = $known->totalengines;
        $record->timecompleted = time();
    }

    /**
     * Enforcement outcome for a verdict the gate reached before the upload landed.
     *
     * A malicious verdict here becomes SCAN_RESULT_FOUND, and Moodle core
     * quarantines, notifies, and refuses the upload. Recording that keeps the
     * audit trail complete and stops asynchronous enforcement, which only acts
     * on the empty state, from ever revisiting a blocked upload.
     *
     * @param string $status Product status.
     * @return string
     */
    private function synchronous_enforcement(string $status): string {
        return $status === scan_status::MALICIOUS
            ? enforcement_state::BLOCKED
            : enforcement_state::NONE;
    }

    /**
     * Apply normalised engine counts.
     *
     * @param \stdClass $record Scan row.
     * @param array|null $stats Provider stats.
     */
    private function apply_counts(\stdClass $record, ?array $stats): void {
        $counts = $this->normaliser->persistable_counts($stats);
        $record->malicious = $counts['malicious'];
        $record->suspicious = $counts['suspicious'];
        $record->undetected = $counts['undetected'];
        $record->harmless = $counts['harmless'];
        $record->timeout = $counts['timeout'];
        $record->totalengines = $counts['totalengines'];
    }

    /**
     * Initialise an antivirus-source row. File identity is optional.
     *
     * @param string $filename Filename.
     * @param string $sha256 SHA-256.
     * @param int $filesize Size.
     * @return \stdClass
     */
    private function new_record(string $filename, string $sha256, int $filesize): \stdClass {
        global $USER;

        $now = time();
        $record = new \stdClass();
        $record->fileid = 0;
        $record->contenthash = '';
        $record->pathnamehash = '';
        $record->contextid = \context_system::instance()->id;
        $record->courseid = 0;
        $record->component = 'antivirus_verdict';
        $record->filearea = plugin_file_lifecycle::GATE_FILEAREA;
        $record->itemid = 0;
        $record->filepath = '/';
        $record->filename = $filename;
        $record->userid = (!empty($USER->id) && \core_user::is_real_user($USER->id)) ? (int) $USER->id : 0;
        $record->source = scan_source::ANTIVIRUS;
        $record->sha256 = $sha256;
        $record->filesize = $filesize;
        $record->mimetype = null;
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
     * Copy the temp file into the plugin gate area when possible.
     *
     * @param string $filepath Temporary path.
     * @param string $filename Filename.
     * @return \stored_file|null
     */
    private function try_store_copy(string $filepath, string $filename): ?\stored_file {
        try {
            return plugin_file_lifecycle::store_path_copy(
                $filepath,
                $filename,
                \context_system::instance(),
                $this->current_userid()
            );
        } catch (\Throwable $e) {
            debugging('antivirus_verdict could not persist a gate copy', \DEBUG_DEVELOPER);
            return null;
        }
    }

    /**
     * Current real user id, or 0.
     *
     * @return int
     */
    private function current_userid(): int {
        global $USER;
        return (!empty($USER->id) && \core_user::is_real_user($USER->id)) ? (int) $USER->id : 0;
    }

    /**
     * Safe display filename. Never a path.
     *
     * @param string $filename Candidate name.
     * @return string
     */
    private function safe_filename(string $filename): string {
        $filename = trim(str_replace(["\0", '\\'], '', $filename));
        $filename = basename(str_replace('/', '', $filename));
        return ($filename === '' || $filename === '.' || $filename === '..') ? 'file' : $filename;
    }
}
