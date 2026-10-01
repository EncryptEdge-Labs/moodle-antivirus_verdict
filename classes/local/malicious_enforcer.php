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
 * Post-upload enforcement for asynchronously discovered malicious verdicts.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

use antivirus_verdict\enforcement_state;
use antivirus_verdict\scan_status;
use antivirus_verdict\scanner;
use core\antivirus\manager;
use core\antivirus\quarantine;


/**
 * Applies a security response when VirusTotal resolves malicious after upload.
 *
 * The synchronous upload gate already returns SCAN_RESULT_FOUND for a known
 * malicious hash, and Moodle core quarantines, notifies, and blocks that
 * upload itself. This class covers the other case: the file was accepted
 * because no verdict existed yet, and the verdict arrived later in the
 * process_scan adhoc task.
 *
 * Moodle core mechanisms are reused rather than reimplemented:
 *   - {@see quarantine::quarantine_file()} captures the content for the
 *     Site administration / Reports / Infected files report.
 *   - {@see \core\event\virus_infected_file_detected} is the audit record.
 *   - {@see manager::send_antivirus_messages()} delivers administrator
 *     notifications through the normal antivirus message channel.
 *
 * This class does not scan, does not call VirusTotal, and does not decide
 * verdicts. It is invoked by {@see scan_service} after a verdict is persisted,
 * while the caller still holds the per-scan lock.
 */
class malicious_enforcer {
    /** Resolution result: the scanned file could not be found. */
    private const TARGET_MISSING = 'missing';

    /** Resolution result: a file exists but is not the scanned content. */
    private const TARGET_MISMATCH = 'mismatch';

    /** Resolution result: a permanent Moodle file owned by another component. */
    private const TARGET_PERMANENT = 'permanent';

    /** Resolution result: a plugin-owned temporary copy. */
    private const TARGET_COPY = 'copy';

    /** @var scan_repository Persistence. */
    private scan_repository $repository;

    /** @var plugin_config Operational settings. */
    private plugin_config $config;

    /** @var file_hasher SHA-256 calculator used for identity verification. */
    private file_hasher $hasher;

    /** @var scanner|null Core scanner adapter used for incident text and messages. */
    private ?scanner $scanner;

    /**
     * Create an enforcer.
     *
     * @param scan_repository $repository Persistence.
     * @param plugin_config $config Operational settings.
     * @param file_hasher|null $hasher SHA-256 calculator.
     * @param scanner|null $scanner Core scanner adapter.
     */
    public function __construct(
        scan_repository $repository,
        plugin_config $config,
        ?file_hasher $hasher = null,
        ?scanner $scanner = null
    ) {
        $this->repository = $repository;
        $this->config = $config;
        $this->hasher = $hasher ?? new file_hasher();
        $this->scanner = $scanner;
    }

    /**
     * Production enforcer using site configuration.
     *
     * @return self
     */
    public static function from_site_config(): self {
        return new self(new scan_repository(), plugin_config::from_site_config());
    }

    /**
     * Enforce a malicious verdict once, and record what happened.
     *
     * Safe to call repeatedly. Non-malicious scans and scans that already
     * carry an outcome are left alone. The caller is expected to hold the
     * per-scan lock, so no second locking system is introduced here.
     *
     * @param \stdClass $record Persisted scan record with a stored verdict.
     * @return string The recorded {@see enforcement_state} value.
     */
    public function enforce(\stdClass $record): string {
        if ((string) $record->status !== scan_status::MALICIOUS) {
            return (string) ($record->enforcement ?? enforcement_state::NONE);
        }

        // Re-read under the caller's lock so a stale in-memory row cannot
        // cause a second enforcement of the same scan.
        $fresh = $this->repository->get_by_id((int) $record->id);
        $current = (string) (($fresh ?? $record)->enforcement ?? enforcement_state::NONE);
        if (!enforcement_state::requires_enforcement($current)) {
            $record->enforcement = $current;
            return $current;
        }

        $this->store($record, enforcement_state::PENDING);

        $notice = $this->build_notice($record);
        $incident = '';
        $zipfile = '';
        $outcome = enforcement_state::FAILED;

        try {
            [$file, $kind] = $this->resolve_target($record);
            $permanents = $this->collect_verified_permanents($record, $file, $kind);
            $hascontent = $file !== null || !empty($permanents);
            if (!$hascontent && $kind === self::TARGET_MISMATCH) {
                $outcome = enforcement_state::MISMATCH;
            } else if (!$hascontent) {
                $outcome = enforcement_state::FILEMISSING;
            } else if ($this->config->asyncenforcement === scan_policy::REPORT) {
                $outcome = enforcement_state::REPORTED;
            } else if (!$this->quarantine_enabled()) {
                $outcome = enforcement_state::QUARANTINEOFF;
            } else {
                $source = $file ?? $permanents[0];
                [$outcome, $zipfile, $incident] = $this->quarantine_and_remove(
                    $record,
                    $source,
                    $permanents,
                    $notice
                );
            }
        } catch (\Throwable $e) {
            $outcome = enforcement_state::FAILED;
            debugging(
                'antivirus_verdict malicious enforcement failed for scan ' . (int) $record->id,
                \DEBUG_DEVELOPER
            );
        }

        $this->store($record, $outcome);

        // The audit record and the notification must never be able to turn a
        // completed security action into a failure, so they run afterwards and
        // cannot change the stored outcome.
        $this->announce($record, $outcome, $zipfile, $notice, $incident);

        return $outcome;
    }

    /**
     * Capture the malicious content, then remove verified permanent files.
     *
     * A Moodle file is only deleted once its content has been captured, so
     * enforcement can never destroy the only copy of the data. Plugin-owned
     * copies are never treated as the live file to remove: they are a scan
     * artefact, not the object Moodle is serving.
     *
     * @param \stdClass $record Scan record.
     * @param \stored_file $source Verified file to read content from.
     * @param \stored_file[] $permanents Verified live Moodle files to remove.
     * @param string $notice Administrator-facing notice.
     * @return array{0:string,1:string,2:string} Outcome, quarantine zip name, incident details.
     */
    private function quarantine_and_remove(
        \stdClass $record,
        \stored_file $source,
        array $permanents,
        string $notice
    ): array {
        $path = $this->copy_to_temporary_path($source);
        $incident = $this->build_incident_details($path, (string) $record->filename, $notice);
        $zipfile = (string) $this->quarantine_content($path, (string) $record->filename, $incident, $notice);
        if ($zipfile === '') {
            return [enforcement_state::QUARANTINEOFF, '', $incident];
        }
        if (empty($permanents)) {
            return [enforcement_state::QUARANTINEDCOPY, $zipfile, $incident];
        }
        foreach ($permanents as $permanent) {
            $this->delete_file($permanent);
        }
        return [enforcement_state::QUARANTINED, $zipfile, $incident];
    }

    /**
     * Resolve and verify the Moodle file that this scan actually examined.
     *
     * Resolution never uses the recorded filename or filepath as a key. The
     * scan record's own file identity is used, and the result must still hash
     * to the SHA-256 that was scanned. Anything else fails closed so that an
     * unrelated file can never be quarantined or deleted.
     *
     * @param \stdClass $record Scan record.
     * @return array{0:\stored_file|null,1:string} File and resolution kind.
     */
    private function resolve_target(\stdClass $record): array {
        $fs = get_file_storage();
        $file = null;

        if ((int) ($record->fileid ?? 0) > 0) {
            $candidate = $fs->get_file_by_id((int) $record->fileid);
            if ($candidate && !$candidate->is_directory()) {
                $file = $candidate;
            }
        }
        if (!$file && trim((string) ($record->pathnamehash ?? '')) !== '') {
            $candidate = $fs->get_file_by_hash((string) $record->pathnamehash);
            if ($candidate && !$candidate->is_directory()) {
                $file = $candidate;
            }
        }
        if (!$file) {
            return [null, self::TARGET_MISSING];
        }
        if (!$this->identity_matches($record, $file)) {
            return [null, self::TARGET_MISMATCH];
        }

        return [$file, $this->is_plugin_copy_record($record) ? self::TARGET_COPY : self::TARGET_PERMANENT];
    }

    /**
     * Live Moodle files that still contain the scanned bytes.
     *
     * Native antivirus scans happen before Moodle stores the upload, so the
     * scan record often points at a plugin-owned copy rather than at the file
     * Moodle later served. Those live files are found by Moodle contenthash
     * and then re-hashed with SHA-256. A file that fails either check is
     * never returned, so a replacement at the same location cannot be removed.
     *
     * @param \stdClass $record Scan record.
     * @param \stored_file|null $resolved File resolved from the scan record.
     * @param string $kind Resolution kind.
     * @return \stored_file[]
     */
    private function collect_verified_permanents(\stdClass $record, ?\stored_file $resolved, string $kind): array {
        $permanents = [];
        if ($kind === self::TARGET_PERMANENT && $resolved) {
            $permanents[(int) $resolved->get_id()] = $resolved;
        }
        foreach ($this->find_content_siblings($record) as $sibling) {
            $permanents[(int) $sibling->get_id()] = $sibling;
        }
        return array_values($permanents);
    }

    /**
     * Other stored files that still hash to the scanned content.
     *
     * @param \stdClass $record Scan record.
     * @return \stored_file[]
     */
    private function find_content_siblings(\stdClass $record): array {
        global $DB;

        $contenthash = trim((string) ($record->contenthash ?? ''));
        if ($contenthash === '' || !preg_match('/^[a-f0-9]{40}$/', strtolower($contenthash))) {
            return [];
        }

        $ids = $DB->get_fieldset_select(
            'files',
            'id',
            'contenthash = :contenthash AND filename <> :dot',
            [
                'contenthash' => $contenthash,
                'dot' => '.',
            ]
        );
        if (empty($ids)) {
            return [];
        }

        $fs = get_file_storage();
        $found = [];
        foreach ($ids as $id) {
            $candidate = $fs->get_file_by_id((int) $id);
            if (!$candidate || $candidate->is_directory()) {
                continue;
            }
            if (plugin_file_lifecycle::is_plugin_copy($candidate)) {
                continue;
            }
            if (!$this->content_matches($record, $candidate)) {
                continue;
            }
            $found[] = $candidate;
        }
        return $found;
    }

    /**
     * Whether the stored file is still the object that was scanned.
     *
     * The File API location must match what was recorded, and the content must
     * still hash to the scanned SHA-256. The content check is authoritative: a
     * file that was replaced at the same location fails it.
     *
     * @param \stdClass $record Scan record.
     * @param \stored_file $file Candidate file.
     * @return bool
     */
    private function identity_matches(\stdClass $record, \stored_file $file): bool {
        if ((string) $file->get_component() !== (string) $record->component) {
            return false;
        }
        if ((string) $file->get_filearea() !== (string) $record->filearea) {
            return false;
        }
        if ((int) $file->get_contextid() !== (int) $record->contextid) {
            return false;
        }
        if ((int) $file->get_itemid() !== (int) $record->itemid) {
            return false;
        }
        return $this->content_matches($record, $file);
    }

    /**
     * Whether the candidate still contains the bytes that were scanned.
     *
     * Moodle's contenthash is a first filter only. The scanned SHA-256 is the
     * identity Verdict will act on.
     *
     * @param \stdClass $record Scan record.
     * @param \stored_file $file Candidate file.
     * @return bool
     */
    private function content_matches(\stdClass $record, \stored_file $file): bool {
        $contenthash = trim((string) ($record->contenthash ?? ''));
        if ($contenthash !== '' && !hash_equals($contenthash, (string) $file->get_contenthash())) {
            return false;
        }

        $sha256 = strtolower(trim((string) ($record->sha256 ?? '')));
        if (!preg_match('/^[a-f0-9]{64}$/', $sha256)) {
            return false;
        }
        return hash_equals($sha256, strtolower($this->hasher->hash_stored_file($file)));
    }

    /**
     * Whether the scan record points at one of this plugin's own copies.
     *
     * @param \stdClass $record Scan record.
     * @return bool
     */
    private function is_plugin_copy_record(\stdClass $record): bool {
        if ((string) $record->component !== plugin_file_lifecycle::COMPONENT) {
            return false;
        }
        return in_array((string) $record->filearea, plugin_file_lifecycle::copy_fileareas(), true);
    }

    /**
     * Persist an enforcement outcome without rewriting the whole scan row.
     *
     * @param \stdClass $record Scan record, updated in place.
     * @param string $state Enforcement outcome.
     */
    private function store(\stdClass $record, string $state): void {
        $record->enforcement = $state;
        $this->repository->set_enforcement((int) $record->id, $state);
    }

    /**
     * Emit the core audit event and notify administrators exactly once.
     *
     * Failures here are logged for developers and never change the stored
     * enforcement outcome, because the security action has already happened.
     *
     * @param \stdClass $record Scan record.
     * @param string $outcome Recorded enforcement outcome.
     * @param string $zipfile Quarantine archive name, when one was created.
     * @param string $notice Administrator-facing notice.
     * @param string $incident Incident details, when already built.
     */
    private function announce(
        \stdClass $record,
        string $outcome,
        string $zipfile,
        string $notice,
        string $incident
    ): void {
        if ($incident === '') {
            $incident = $this->build_incident_details('', (string) $record->filename, $notice);
        }
        if ($zipfile === '') {
            $zipfile = get_string('enforce_nozipfile', 'antivirus_verdict');
        }

        try {
            $this->trigger_detected_event($record, $zipfile, $incident);
        } catch (\Throwable $e) {
            debugging(
                'antivirus_verdict could not log the infected-file event for scan ' . (int) $record->id,
                \DEBUG_DEVELOPER
            );
        }

        try {
            $this->notify_admins($incident, $notice);
        } catch (\Throwable $e) {
            debugging(
                'antivirus_verdict could not notify administrators for scan ' . (int) $record->id,
                \DEBUG_DEVELOPER
            );
        }
    }

    /**
     * Administrator-facing summary. Never contains credentials or provider headers.
     *
     * @param \stdClass $record Scan record.
     * @return string
     */
    private function build_notice(\stdClass $record): string {
        $detection = scan_presenter::detection_label($record);
        return get_string('enforce_notice', 'antivirus_verdict', (object) [
            'filename' => (string) $record->filename,
            'sha256' => strtolower(trim((string) $record->sha256)),
            'detection' => $detection !== '' ? $detection : get_string('valueempty', 'antivirus_verdict'),
            'detected' => userdate((int) $record->timecompleted ?: time()),
            'scanid' => (int) $record->id,
        ]);
    }

    /**
     * Core incident details markup, with a plain fallback.
     *
     * @param string $path Readable filesystem path, or empty when unavailable.
     * @param string $filename Original filename.
     * @param string $notice Administrator-facing notice.
     * @return string
     */
    private function build_incident_details(string $path, string $filename, string $notice): string {
        try {
            return $this->scanner()->get_incident_details($path, $filename, $notice, true);
        } catch (\Throwable $e) {
            return $notice;
        }
    }

    /**
     * Copy stored content to a request-scoped path for quarantine and hashing.
     *
     * @param \stored_file $file Target file.
     * @return string Filesystem path.
     */
    private function copy_to_temporary_path(\stored_file $file): string {
        $path = make_request_directory() . DIRECTORY_SEPARATOR . 'verdict_enforce_' . $file->get_id();
        $file->copy_content_to($path);
        return $path;
    }

    /**
     * Whether Moodle's antivirus quarantine is available.
     *
     * Overridable so tests do not depend on site configuration.
     *
     * @return bool
     */
    protected function quarantine_enabled(): bool {
        return quarantine::is_quarantine_enabled();
    }

    /**
     * Capture the malicious content in Moodle's antivirus quarantine.
     *
     * @param string $path Readable filesystem path.
     * @param string $filename Original filename.
     * @param string $incident Incident details.
     * @param string $notice Administrator-facing notice.
     * @return string|null Quarantine archive name, or null when not stored.
     */
    protected function quarantine_content(
        string $path,
        string $filename,
        string $incident,
        string $notice
    ): ?string {
        return quarantine::quarantine_file($path, $filename, $incident, $notice);
    }

    /**
     * Remove the verified malicious Moodle file.
     *
     * @param \stored_file $file Verified target file.
     */
    protected function delete_file(\stored_file $file): void {
        $file->delete();
    }

    /**
     * Log the core infected-file event as the audit record.
     *
     * @param \stdClass $record Scan record.
     * @param string $zipfile Quarantine archive name or placeholder.
     * @param string $incident Incident details.
     */
    protected function trigger_detected_event(\stdClass $record, string $zipfile, string $incident): void {
        $params = [
            'context' => \context_system::instance(),
            'other' => [
                'filename' => (string) $record->filename,
                'zipfile' => $zipfile,
                'incidentdetails' => $incident,
            ],
        ];
        if ((int) $record->userid > 0) {
            $params['relateduserid'] = (int) $record->userid;
        }
        \core\event\virus_infected_file_detected::create($params)->trigger();
    }

    /**
     * Send administrator notifications through the core antivirus channel.
     *
     * @param string $incident Incident details.
     * @param string $notice Administrator-facing notice.
     */
    protected function notify_admins(string $incident, string $notice): void {
        // A fresh scanner per notification. core\antivirus\scanner queues
        // messages on the instance, so a reused one would resend earlier
        // incidents alongside this one.
        $scanner = new scanner();
        $scanner->publish_notice($notice);
        manager::send_antivirus_messages($scanner, $incident);
    }

    /**
     * Core scanner adapter used to build incident text.
     *
     * @return scanner
     */
    private function scanner(): scanner {
        return $this->scanner ?? new scanner();
    }
}
