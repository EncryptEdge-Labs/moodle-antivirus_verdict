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
 * Enforcer that records core interactions instead of performing them.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\tests;

use antivirus_verdict\local\malicious_enforcer;


/**
 * Captures quarantine, deletion, event, and notification calls for assertions.
 *
 * Only the seams that reach Moodle core are overridden. Resolution, identity
 * verification, idempotency, and outcome persistence run unmodified.
 */
class recording_enforcer extends malicious_enforcer {
    /** @var array<int,array{filename:string,content:string}> Quarantined payloads. */
    public array $quarantined = [];

    /** @var int[] Ids of files deleted from the File API. */
    public array $deleted = [];

    /** @var array<int,array{filename:string,zipfile:string}> Infected-file events. */
    public array $events = [];

    /** @var string[] Administrator notices. */
    public array $notifications = [];

    /** @var bool Whether Moodle's antivirus quarantine is treated as enabled. */
    public bool $quarantineenabled = true;

    /** @var \Throwable|null Error raised by quarantine. */
    public ?\Throwable $quarantinethrows = null;

    /** @var \Throwable|null Error raised by the audit event. */
    public ?\Throwable $eventthrows = null;

    /** @var \Throwable|null Error raised by administrator notification. */
    public ?\Throwable $notifythrows = null;

    /**
     * Whether quarantine is available.
     *
     * @return bool
     */
    protected function quarantine_enabled(): bool {
        return $this->quarantineenabled;
    }

    /**
     * Record the exact bytes that would have been quarantined.
     *
     * @param string $path Readable filesystem path.
     * @param string $filename Original filename.
     * @param string $incident Incident details.
     * @param string $notice Administrator-facing notice.
     * @return string|null
     */
    protected function quarantine_content(
        string $path,
        string $filename,
        string $incident,
        string $notice
    ): ?string {
        if ($this->quarantinethrows) {
            throw $this->quarantinethrows;
        }
        $this->quarantined[] = [
            'filename' => $filename,
            'content' => (string) file_get_contents($path),
        ];
        return 'phpunit_infected_file.zip';
    }

    /**
     * Record and perform the deletion so tests can assert the file is gone.
     *
     * @param \stored_file $file Verified target file.
     */
    protected function delete_file(\stored_file $file): void {
        $this->deleted[] = (int) $file->get_id();
        parent::delete_file($file);
    }

    /**
     * Record the audit event instead of writing to the log store.
     *
     * @param \stdClass $record Scan record.
     * @param string $zipfile Quarantine archive name or placeholder.
     * @param string $incident Incident details.
     */
    protected function trigger_detected_event(\stdClass $record, string $zipfile, string $incident): void {
        if ($this->eventthrows) {
            throw $this->eventthrows;
        }
        $this->events[] = [
            'filename' => (string) $record->filename,
            'zipfile' => $zipfile,
        ];
    }

    /**
     * Record the administrator notice instead of sending messages.
     *
     * @param string $incident Incident details.
     * @param string $notice Administrator-facing notice.
     */
    protected function notify_admins(string $incident, string $notice): void {
        if ($this->notifythrows) {
            throw $this->notifythrows;
        }
        $this->notifications[] = $notice;
    }
}
