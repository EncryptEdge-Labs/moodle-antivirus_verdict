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
 * Administrator bulk and retrospective scanning.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

use antivirus_verdict\archive_outcome;
use antivirus_verdict\scan_source;
use antivirus_verdict\scan_status;
use antivirus_verdict\task\process_bulk_scan_batch;
use core\task\manager;


/**
 * Queues batched course file sweeps through adhoc tasks.
 */
class bulk_scan_service {
    /** Files processed per adhoc batch. */
    public const BATCH_SIZE = 40;

    /** @var scan_service Scan engine. */
    private scan_service $scanservice;

    /** @var scan_repository Persistence. */
    private scan_repository $repository;

    /** @var plugin_config Operational settings. */
    private plugin_config $config;

    /**
     * Create a bulk scan service.
     *
     * @param scan_service $scanservice Scan engine.
     * @param scan_repository $repository Persistence.
     * @param plugin_config $config Operational settings.
     */
    public function __construct(scan_service $scanservice, scan_repository $repository, plugin_config $config) {
        $this->scanservice = $scanservice;
        $this->repository = $repository;
        $this->config = $config;
    }

    /**
     * Production service using site configuration.
     *
     * @return self
     */
    public static function from_site_config(): self {
        return new self(
            scan_service::from_site_config(),
            new scan_repository(),
            plugin_config::from_site_config()
        );
    }

    /**
     * Whether bulk scanning can be started.
     *
     * @return bool
     */
    public function can_start(): bool {
        return $this->config->backfill_operational();
    }

    /**
     * Queue a course-wide retrospective sweep.
     *
     * @param int $courseid Target course.
     * @param int $userid Requesting administrator.
     * @param bool $onlymissing Skip files with a completed scan row.
     * @return bool True when a worker was queued.
     */
    public function queue_course_sweep(
        int $courseid,
        int $userid,
        bool $onlymissing = true,
        string $source = scan_source::BULK
    ): bool {
        if (!$this->can_start() || $courseid <= 0) {
            return false;
        }
        if (!scan_source::is_valid($source)) {
            $source = scan_source::BULK;
        }

        $task = new process_bulk_scan_batch();
        $task->set_custom_data((object) [
            'courseid' => $courseid,
            'userid' => max(0, $userid),
            'afterfileid' => 0,
            'onlymissing' => $onlymissing,
            'source' => $source,
        ]);
        $task->set_userid(max(0, $userid));
        manager::queue_adhoc_task($task, true);
        return true;
    }

    /**
     * Process one batch inside an adhoc task.
     *
     * @param int $courseid Course id.
     * @param int $userid Bulk operator (stored in initiatedby when distinct from file owner).
     * @param int $afterfileid Cursor.
     * @param bool $onlymissing Skip already scanned files.
     * @param string $source Scan source label.
     * @return int Next cursor (0 when finished).
     */
    public function process_batch(
        int $courseid,
        int $userid,
        int $afterfileid,
        bool $onlymissing,
        string $source
    ): int {
        $iterator = new course_file_iterator($courseid);
        $ids = $iterator->next_file_ids($afterfileid, self::BATCH_SIZE);
        if ($ids === []) {
            return 0;
        }

        $fs = get_file_storage();
        $scanner = new file_area_scanner($this->scanservice, $this->config);
        $lastid = $afterfileid;

        foreach ($ids as $fileid) {
            $lastid = $fileid;
            $file = $fs->get_file_by_id($fileid);
            if (!$file) {
                continue;
            }
            if ($onlymissing && $this->has_completed_scan($file)) {
                continue;
            }
            $fileowner = max(0, (int) $file->get_userid());
            $scanner->queue_file($file, $source, $fileowner, $userid);
        }

        if (count($ids) < self::BATCH_SIZE) {
            return 0;
        }
        return $lastid;
    }

    /**
     * Whether a stored file already has a completed scan row.
     *
     * @param \stored_file $file Moodle file.
     * @return bool
     */
    private function has_completed_scan(\stored_file $file): bool {
        $active = $this->repository->find_active_by_pathnamehash($file->get_pathnamehash());
        if ($active) {
            // An open clean or suspicious container is not a finished scan.
            // create_or_reuse still attaches to that row, so bulk does not
            // insert a second container.
            $openarchive = (string) ($active->archiveoutcome ?? '') === archive_outcome::PROCESSING
                && (string) $active->status !== scan_status::MALICIOUS;
            if (!$openarchive) {
                return true;
            }
        }
        try {
            $sha = (new file_hasher())->hash_stored_file($file);
        } catch (\Throwable $e) {
            return false;
        }
        if ($sha === '') {
            return false;
        }
        return $this->repository->find_completed_verdict_by_sha256($sha) !== null;
    }
}
