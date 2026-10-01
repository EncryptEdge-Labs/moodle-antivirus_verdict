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
 * Purge scan history that exceeds the configured retention period.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

use core\lock\lock_config;


/**
 * Bounded retention cleanup for antivirus_verdict_scans and plugin copies.
 */
class scan_retention_cleanup {
    /** Rows examined per batch. */
    public const BATCH_SIZE = 50;

    /** @var scan_repository Scan persistence. */
    private scan_repository $repository;

    /** @var int|null Frozen clock for tests. */
    private ?int $now;

    /**
     * Create the cleanup service.
     *
     * @param scan_repository|null $repository Repository.
     * @param int|null $now Optional unix time for tests.
     */
    public function __construct(?scan_repository $repository = null, ?int $now = null) {
        $this->repository = $repository ?? new scan_repository();
        $this->now = $now;
    }

    /**
     * Run retention cleanup until no eligible rows remain in this invocation.
     *
     * @param int|null $retentiondays Override retention days for tests.
     * @return array{purged:int,skipped:int,filefailures:int,batches:int}
     */
    public function run(?int $retentiondays = null): array {
        $retentiondays = $retentiondays ?? scan_retention::days_from_config();
        $now = $this->now ?? time();
        $cutoff = scan_retention::cutoff_timestamp($now, $retentiondays);
        if ($cutoff === null) {
            return [
                'purged' => 0,
                'skipped' => 0,
                'filefailures' => 0,
                'batches' => 0,
            ];
        }

        $stats = [
            'purged' => 0,
            'skipped' => 0,
            'filefailures' => 0,
            'batches' => 0,
        ];

        do {
            $batch = $this->repository->find_retention_candidates($cutoff, self::BATCH_SIZE);
            if ($batch === []) {
                break;
            }
            $stats['batches']++;
            foreach ($batch as $record) {
                if ($this->purge_record((int) $record->id, $now, $retentiondays, $stats)) {
                    $stats['purged']++;
                } else {
                    $stats['skipped']++;
                }
            }
        } while (count($batch) === self::BATCH_SIZE);

        return $stats;
    }

    /**
     * Purge one scan when it is still eligible under a per-scan lock.
     *
     * @param int $scanid Scan id.
     * @param int $now Current time.
     * @param int $retentiondays Retention policy.
     * @param array $stats Mutable stats for file failures.
     * @return bool True when the scan row was deleted.
     */
    private function purge_record(int $scanid, int $now, int $retentiondays, array &$stats): bool {
        if ($scanid <= 0) {
            return false;
        }

        $factory = lock_config::get_lock_factory('antivirus_verdict');
        $lock = $factory->get_lock('scan_' . $scanid, 0);
        if (!$lock) {
            return false;
        }

        try {
            $record = $this->repository->get_by_id($scanid);
            if (!$record || !scan_retention::is_eligible($record, $now, $retentiondays)) {
                return false;
            }

            try {
                plugin_file_lifecycle::delete_copy_for_scan_if_unreferenced($record, $this->repository);
            } catch (\Throwable $e) {
                $stats['filefailures']++;
                debugging(
                    'antivirus_verdict retention file cleanup failed for scan ' . $scanid,
                    \DEBUG_DEVELOPER
                );
            }

            $this->repository->delete_by_id($scanid);
            return true;
        } finally {
            $lock->release();
        }
    }
}
