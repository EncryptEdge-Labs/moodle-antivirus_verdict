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
 * Site-wide totals for provider operations and avoided provider work.
 *
 * These are local operational counts. They are not a provider quota.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

/**
 * Durable installation totals in antivirus_verdict_opcounts.
 *
 * Each record method adds one with a single SQL increment. A failure is
 * logged and swallowed so accounting cannot change a verdict.
 */
class operation_counts {
    /** @var string[] Columns that may be incremented. */
    private const FIELDS = [
        'hashlookups',
        'uploads',
        'polls',
        'completedreuses',
        'inflightjoins',
    ];

    /**
     * Insert the single totals row when install or upgrade has not done so.
     */
    public static function install_row(): void {
        global $DB;
        if ($DB->record_exists('antivirus_verdict_opcounts', [])) {
            return;
        }
        $DB->insert_record('antivirus_verdict_opcounts', (object) [
            'hashlookups' => 0,
            'uploads' => 0,
            'polls' => 0,
            'completedreuses' => 0,
            'inflightjoins' => 0,
        ]);
    }

    /**
     * Current site totals. Missing storage reads as zero.
     *
     * @return \stdClass
     */
    public function totals(): \stdClass {
        global $DB;
        $empty = (object) [
            'hashlookups' => 0,
            'uploads' => 0,
            'polls' => 0,
            'completedreuses' => 0,
            'inflightjoins' => 0,
        ];
        try {
            $row = $DB->get_record_sql('SELECT * FROM {antivirus_verdict_opcounts} ORDER BY id ASC', null, \IGNORE_MULTIPLE);
        } catch (\Throwable $e) {
            debugging('antivirus_verdict operation accounting could not be read', \DEBUG_DEVELOPER);
            return $empty;
        }
        if (!$row) {
            return $empty;
        }
        foreach (self::FIELDS as $field) {
            $empty->{$field} = (int) ($row->{$field} ?? 0);
        }
        return $empty;
    }

    /**
     * One hash lookup was sent to the provider.
     */
    public function record_hash_lookup(): void {
        $this->increment('hashlookups');
    }

    /**
     * One file upload was sent to the provider.
     */
    public function record_upload(): void {
        $this->increment('uploads');
    }

    /**
     * One analysis poll was sent to the provider.
     */
    public function record_poll(): void {
        $this->increment('polls');
    }

    /**
     * One scan reused a completed result and did not start provider work.
     */
    public function record_completed_reuse(): void {
        $this->increment('completedreuses');
    }

    /**
     * One scan joined an in-flight provider analysis.
     */
    public function record_inflight_join(): void {
        $this->increment('inflightjoins');
    }

    /**
     * Add one to a totals column without holding a transaction.
     *
     * @param string $field Whitelisted column name.
     */
    private function increment(string $field): void {
        global $DB;
        if (!in_array($field, self::FIELDS, true)) {
            return;
        }
        try {
            $id = $this->row_id();
            $DB->execute(
                "UPDATE {antivirus_verdict_opcounts} SET {$field} = {$field} + 1 WHERE id = :id",
                ['id' => $id]
            );
        } catch (\Throwable $e) {
            debugging('antivirus_verdict operation accounting failed', \DEBUG_DEVELOPER);
        }
    }

    /**
     * Id of the totals row, creating it if upgrade has not inserted one yet.
     *
     * @return int
     */
    private function row_id(): int {
        global $DB;
        $id = $DB->get_field_sql('SELECT MIN(id) FROM {antivirus_verdict_opcounts}');
        if ($id) {
            return (int) $id;
        }
        self::install_row();
        $id = $DB->get_field_sql('SELECT MIN(id) FROM {antivirus_verdict_opcounts}');
        if (!$id) {
            throw new \dml_exception('antivirus_verdict operation totals row is missing');
        }
        return (int) $id;
    }
}
