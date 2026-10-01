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
 * Local ceilings for provider operations.
 *
 * A ceiling of 0 means this site has not set a limit. These counters are
 * reserved slots, not the historical totals in operation_counts, and they
 * are not a VirusTotal quota.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

/**
 * Atomic reservation of one lookup, upload, or poll slot.
 */
class operation_reservation {
    /** @var string[] Reservation columns. */
    private const FIELDS = [
        'lookups',
        'uploads',
        'polls',
    ];

    /**
     * Insert the single reservation row when install or upgrade has not done so.
     */
    public static function install_row(): void {
        global $DB;
        if ($DB->record_exists('antivirus_verdict_opreserve', [])) {
            return;
        }
        $DB->insert_record('antivirus_verdict_opreserve', (object) [
            'lookups' => 0,
            'uploads' => 0,
            'polls' => 0,
        ]);
    }

    /**
     * Current reserved slots. Missing storage reads as zero.
     *
     * @return \stdClass
     */
    public function totals(): \stdClass {
        global $DB;
        $empty = (object) [
            'lookups' => 0,
            'uploads' => 0,
            'polls' => 0,
        ];
        try {
            $row = $DB->get_record_sql(
                'SELECT * FROM {antivirus_verdict_opreserve} ORDER BY id ASC',
                null,
                \IGNORE_MULTIPLE
            );
        } catch (\Throwable $e) {
            debugging('antivirus_verdict operation reservation could not be read', \DEBUG_DEVELOPER);
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
     * Reserve one hash lookup, or allow it when the ceiling is disabled.
     *
     * @param int $ceiling Local ceiling. 0 means no limit.
     * @return reservation_result
     */
    public function reserve_lookup(int $ceiling): reservation_result {
        return $this->reserve('lookups', $ceiling);
    }

    /**
     * Reserve one file upload, or allow it when the ceiling is disabled.
     *
     * @param int $ceiling Local ceiling. 0 means no limit.
     * @return reservation_result
     */
    public function reserve_upload(int $ceiling): reservation_result {
        return $this->reserve('uploads', $ceiling);
    }

    /**
     * Reserve one analysis poll, or allow it when the ceiling is disabled.
     *
     * @param int $ceiling Local ceiling. 0 means no limit.
     * @return reservation_result
     */
    public function reserve_poll(int $ceiling): reservation_result {
        return $this->reserve('polls', $ceiling);
    }

    /**
     * Claim one slot when the stored count is still below the ceiling.
     *
     * The increment and the ceiling test are one UPDATE statement. A ceiling
     * of 0 does not write a reservation.
     *
     * @param string $field Whitelisted column.
     * @param int $ceiling Local ceiling.
     * @return reservation_result
     */
    private function reserve(string $field, int $ceiling): reservation_result {
        if (!in_array($field, self::FIELDS, true)) {
            return new reservation_result(reservation_result::FAILED);
        }
        $ceiling = plugin_config::normalise_ceiling($ceiling);
        if ($ceiling === 0) {
            return new reservation_result(reservation_result::ALLOWED);
        }
        try {
            $claimed = $this->claim($field, $ceiling);
        } catch (\Throwable $e) {
            debugging('antivirus_verdict operation reservation failed', \DEBUG_DEVELOPER);
            return new reservation_result(reservation_result::FAILED);
        }
        if ($claimed === 1) {
            return new reservation_result(reservation_result::ALLOWED);
        }
        if ($claimed === 0) {
            return new reservation_result(reservation_result::DENIED);
        }
        return new reservation_result(reservation_result::FAILED);
    }

    /**
     * Atomically increment one column when it is still below the ceiling.
     *
     * @param string $field Whitelisted column.
     * @param int $ceiling Positive ceiling.
     * @return int 1 when a slot was claimed, 0 when the ceiling blocked it.
     */
    private function claim(string $field, int $ceiling): int {
        global $DB;
        $id = $this->row_id();
        $family = $DB->get_dbfamily();
        if ($family === 'postgres') {
            return $this->claim_postgres($field, $id, $ceiling);
        }
        if ($family !== 'mysql') {
            return -1;
        }
        $DB->execute(
            "UPDATE {antivirus_verdict_opreserve}
                SET {$field} = {$field} + 1
              WHERE id = :id AND {$field} < :ceiling",
            ['id' => $id, 'ceiling' => $ceiling]
        );
        $property = new \ReflectionProperty($DB, 'mysqli');
        $property->setAccessible(true);
        $mysqli = $property->getValue($DB);
        return (int) $mysqli->affected_rows;
    }

    /**
     * Conditional increment on PostgreSQL, where Moodle frees the result
     * before execute() returns.
     *
     * @param string $field Whitelisted column.
     * @param int $id Reservation row id.
     * @param int $ceiling Positive ceiling.
     * @return int
     */
    private function claim_postgres(string $field, int $id, int $ceiling): int {
        global $DB;
        $property = new \ReflectionProperty($DB, 'pgsql');
        $property->setAccessible(true);
        $pgsql = $property->getValue($DB);
        $table = $DB->get_prefix() . 'antivirus_verdict_opreserve';
        $sql = "UPDATE {$table} SET {$field} = {$field} + 1 WHERE id = $1 AND {$field} < $2";
        $result = pg_query_params($pgsql, $sql, [$id, $ceiling]);
        if ($result === false) {
            return -1;
        }
        $affected = (int) pg_affected_rows($result);
        pg_free_result($result);
        if (defined('PHPUNIT_TEST') && PHPUNIT_TEST) {
            \testing_util::set_table_modified_by_sql('UPDATE {antivirus_verdict_opreserve} SET id = id');
        }
        return $affected;
    }

    /**
     * Id of the reservation row, creating it if upgrade has not inserted one yet.
     *
     * @return int
     */
    private function row_id(): int {
        global $DB;
        $id = $DB->get_field_sql('SELECT MIN(id) FROM {antivirus_verdict_opreserve}');
        if ($id) {
            return (int) $id;
        }
        self::install_row();
        $id = $DB->get_field_sql('SELECT MIN(id) FROM {antivirus_verdict_opreserve}');
        if (!$id) {
            throw new \dml_exception('antivirus_verdict operation reservation row is missing');
        }
        return (int) $id;
    }
}
