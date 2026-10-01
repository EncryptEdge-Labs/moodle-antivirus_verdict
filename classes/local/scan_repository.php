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
 * Persistence for VirusTotal scan records.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

use antivirus_verdict\archive_outcome;
use antivirus_verdict\enforcement_state;
use antivirus_verdict\scan_phase;
use antivirus_verdict\scan_source;
use antivirus_verdict\scan_status;


/**
 * DML access for antivirus_verdict_scans. Does not call VirusTotal.
 */
class scan_repository {
    /** Table name without prefix. */
    public const TABLE = 'antivirus_verdict_scans';

    /**
     * When set, overview and quarantine queries use this user's history visibility.
     *
     * Null leaves those queries unscoped, which is the site-manager and test path.
     *
     * @var int|null
     */
    private ?int $visibilityuserid = null;

    /**
     * Return a repository whose aggregate queries are limited to one viewer.
     *
     * @param int $userid Viewer user id.
     * @return self
     */
    public function limited_to_viewer(int $userid): self {
        $copy = clone $this;
        $copy->visibilityuserid = $userid;
        return $copy;
    }

    /**
     * History visibility SQL for the scoped viewer, or empty when unscoped.
     *
     * @return array{0:string,1:array}
     */
    private function viewer_visibility(): array {
        if ($this->visibilityuserid === null || scan_access::can_manage_site($this->visibilityuserid)) {
            return ['', []];
        }
        return scan_access::history_visibility_sql($this->visibilityuserid, 0);
    }

    /**
     * AND the viewer restriction onto an existing WHERE clause.
     *
     * @param string $where Existing clause, without the WHERE keyword.
     * @param array $params Named parameters for the clause.
     * @return array{0:string,1:array}
     */
    private function restrict(string $where, array $params): array {
        [$visible, $visibleparams] = $this->viewer_visibility();
        if ($visible === '') {
            return [$where, $params];
        }
        if ($where === '') {
            return [$visible, $visibleparams];
        }
        return ['(' . $where . ') AND (' . $visible . ')', $params + $visibleparams];
    }

    /**
     * Load a scan by primary key.
     *
     * @param int $id Scan id.
     * @return \stdClass|null
     */
    public function get_by_id(int $id): ?\stdClass {
        global $DB;
        if ($id <= 0) {
            return null;
        }
        $record = $DB->get_record(self::TABLE, ['id' => $id]);
        return $record ?: null;
    }

    /**
     * Member scans belonging to a container scan.
     *
     * @param int $parentid Container scan id.
     * @return \stdClass[]
     */
    public function find_children_by_parent(int $parentid): array {
        global $DB;
        if ($parentid <= 0) {
            return [];
        }
        return $DB->get_records(self::TABLE, ['parentscanid' => $parentid], 'id ASC');
    }

    /**
     * Latest in-flight scan for a Moodle file identity.
     *
     * @param string $pathnamehash Moodle pathname hash.
     * @return \stdClass|null
     */
    public function find_active_by_pathnamehash(string $pathnamehash): ?\stdClass {
        global $DB;
        [$insql, $params] = $DB->get_in_or_equal(scan_phase::active(), \SQL_PARAMS_NAMED, 'ph');
        $params['pathnamehash'] = $pathnamehash;
        $params['archiveprocessing'] = \antivirus_verdict\archive_outcome::PROCESSING;
        $record = $DB->get_record_select(
            self::TABLE,
            "pathnamehash = :pathnamehash AND (phase {$insql} OR archiveoutcome = :archiveprocessing)",
            $params,
            '*',
            \IGNORE_MULTIPLE
        );
        return $record ?: null;
    }

    /**
     * Scans for a SHA-256, newest first.
     *
     * @param string $sha256 Hex SHA-256.
     * @return \stdClass[]
     */
    public function find_by_sha256(string $sha256): array {
        global $DB;
        if ($sha256 === '') {
            return [];
        }
        return $DB->get_records(self::TABLE, ['sha256' => $sha256], 'id DESC');
    }

    /**
     * Latest completed clean, suspicious, or malicious row for a SHA-256.
     *
     * @param string $sha256 Hex SHA-256.
     * @return \stdClass|null
     */
    public function find_completed_verdict_by_sha256(string $sha256): ?\stdClass {
        global $DB;
        if ($sha256 === '') {
            return null;
        }
        [$insql, $params] = $DB->get_in_or_equal([
            scan_status::CLEAN,
            scan_status::SUSPICIOUS,
            scan_status::MALICIOUS,
        ], \SQL_PARAMS_NAMED, 'st');
        $params['sha256'] = $sha256;
        $params['phase'] = scan_phase::COMPLETED;
        $params['archiveempty'] = \antivirus_verdict\archive_outcome::NONE;
        $params['archivecomplete'] = \antivirus_verdict\archive_outcome::COMPLETE;
        $params['statusmalicious'] = scan_status::MALICIOUS;
        // Open clean/suspicious containers are not reusable. A malicious
        // provider verdict is reusable even while member inspection is open,
        // because later aggregation cannot weaken it.
        $records = $DB->get_records_select(
            self::TABLE,
            "sha256 = :sha256 AND phase = :phase AND status {$insql}
                AND (
                    archiveoutcome IS NULL
                    OR archiveoutcome = :archiveempty
                    OR archiveoutcome = :archivecomplete
                    OR status = :statusmalicious
                )",
            $params,
            'id DESC',
            '*',
            0,
            1
        );
        $record = reset($records);
        return $record ?: null;
    }

    /**
     * Latest in-flight scan for a SHA-256.
     *
     * @param string $sha256 Hex SHA-256.
     * @return \stdClass|null
     */
    public function find_active_by_sha256(string $sha256): ?\stdClass {
        global $DB;
        if ($sha256 === '') {
            return null;
        }
        [$insql, $params] = $DB->get_in_or_equal(scan_phase::active(), \SQL_PARAMS_NAMED, 'ph');
        $params['sha256'] = $sha256;
        $params['archiveprocessing'] = \antivirus_verdict\archive_outcome::PROCESSING;
        // A container whose provider step has finished is still in flight while
        // member inspection is open. phase=completed alone would miss it.
        $records = $DB->get_records_select(
            self::TABLE,
            "sha256 = :sha256 AND (phase {$insql} OR archiveoutcome = :archiveprocessing)",
            $params,
            'id DESC',
            '*',
            0,
            1
        );
        $record = reset($records);
        return $record ?: null;
    }

    /**
     * Scan that currently owns an analysis identifier.
     *
     * @param string $analysisid Provider analysis id.
     * @return \stdClass|null
     */
    public function find_by_analysis_id(string $analysisid): ?\stdClass {
        global $DB;
        if ($analysisid === '') {
            return null;
        }
        $record = $DB->get_record(self::TABLE, ['vtanalysisid' => $analysisid], '*', \IGNORE_MULTIPLE);
        return $record ?: null;
    }

    /**
     * Active scan rows waiting on one provider analysis of one SHA-256.
     *
     * Archive parents whose provider step has already finished are not active,
     * so member inspection is not selected here.
     *
     * @param string $analysisid Provider analysis id.
     * @param string $sha256 Hex SHA-256.
     * @return \stdClass[]
     */
    public function find_waiting_by_analysis(string $analysisid, string $sha256): array {
        global $DB;
        if ($analysisid === '' || $sha256 === '') {
            return [];
        }
        [$insql, $params] = $DB->get_in_or_equal(scan_phase::active(), \SQL_PARAMS_NAMED, 'ph');
        $params['analysisid'] = $analysisid;
        $params['sha256'] = $sha256;
        return $DB->get_records_select(
            self::TABLE,
            "vtanalysisid = :analysisid AND sha256 = :sha256 AND phase {$insql}",
            $params,
            'id ASC'
        );
    }

    /**
     * Insert a scan row and return its id.
     *
     * @param \stdClass $record Scan fields.
     * @return int
     */
    public function insert(\stdClass $record): int {
        global $DB;
        return (int) $DB->insert_record(self::TABLE, $record);
    }

    /**
     * Persist an existing scan row.
     *
     * @param \stdClass $record Scan fields including id.
     */
    public function update(\stdClass $record): void {
        global $DB;
        $record->timemodified = time();
        $DB->update_record(self::TABLE, $record);
    }

    /**
     * Persist only the enforcement outcome for a scan.
     *
     * Deliberately narrower than {@see update()}: enforcement runs after the
     * verdict is stored, and must not overwrite columns another worker may
     * have touched in the meantime.
     *
     * @param int $id Scan id.
     * @param string $state Enforcement outcome.
     */
    public function set_enforcement(int $id, string $state): void {
        global $DB;
        if ($id <= 0) {
            return;
        }
        $DB->update_record(self::TABLE, (object) [
            'id' => $id,
            'enforcement' => $state,
            'timemodified' => time(),
        ]);
    }

    /**
     * Count history rows the user is allowed to see.
     *
     * @param int $userid User id.
     * @param array $filters Optional status, source, filename, courseid.
     * @return int
     */
    public function count_visible_history(int $userid, array $filters = []): int {
        global $DB;
        [$where, $params] = $this->visible_history_where($userid, $filters);
        return (int) $DB->count_records_select(self::TABLE, $where, $params);
    }

    /**
     * History rows the user is allowed to see, newest first.
     *
     * @param int $userid User id.
     * @param array $filters Optional status, source, filename, courseid.
     * @param int $limit Page size.
     * @param int $offset Offset.
     * @return \stdClass[]
     */
    public function get_visible_history(int $userid, array $filters = [], int $limit = 25, int $offset = 0): array {
        global $DB;
        [$where, $params] = $this->visible_history_where($userid, $filters);
        return $DB->get_records_select(
            self::TABLE,
            $where,
            $params,
            'timecreated DESC, id DESC',
            '*',
            $offset,
            $limit
        );
    }

    /**
     * SQL used by the paginated history table.
     *
     * @param int $userid User id.
     * @param array $filters Optional status, source, filename, courseid.
     * @return array{0:string,1:array} Where clause and params.
     */
    public function visible_history_where(int $userid, array $filters = []): array {
        global $DB;

        $pagecourseid = isset($filters['courseid']) ? (int) $filters['courseid'] : 0;
        [$where, $params] = scan_access::history_visibility_sql($userid, $pagecourseid);

        if (!empty($filters['status']) && scan_status::is_valid((string) $filters['status'])) {
            $where .= ' AND status = :filterstatus';
            $params['filterstatus'] = $filters['status'];
        }
        if (!empty($filters['source']) && scan_source::is_valid((string) $filters['source'])) {
            $where .= ' AND source = :filtersource';
            $params['filtersource'] = $filters['source'];
        }
        if (!empty($filters['filename']) && is_string($filters['filename'])) {
            $where .= ' AND ' . $DB->sql_like('filename', ':filterfilename', false, false);
            $params['filterfilename'] = '%' . $DB->sql_like_escape(trim($filters['filename'])) . '%';
        }

        return [$where, $params];
    }

    /**
     * Site-wide status counts. Total is the sum of grouped status rows.
     *
     * Known statuses are counted from the stored status column. They sum to
     * total when every row uses a recognised status.
     *
     * @return array<string,int>
     */
    public function get_overview_status_counts(): array {
        global $DB;

        $counts = array_fill_keys(scan_status::all(), 0);
        [$where, $params] = $this->restrict('', []);
        $sql = 'SELECT status, COUNT(1) AS n FROM {' . self::TABLE . '}';
        if ($where !== '') {
            $sql .= ' WHERE ' . $where;
        }
        $sql .= ' GROUP BY status';
        $rows = $DB->get_records_sql($sql, $params);
        $total = 0;
        foreach ($rows as $row) {
            $n = (int) $row->n;
            $total += $n;
            $status = (string) $row->status;
            if (array_key_exists($status, $counts)) {
                $counts[$status] = $n;
            }
        }
        $counts['total'] = $total;
        return $counts;
    }

    /**
     * Count scans created at or after a Unix timestamp.
     *
     * @param int $since Unix timestamp.
     * @return int
     */
    public function count_created_since(int $since): int {
        global $DB;
        [$where, $params] = $this->restrict('timecreated >= :since', ['since' => $since]);
        return (int) $DB->count_records_select(self::TABLE, $where, $params);
    }

    /**
     * Count scans still in an active async phase.
     *
     * @return int
     */
    public function count_active_scans(): int {
        global $DB;
        [$insql, $params] = $DB->get_in_or_equal(scan_phase::active(), \SQL_PARAMS_NAMED, 'ph');
        [$where, $params] = $this->restrict("phase {$insql}", $params);
        return (int) $DB->count_records_select(self::TABLE, $where, $params);
    }

    /**
     * Count scans in one lifecycle phase.
     *
     * @param string $phase Scan phase constant.
     * @return int
     */
    public function count_by_phase(string $phase): int {
        global $DB;
        if ($phase === '') {
            return 0;
        }
        [$where, $params] = $this->restrict('phase = :phase', ['phase' => $phase]);
        return (int) $DB->count_records_select(self::TABLE, $where, $params);
    }

    /**
     * Distinct SHA-256 values among completed verdicts.
     *
     * @return int
     */
    public function count_distinct_completed_hashes(): int {
        global $DB;
        [$insql, $params] = $DB->get_in_or_equal([
            scan_status::CLEAN,
            scan_status::SUSPICIOUS,
            scan_status::MALICIOUS,
        ], \SQL_PARAMS_NAMED, 'st');
        $params['phase'] = scan_phase::COMPLETED;
        [$where, $params] = $this->restrict(
            "phase = :phase AND status {$insql} AND sha256 <> ''",
            $params
        );
        return (int) $DB->count_records_select(
            self::TABLE,
            $where,
            $params,
            'COUNT(DISTINCT sha256)'
        );
    }

    /**
     * Completed verdict rows (clean, suspicious, or malicious).
     *
     * @return int
     */
    public function count_completed_verdicts(): int {
        global $DB;
        [$insql, $params] = $DB->get_in_or_equal([
            scan_status::CLEAN,
            scan_status::SUSPICIOUS,
            scan_status::MALICIOUS,
        ], \SQL_PARAMS_NAMED, 'st');
        $params['phase'] = scan_phase::COMPLETED;
        [$where, $params] = $this->restrict("phase = :phase AND status {$insql} AND sha256 <> ''", $params);
        return (int) $DB->count_records_select(self::TABLE, $where, $params);
    }

    /**
     * Scan volume per calendar day for a trailing window.
     *
     * @param int $days Number of days including today.
     * @return array<int,int> Unix day-start => count.
     */
    public function count_created_by_day(int $days): array {
        global $DB;
        $days = max(1, $days);
        $start = usergetmidnight(time()) - (($days - 1) * DAYSECS);
        $out = [];
        for ($i = 0; $i < $days; $i++) {
            $daystart = $start + ($i * DAYSECS);
            $dayend = $daystart + DAYSECS;
            [$where, $params] = $this->restrict(
                'timecreated >= :daystart AND timecreated < :dayend',
                ['daystart' => $daystart, 'dayend' => $dayend]
            );
            $out[$daystart] = (int) $DB->count_records_select(self::TABLE, $where, $params);
        }
        return $out;
    }

    /**
     * Archive container and member aggregates.
     *
     * @return array{containers:int,members:int,uninspectable:int,maliciousmembers:int}
     */
    public function archive_depth_counts(): array {
        global $DB;
        [$memberwhere, $memberparams] = $this->restrict('parentscanid > 0', []);
        $members = (int) $DB->count_records_select(self::TABLE, $memberwhere, $memberparams);
        $containers = (int) $DB->count_records_sql(
            'SELECT COUNT(DISTINCT parentscanid) FROM {' . self::TABLE . '} WHERE ' . $memberwhere,
            $memberparams
        );
        [$insql, $params] = $DB->get_in_or_equal([
            archive_outcome::UNSUPPORTED,
            archive_outcome::EXTRACT_ERROR,
        ], \SQL_PARAMS_NAMED, 'ao');
        [$where, $params] = $this->restrict("archiveoutcome {$insql}", $params);
        $uninspectable = (int) $DB->count_records_select(self::TABLE, $where, $params);
        [$malwhere, $malparams] = $this->restrict(
            'parentscanid > 0 AND status = :status',
            ['status' => scan_status::MALICIOUS]
        );
        $maliciousmembers = (int) $DB->count_records_select(self::TABLE, $malwhere, $malparams);
        return [
            'containers' => $containers,
            'members' => $members,
            'uninspectable' => $uninspectable,
            'maliciousmembers' => $maliciousmembers,
        ];
    }

    /**
     * Error-status rows grouped by stored error code, highest count first.
     *
     * @param int $limit Maximum distinct codes.
     * @return array<int,array{errorcode:string,count:int}>
     */
    public function error_code_counts(int $limit = 5): array {
        global $DB;
        $limit = max(1, $limit);
        [$where, $params] = $this->restrict(
            "status = :status AND errorcode IS NOT NULL AND errorcode <> :empty",
            ['status' => scan_status::ERROR, 'empty' => '']
        );
        $sql = 'SELECT errorcode, COUNT(1) AS cnt
                  FROM {' . self::TABLE . '}
                 WHERE ' . $where . '
              GROUP BY errorcode
              ORDER BY cnt DESC, errorcode ASC';
        $records = $DB->get_records_sql($sql, $params, 0, $limit);
        $rows = [];
        foreach ($records as $record) {
            $rows[] = [
                'errorcode' => (string) $record->errorcode,
                'count' => (int) $record->cnt,
            ];
        }
        return $rows;
    }

    /**
     * Recent malicious-enforcement rows with an outcome other than none.
     *
     * @param int $limit Maximum rows.
     * @return \stdClass[]
     */
    public function get_enforcement_events(int $limit = 8): array {
        global $DB;
        $limit = max(1, $limit);
        [$where, $params] = $this->restrict(
            "enforcement <> :none AND enforcement <> ''",
            ['none' => enforcement_state::NONE]
        );
        return $DB->get_records_select(
            self::TABLE,
            $where,
            $params,
            'timemodified DESC, id DESC',
            '*',
            0,
            $limit
        );
    }

    /**
     * Most recent stored scan error code (stable string, never a secret).
     *
     * @return string
     */
    public function latest_error_code(): string {
        global $DB;
        [$where, $params] = $this->restrict(
            "status = :status AND errorcode IS NOT NULL AND errorcode <> ''",
            ['status' => scan_status::ERROR]
        );
        $records = $DB->get_records_select(
            self::TABLE,
            $where,
            $params,
            'timemodified DESC, id DESC',
            'id, errorcode',
            0,
            1
        );
        if ($records === []) {
            return '';
        }
        $row = reset($records);
        return (string) $row->errorcode;
    }

    /**
     * Active scans that have not been updated since the given timestamp.
     *
     * Uses the phase list and timemodified. Result size is capped so recovery
     * cannot load the whole table.
     *
     * @param int $modifiedbefore Inclusive Unix timestamp.
     * @param int $limit Maximum rows.
     * @return \stdClass[]
     */
    public function find_stale_active(int $modifiedbefore, int $limit = 50): array {
        global $DB;
        if ($limit <= 0) {
            return [];
        }
        [$insql, $params] = $DB->get_in_or_equal(scan_phase::active(), \SQL_PARAMS_NAMED, 'ph');
        $params['modifiedbefore'] = $modifiedbefore;
        return $DB->get_records_select(
            self::TABLE,
            "phase {$insql} AND timemodified <= :modifiedbefore",
            $params,
            'timemodified ASC, id ASC',
            '*',
            0,
            $limit
        );
    }

    /**
     * Container rows whose member inspection is still open and stale.
     *
     * These rows can already have phase=completed because the provider step
     * finished. They must not be sent back through process_scan.
     *
     * @param int $modifiedbefore Inclusive Unix timestamp.
     * @param int $limit Maximum rows.
     * @return \stdClass[]
     */
    public function find_stale_archives(int $modifiedbefore, int $limit = 50): array {
        global $DB;
        if ($limit <= 0) {
            return [];
        }
        return $DB->get_records_select(
            self::TABLE,
            "parentscanid = 0
                AND archiveoutcome = :archiveprocessing
                AND timemodified <= :modifiedbefore",
            [
                'archiveprocessing' => \antivirus_verdict\archive_outcome::PROCESSING,
                'modifiedbefore' => $modifiedbefore,
            ],
            'timemodified ASC, id ASC',
            '*',
            0,
            $limit
        );
    }

    /**
     * Terminal scans old enough for retention cleanup.
     *
     * Active phases, pending malicious enforcement, and recent rows are excluded
     * in SQL so the task does not load the whole table.
     *
     * @param int $cutoff Exclusive unix timestamp; rows older than this may purge.
     * @param int $limit Maximum rows.
     * @return \stdClass[]
     */
    public function find_retention_candidates(int $cutoff, int $limit = 50): array {
        global $DB;
        if ($limit <= 0 || $cutoff <= 0) {
            return [];
        }
        [$terminalinsql, $params] = $DB->get_in_or_equal([
            scan_phase::COMPLETED,
            scan_phase::FAILED,
            scan_phase::SKIPPED,
        ], \SQL_PARAMS_NAMED, 'tp');
        $params['cutoffcompleted'] = $cutoff;
        $params['cutoffmodified'] = $cutoff;
        $params['statuspending'] = scan_status::PENDING;
        $params['statusmalicious'] = scan_status::MALICIOUS;
        $params['enfnone'] = enforcement_state::NONE;
        $params['enfpending'] = enforcement_state::PENDING;
        $params['archiveprocessing'] = \antivirus_verdict\archive_outcome::PROCESSING;

        $select = "phase {$terminalinsql}
            AND status <> :statuspending
            AND (archiveoutcome IS NULL OR archiveoutcome <> :archiveprocessing)
            AND (
                (timecompleted > 0 AND timecompleted < :cutoffcompleted)
                OR (timecompleted = 0 AND timemodified > 0 AND timemodified < :cutoffmodified)
            )
            AND NOT (
                status = :statusmalicious
                AND enforcement IN (:enfnone, :enfpending)
            )";

        return $DB->get_records_select(
            self::TABLE,
            $select,
            $params,
            'id ASC',
            '*',
            0,
            $limit
        );
    }

    /**
     * Count other scan rows referencing the same Moodle file identity.
     *
     * @param int $fileid Moodle files.id.
     * @param string $pathnamehash Moodle pathname hash.
     * @param int $excludeid Scan id to ignore.
     * @return int
     */
    public function count_references_to_file(int $fileid, string $pathnamehash, int $excludeid = 0): int {
        global $DB;
        $conditions = [];
        $params = [];
        if ($fileid > 0) {
            $conditions[] = 'fileid = :fileid';
            $params['fileid'] = $fileid;
        }
        if ($pathnamehash !== '') {
            $conditions[] = 'pathnamehash = :pathnamehash';
            $params['pathnamehash'] = $pathnamehash;
        }
        if ($conditions === []) {
            return 0;
        }
        $where = '(' . implode(' OR ', $conditions) . ')';
        if ($excludeid > 0) {
            $where .= ' AND id <> :excludeid';
            $params['excludeid'] = $excludeid;
        }
        return (int) $DB->count_records_select(self::TABLE, $where, $params);
    }

    /**
     * Delete a scan row by id.
     *
     * @param int $id Scan id.
     */
    public function delete_by_id(int $id): void {
        global $DB;
        if ($id <= 0) {
            return;
        }
        $DB->delete_records(self::TABLE, ['id' => $id]);
    }

    /**
     * Remove native upload-gate preflight rows superseded by a manual scan.
     *
     * When a file is chosen in the manual scan file picker, Moodle runs the
     * antivirus gate on the draft upload first. Queueing the manual scan should
     * not leave a second user-visible history row for the same content.
     *
     * Only gate preflight rows are removed (antivirus source, gate file area).
     * Legitimate standalone antivirus scans are untouched.
     *
     * @param \stdClass $manual Manual scan row with id, sha256, filename, userid, timecreated.
     * @return int Number of rows deleted.
     */
    public function discard_gate_preflight_for_manual(\stdClass $manual): int {
        global $DB;

        $manualid = (int) ($manual->id ?? 0);
        $sha256 = (string) ($manual->sha256 ?? '');
        if ($manualid <= 0 || $sha256 === '') {
            return 0;
        }

        $filename = (string) ($manual->filename ?? '');
        $userid = (int) ($manual->userid ?? 0);
        $created = (int) ($manual->timecreated ?? time());
        $since = $created - HOURSECS;

        $select = 'source = :source AND sha256 = :sha256 AND filename = :filename AND id <> :manualid'
            . ' AND timecreated >= :since AND timecreated <= :created'
            . ' AND component = :component AND filearea = :filearea';

        $params = [
            'source' => scan_source::ANTIVIRUS,
            'sha256' => $sha256,
            'filename' => $filename,
            'manualid' => $manualid,
            'since' => $since,
            'created' => $created,
            'component' => plugin_file_lifecycle::COMPONENT,
            'filearea' => plugin_file_lifecycle::GATE_FILEAREA,
        ];

        if ($userid > 0) {
            $select .= ' AND (userid = :userid OR userid = 0)';
            $params['userid'] = $userid;
        }

        $ids = $DB->get_fieldset_select(self::TABLE, 'id', $select, $params);
        $deleted = 0;
        foreach ($ids as $id) {
            $this->delete_by_id((int) $id);
            $deleted++;
        }
        return $deleted;
    }

    /**
     * Newest scans for the administrator overview.
     *
     * @param int $limit Maximum rows.
     * @return \stdClass[]
     */
    public function get_recent_scans(int $limit = 10): array {
        global $DB;
        if ($limit <= 0) {
            return [];
        }
        [$where, $params] = $this->restrict('', []);
        if ($where === '') {
            return $DB->get_records(
                self::TABLE,
                null,
                'timecreated DESC, id DESC',
                '*',
                0,
                $limit
            );
        }
        return $DB->get_records_select(
            self::TABLE,
            $where,
            $params,
            'timecreated DESC, id DESC',
            '*',
            0,
            $limit
        );
    }

    /**
     * Malicious scans with a quarantine-related enforcement outcome.
     *
     * @param int $limit Maximum rows.
     * @return \stdClass[]
     */
    public function find_quarantine_inventory(int $limit = 50): array {
        global $DB;
        if ($limit <= 0) {
            return [];
        }
        [$insql, $params] = $this->quarantine_inventory_filter();
        [$where, $params] = $this->restrict("status = :status AND enforcement {$insql}", $params);
        return $DB->get_records_select(
            self::TABLE,
            $where,
            $params,
            'timecompleted DESC, id DESC',
            '*',
            0,
            $limit
        );
    }

    /**
     * Count of the same inventory query used by {@see find_quarantine_inventory()}.
     *
     * @return int
     */
    public function count_quarantine_inventory(): int {
        global $DB;
        [$insql, $params] = $this->quarantine_inventory_filter();
        [$where, $params] = $this->restrict("status = :status AND enforcement {$insql}", $params);
        return (int) $DB->count_records_select(self::TABLE, $where, $params);
    }

    /**
     * Shared filter for quarantine inventory list and count.
     *
     * @return array{0:string,1:array}
     */
    private function quarantine_inventory_filter(): array {
        global $DB;
        [$insql, $params] = $DB->get_in_or_equal([
            enforcement_state::QUARANTINED,
            enforcement_state::QUARANTINEDCOPY,
            enforcement_state::REPORTED,
            enforcement_state::BLOCKED,
        ], \SQL_PARAMS_NAMED, 'enf');
        $params['status'] = scan_status::MALICIOUS;
        return [$insql, $params];
    }

    /**
     * Count scans with one of the given enforcement outcomes.
     *
     * @param string[] $states Enforcement values.
     * @return int
     */
    public function count_by_enforcement(array $states): int {
        global $DB;
        if ($states === []) {
            return 0;
        }
        [$insql, $params] = $DB->get_in_or_equal($states, \SQL_PARAMS_NAMED, 'enf');
        return (int) $DB->count_records_select(self::TABLE, "enforcement {$insql}", $params);
    }

    /**
     * Count scans with a user-facing status.
     *
     * @param string $status Status constant.
     * @return int
     */
    public function count_by_status(string $status): int {
        global $DB;
        return (int) $DB->count_records(self::TABLE, ['status' => $status]);
    }

    /**
     * Gate scans that may belong to one assignment submission file.
     *
     * Matching uses Moodle contenthash, upload user, filename, and file-anchored time bounds.
     *
     * @param string $contenthash Moodle stored_file contenthash.
     * @param int $userid Learner who submitted.
     * @param string $filename Submission filename.
     * @param int $filetimecreated Authoritative submission stored_file.timecreated.
     * @param int $eventtime assessable_submitted timecreated.
     * @param int $maxagebeforefile Seconds gate may precede file timecreated.
     * @param int $gateafterfileslack Seconds gate may follow file timecreated.
     * @param int $eventafterslack Seconds gate may follow event timecreated.
     * @return \stdClass[] Newest first.
     */
    public function find_unlinked_gate_scans_for_submission_file(
        string $contenthash,
        int $userid,
        string $filename,
        int $filetimecreated,
        int $eventtime,
        int $maxagebeforefile,
        int $gateafterfileslack,
        int $eventafterslack
    ): array {
        global $DB;

        if ($userid <= 0 || $filename === '') {
            return [];
        }

        if ($filetimecreated <= 0 && $eventtime <= 0) {
            return [];
        }

        $since = 0;
        $until = PHP_INT_MAX;
        if ($filetimecreated > 0) {
            $since = max(0, $filetimecreated - max(1, $maxagebeforefile));
            $until = min($until, $filetimecreated + max(0, $gateafterfileslack));
        }
        if ($eventtime > 0) {
            $until = min($until, $eventtime + max(0, $eventafterslack));
            if ($filetimecreated <= 0) {
                $since = max($since, $eventtime - max(1, $maxagebeforefile));
            }
        }

        $select = 'source = :source AND submissionid = 0 AND userid = :userid AND filename = :filename'
            . ' AND timecreated >= :since AND timecreated <= :until'
            . ' AND component = :component AND filearea = :filearea';
        $params = [
            'source' => scan_source::ANTIVIRUS,
            'userid' => $userid,
            'filename' => $filename,
            'since' => $since,
            'until' => $until,
            'component' => plugin_file_lifecycle::COMPONENT,
            'filearea' => plugin_file_lifecycle::GATE_FILEAREA,
        ];
        if ($contenthash !== '') {
            $select .= ' AND (contenthash = :contenthash OR contenthash = :emptyhash OR contenthash IS NULL)';
            $params['contenthash'] = $contenthash;
            $params['emptyhash'] = '';
        }

        return $DB->get_records_select(
            self::TABLE,
            $select,
            $params,
            'timecreated DESC, id DESC'
        );
    }

    /**
     * Persist assignment audit fields on a gate scan without changing gate file identity.
     *
     * @param int $scanid Gate scan id.
     * @param int $contextid Module context id.
     * @param int $courseid Course id.
     * @param int $submissionid assign_submission.id.
     */
    public function apply_assignment_context_to_gate_scan(
        int $scanid,
        int $contextid,
        int $courseid,
        int $submissionid
    ): void {
        global $DB;
        if ($scanid <= 0 || $contextid <= 0 || $courseid <= 0 || $submissionid <= 0) {
            return;
        }
        $DB->update_record(self::TABLE, (object) [
            'id' => $scanid,
            'contextid' => $contextid,
            'courseid' => $courseid,
            'submissionid' => $submissionid,
            'timemodified' => time(),
        ]);
    }

    /**
     * Assignment backfill scan for the same submission file as a linked gate row.
     *
     * @param \stdClass $gate Gate scan with submissionid and contenthash.
     * @return \stdClass|null
     */
    public function find_assign_scan_for_gate_context(\stdClass $gate): ?\stdClass {
        global $DB;

        $submissionid = (int) ($gate->submissionid ?? 0);
        $contenthash = (string) ($gate->contenthash ?? '');
        $userid = (int) ($gate->userid ?? 0);
        if ($submissionid <= 0 || $contenthash === '') {
            return null;
        }

        $records = $DB->get_records_select(
            self::TABLE,
            'source = :source AND submissionid = :submissionid AND contenthash = :contenthash'
                . ' AND userid = :userid AND component = :component AND filearea = :filearea',
            [
                'source' => scan_source::ASSIGN,
                'submissionid' => $submissionid,
                'contenthash' => $contenthash,
                'userid' => $userid,
                'component' => assignment_scanner::FILE_COMPONENT,
                'filearea' => assignment_scanner::FILE_AREA,
            ],
            'id DESC',
            '*',
            0,
            1
        );
        $record = reset($records);
        return $record ?: null;
    }

    /**
     * Gate scan linked to the same assignment submission file.
     *
     * @param \stdClass $assign Assignment-source scan row.
     * @return \stdClass|null
     */
    public function find_gate_scan_for_assign_context(\stdClass $assign): ?\stdClass {
        global $DB;

        $submissionid = (int) ($assign->submissionid ?? 0);
        $contenthash = (string) ($assign->contenthash ?? '');
        $userid = (int) ($assign->userid ?? 0);
        if ($submissionid <= 0 || $contenthash === '') {
            return null;
        }

        $records = $DB->get_records_select(
            self::TABLE,
            'source = :source AND submissionid = :submissionid AND contenthash = :contenthash'
                . ' AND userid = :userid AND component = :component AND filearea = :filearea',
            [
                'source' => scan_source::ANTIVIRUS,
                'submissionid' => $submissionid,
                'contenthash' => $contenthash,
                'userid' => $userid,
                'component' => plugin_file_lifecycle::COMPONENT,
                'filearea' => plugin_file_lifecycle::GATE_FILEAREA,
            ],
            'timecreated DESC, id DESC',
            '*',
            0,
            1
        );
        $record = reset($records);
        return $record ?: null;
    }
}
