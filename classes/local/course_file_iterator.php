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
 * Iterates Moodle stored files belonging to a course.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;


/**
 * Batched file id iterator for bulk and restore sweeps.
 */
class course_file_iterator {
    /** @var int Course id. */
    private int $courseid;

    /**
     * Create an iterator for one course.
     *
     * @param int $courseid Course id.
     */
    public function __construct(int $courseid) {
        $this->courseid = max(0, $courseid);
    }

    /**
     * Context ids for the course and its activity modules.
     *
     * @return int[]
     */
    public function context_ids(): array {
        if ($this->courseid <= 0) {
            return [];
        }
        $ids = [\context_course::instance($this->courseid)->id];
        try {
            $modinfo = get_fast_modinfo($this->courseid);
            foreach ($modinfo->get_cms() as $cm) {
                $ids[] = \context_module::instance($cm->id)->id;
            }
        } catch (\Throwable $e) {
            debugging('antivirus_verdict course context enumeration failed: ' . $e->getMessage(), \DEBUG_DEVELOPER);
        }
        return array_values(array_unique($ids));
    }

    /**
     * Fetch the next batch of file ids after a cursor.
     *
     * @param int $afterfileid Last processed files.id.
     * @param int $limit Maximum rows.
     * @return int[] File ids in ascending order.
     */
    public function next_file_ids(int $afterfileid, int $limit): array {
        global $DB;

        $contextids = $this->context_ids();
        if ($contextids === [] || $limit <= 0) {
            return [];
        }

        [$insql, $params] = $DB->get_in_or_equal($contextids, \SQL_PARAMS_NAMED, 'ctx');
        $params['afterid'] = max(0, $afterfileid);

        $sql = "SELECT f.id
                  FROM {files} f
                 WHERE f.contextid {$insql}
                   AND f.id > :afterid
                   AND f.filename <> '.'
                   AND f.filesize > 0
              ORDER BY f.id ASC";

        $records = $DB->get_records_sql($sql, $params, 0, $limit);
        return array_map('intval', array_keys($records));
    }
}
