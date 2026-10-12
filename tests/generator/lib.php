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
 * PHPUnit / Behat data generator for Verdict scan rows (no provider calls).
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

use antivirus_verdict\enforcement_state;
use antivirus_verdict\local\scan_repository;
use antivirus_verdict\scan_phase;
use antivirus_verdict\scan_source;
use antivirus_verdict\scan_status;

/**
 * Creates deterministic scan records for acceptance and unit tests.
 */
class antivirus_verdict_generator extends component_generator_base {
    /**
     * Insert a scan row without contacting VirusTotal.
     *
     * @param array $record Field overrides (filename, status, user, course, sha256, errorcode, …).
     * @return \stdClass Persisted scan including id.
     */
    public function create_scan(array $record = []): \stdClass {
        global $DB;

        $now = time();
        $filename = $record['filename'] ?? 'behat-fixture.bin';
        $status = $record['status'] ?? scan_status::CLEAN;
        $phase = $record['phase'] ?? ($status === scan_status::PENDING ? scan_phase::POLLING : scan_phase::COMPLETED);

        $userid = 0;
        if (!empty($record['user'])) {
            $user = $DB->get_record('user', ['username' => $record['user']], '*', MUST_EXIST);
            $userid = (int) $user->id;
        } else if (!empty($record['userid'])) {
            $userid = (int) $record['userid'];
        }

        $courseid = 0;
        if (!empty($record['course'])) {
            $course = $DB->get_record('course', ['shortname' => $record['course']], '*', MUST_EXIST);
            $courseid = (int) $course->id;
            $context = \context_course::instance($courseid);
        } else {
            $context = \context_system::instance();
            if (!empty($record['courseid'])) {
                $courseid = (int) $record['courseid'];
            }
        }

        $sha256 = $record['sha256'] ?? hash('sha256', 'behat:' . $filename . ':' . microtime(true));
        $hashseed = substr($sha256, 0, 20);

        $row = (object) array_merge([
            'fileid' => 0,
            'contenthash' => str_pad($hashseed, 40, 'a'),
            'pathnamehash' => str_pad(substr(hash('sha1', $filename), 0, 20), 40, 'b'),
            'contextid' => $context->id,
            'courseid' => $courseid,
            'component' => 'antivirus_verdict',
            'filearea' => 'manual',
            'itemid' => 0,
            'filepath' => '/',
            'filename' => $filename,
            'userid' => $userid,
            'initiatedby' => $userid,
            'submissionid' => 0,
            'source' => scan_source::MANUAL,
            'sha256' => $sha256,
            'filesize' => 128,
            'mimetype' => 'application/octet-stream',
            'status' => $status,
            'phase' => $phase,
            'vtanalysisid' => null,
            'vtfileid' => null,
            'malicious' => $status === scan_status::MALICIOUS ? 3 : 0,
            'suspicious' => null,
            'undetected' => null,
            'harmless' => null,
            'timeout' => null,
            'totalengines' => $status === scan_status::PENDING ? null : 70,
            'errorcode' => null,
            'enforcement' => enforcement_state::NONE,
            'pollattempts' => 0,
            'timelastpoll' => 0,
            'timesubmitted' => $now,
            'timecreated' => $now,
            'timemodified' => $now,
            'timecompleted' => $status === scan_status::PENDING ? 0 : $now,
            'parentscanid' => 0,
            'archiveoutcome' => null,
        ], array_diff_key($record, array_flip(['user', 'course'])));

        if ($status === scan_status::ERROR && empty($row->errorcode)) {
            $row->errorcode = 'error_network';
        }

        $repo = new scan_repository();
        $row->id = $repo->insert($row);
        return $row;
    }
}
