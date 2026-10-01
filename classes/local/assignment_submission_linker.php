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
 * Links native antivirus gate scans to assignment submission context.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

use mod_assign\event\assessable_submitted;


/**
 * Correlates gate pre-upload scans with assessable_submitted events.
 *
 * Gate rows keep plugin file identity for enforcement. Course, module context,
 * and submission id are stored for audit from the Moodle event. Submission File
 * API rows strengthen correlation when present but are not required.
 */
class assignment_submission_linker {
    /**
     * Maximum seconds a gate may precede a known File API timecreated.
     *
     * Covers draft uploads (file stored days before assessable_submitted).
     */
    public const GATE_MAX_AGE_BEFORE_FILE_SECONDS = 2592000;

    /**
     * Gate timecreated may follow stored_file.timecreated by at most this many seconds.
     *
     * Not a storage-latency budget: antivirus runs before Moodle accepts the upload.
     */
    public const GATE_AFTER_FILE_SLACK_SECONDS = 60;

    /**
     * Gate must not be newer than assessable_submitted timecreated plus this slack.
     */
    public const EVENT_AFTER_SUBMIT_SLACK_SECONDS = 300;

    /**
     * User-draft File API evidence must fall within this many seconds before the event.
     *
     * Drafts are not assignment-scoped. A two-hour leftover draft from another activity
     * must not be treated as evidence for this submission.
     */
    public const EVENT_ONLY_MAX_AGE_SECONDS = 300;

    /**
     * When several gate rows share contenthash/filename/user, require gate time to be
     * within this many seconds before the evidence file (synchronous upload pair).
     */
    public const UPLOAD_PAIR_MAX_SECONDS = 120;

    /** @var scan_repository Scan persistence. */
    private scan_repository $repository;

    /**
     * Create a linker with injected persistence.
     *
     * @param scan_repository $repository Scan persistence.
     */
    public function __construct(scan_repository $repository) {
        $this->repository = $repository;
    }

    /**
     * Production linker using site services. Does not construct the assignment scanner.
     *
     * @return self
     */
    public static function from_site_config(): self {
        return new self(new scan_repository());
    }

    /**
     * Attach submission context to matching antivirus gate rows.
     *
     * @param assessable_submitted $event Assignment submission event.
     * @return int Number of gate rows linked.
     */
    public function link_from_event(assessable_submitted $event): int {
        try {
            $submissionid = (int) $event->objectid;
            if ($submissionid <= 0) {
                return 0;
            }

            $context = $event->get_context();
            if (!$context instanceof \context_module) {
                return 0;
            }

            $courseid = (int) $event->courseid;
            if ($courseid <= 0) {
                $coursectx = $context->get_course_context(false);
                $courseid = $coursectx ? (int) $coursectx->instanceid : 0;
            }
            if ($courseid <= 0) {
                debugging(
                    'antivirus_verdict assignment gate link skipped: event has no course id',
                    \DEBUG_DEVELOPER
                );
                return 0;
            }

            $eventtime = (int) $event->timecreated;
            $userid = $this->learner_userid_from_event($event);
            if ($userid <= 0) {
                return 0;
            }

            $submissionfiles = $this->area_files(
                $context->id,
                assignment_scanner::FILE_COMPONENT,
                assignment_scanner::FILE_AREA,
                $submissionid
            );
            if ($submissionfiles !== []) {
                return $this->link_gates_for_files(
                    $submissionfiles,
                    $userid,
                    $eventtime,
                    (int) $context->id,
                    $courseid,
                    $submissionid,
                    false
                );
            }

            $drafts = $this->recent_user_draft_files($userid, $eventtime);
            if (count($drafts) !== 1) {
                if (count($drafts) > 1) {
                    debugging(
                        'antivirus_verdict assignment gate link skipped: multiple user drafts near event for user '
                            . $userid,
                        \DEBUG_DEVELOPER
                    );
                }
                return 0;
            }
            if ($this->other_recent_assign_submission_exists($userid, $eventtime, $submissionid)) {
                debugging(
                    'antivirus_verdict assignment gate link skipped: other recent assign_submission for user '
                        . $userid,
                    \DEBUG_DEVELOPER
                );
                return 0;
            }
            return $this->link_gates_for_files(
                $drafts,
                $userid,
                $eventtime,
                (int) $context->id,
                $courseid,
                $submissionid,
                true
            );
        } catch (\Throwable $e) {
            debugging('antivirus_verdict assignment gate link failed: ' . $e->getMessage(), \DEBUG_DEVELOPER);
            return 0;
        }
    }

    /**
     * Correlate gates to evidence files and persist assignment context.
     *
     * Submission-area files may produce one link per file. Draft evidence is not
     * assignment-scoped, so only a single unambiguous gate may be linked.
     *
     * @param \stored_file[] $files Evidence files.
     * @param int $userid Submitter.
     * @param int $eventtime Event timecreated.
     * @param int $contextid Module context id.
     * @param int $courseid Course id.
     * @param int $submissionid assign_submission.id.
     * @param bool $draftmode True when evidence is user/draft, not submission files.
     * @return int Number of rows linked.
     */
    private function link_gates_for_files(
        array $files,
        int $userid,
        int $eventtime,
        int $contextid,
        int $courseid,
        int $submissionid,
        bool $draftmode
    ): int {
        $selected = [];
        foreach ($files as $file) {
            if ($file->is_directory()) {
                continue;
            }
            $gates = $this->repository->find_unlinked_gate_scans_for_submission_file(
                $file->get_contenthash(),
                $userid,
                $file->get_filename(),
                (int) $file->get_timecreated(),
                $eventtime,
                self::GATE_MAX_AGE_BEFORE_FILE_SECONDS,
                self::GATE_AFTER_FILE_SLACK_SECONDS,
                self::EVENT_AFTER_SUBMIT_SLACK_SECONDS
            );
            $gate = $this->pick_best_gate($gates, $file);
            if (!$gate || (int) ($gate->submissionid ?? 0) > 0) {
                continue;
            }
            if (!$this->evidence_file_still_matches($file, $gate)) {
                continue;
            }
            $selected[(int) $gate->id] = $gate;
        }

        if ($draftmode) {
            if (count($selected) !== 1) {
                if (count($selected) > 1) {
                    debugging(
                        'antivirus_verdict assignment gate link skipped: ambiguous draft evidence for user ' . $userid,
                        \DEBUG_DEVELOPER
                    );
                }
                return 0;
            }
        }

        $linked = 0;
        foreach ($selected as $gate) {
            $this->repository->apply_assignment_context_to_gate_scan(
                (int) $gate->id,
                $contextid,
                $courseid,
                $submissionid
            );
            $linked++;
        }
        return $linked;
    }

    /**
     * Submitter from assign_submission when present, otherwise the event user.
     *
     * Status (submitted/reopened/draft) is not required: the event is authoritative.
     *
     * @param assessable_submitted $event Assignment submission event.
     * @return int
     */
    private function learner_userid_from_event(assessable_submitted $event): int {
        global $DB;

        $submissionid = (int) $event->objectid;
        if ($submissionid > 0 && $DB->get_manager()->table_exists('assign_submission')) {
            $submission = $DB->get_record('assign_submission', ['id' => $submissionid], 'id, userid', IGNORE_MISSING);
            if ($submission && (int) $submission->userid > 0) {
                return (int) $submission->userid;
            }
        }
        if (!empty($event->relateduserid) && (int) $event->relateduserid > 0) {
            return (int) $event->relateduserid;
        }
        return max(0, (int) $event->userid);
    }

    /**
     * Non-directory files in a File API area.
     *
     * @param int $contextid Context id.
     * @param string $component Component.
     * @param string $filearea File area.
     * @param int $itemid Item id.
     * @return \stored_file[]
     */
    private function area_files(int $contextid, string $component, string $filearea, int $itemid): array {
        $fs = get_file_storage();
        $files = $fs->get_area_files($contextid, $component, $filearea, $itemid, 'id', false);
        $eligible = [];
        foreach ($files as $file) {
            if ($file->is_directory()) {
                continue;
            }
            $eligible[] = $file;
        }
        return $eligible;
    }

    /**
     * True when another assign_submission for this user was written in the draft window.
     *
     * Prevents attributing a leftover draft to the wrong activity when the student
     * submitted more than one assignment in the same bounded interval.
     *
     * @param int $userid Submitter.
     * @param int $eventtime Event timecreated.
     * @param int $submissionid Current assign_submission.id.
     * @return bool
     */
    private function other_recent_assign_submission_exists(int $userid, int $eventtime, int $submissionid): bool {
        global $DB;

        if ($userid <= 0 || $eventtime <= 0 || !$DB->get_manager()->table_exists('assign_submission')) {
            return true;
        }

        $since = max(0, $eventtime - self::EVENT_ONLY_MAX_AGE_SECONDS);
        $until = $eventtime + self::EVENT_AFTER_SUBMIT_SLACK_SECONDS;
        return $DB->record_exists_select(
            'assign_submission',
            'userid = :userid AND id <> :submissionid AND timemodified >= :since AND timemodified <= :until',
            [
                'userid' => $userid,
                'submissionid' => $submissionid,
                'since' => $since,
                'until' => $until,
            ]
        );
    }

    /**
     * Recent user-draft files for the submitter (Moodle file picker copies).
     *
     * @param int $userid User id.
     * @param int $eventtime Event timecreated.
     * @return \stored_file[]
     */
    private function recent_user_draft_files(int $userid, int $eventtime): array {
        global $DB;

        if ($userid <= 0 || $eventtime <= 0) {
            return [];
        }

        $since = max(0, $eventtime - self::EVENT_ONLY_MAX_AGE_SECONDS);
        $until = $eventtime + self::EVENT_AFTER_SUBMIT_SLACK_SECONDS;
        $records = $DB->get_records_select(
            'files',
            'userid = :userid AND component = :component AND filearea = :filearea AND filename <> :dot'
                . ' AND filesize > 0 AND timecreated >= :since AND timecreated <= :until',
            [
                'userid' => $userid,
                'component' => 'user',
                'filearea' => 'draft',
                'dot' => '.',
                'since' => $since,
                'until' => $until,
            ],
            'timecreated DESC, id DESC'
        );

        $fs = get_file_storage();
        $files = [];
        foreach ($records as $record) {
            $file = $fs->get_file_by_id((int) $record->id);
            if ($file && !$file->is_directory()) {
                $files[] = $file;
            }
        }
        return $files;
    }

    /**
     * Choose the gate scan that best matches one evidence file.
     *
     * @param \stdClass[] $gates Candidate rows (newest first).
     * @param \stored_file $file Evidence file.
     * @return \stdClass|null
     */
    private function pick_best_gate(array $gates, \stored_file $file): ?\stdClass {
        if ($gates === []) {
            return null;
        }

        $pool = $gates;
        if (count($gates) > 1) {
            $pool = $this->filter_upload_pair_candidates($gates, $file);
            if ($pool === []) {
                return null;
            }
        }

        $filetime = (int) $file->get_timecreated();
        $slack = self::GATE_AFTER_FILE_SLACK_SECONDS;
        $best = null;
        $bestdelta = null;

        foreach ($pool as $gate) {
            $gatetime = (int) $gate->timecreated;
            if ($filetime > 0) {
                if ($gatetime > $filetime + $slack) {
                    continue;
                }
                $delta = $filetime - $gatetime;
                if ($delta < 0) {
                    continue;
                }
            } else {
                $delta = 0;
            }

            if (
                $best === null
                || $delta < $bestdelta
                || ($delta === $bestdelta && $gatetime > (int) $best->timecreated)
            ) {
                $best = $gate;
                $bestdelta = $delta;
            }
        }

        return $best;
    }

    /**
     * Narrow ambiguous candidate sets to synchronous upload pairs.
     *
     * @param \stdClass[] $gates Candidate rows.
     * @param \stored_file $file Evidence file.
     * @return \stdClass[]
     */
    private function filter_upload_pair_candidates(array $gates, \stored_file $file): array {
        $filetime = (int) $file->get_timecreated();
        if ($filetime <= 0) {
            return [];
        }

        $filtered = [];
        foreach ($gates as $gate) {
            $gatetime = (int) $gate->timecreated;
            if (
                $gatetime >= $filetime - self::UPLOAD_PAIR_MAX_SECONDS
                && $gatetime <= $filetime + self::GATE_AFTER_FILE_SLACK_SECONDS
            ) {
                $filtered[] = $gate;
            }
        }
        return $filtered;
    }

    /**
     * Confirm the evidence file still matches the gate row at link time.
     *
     * @param \stored_file $file Evidence file.
     * @param \stdClass $gate Gate scan row.
     * @return bool
     */
    private function evidence_file_still_matches(\stored_file $file, \stdClass $gate): bool {
        $gatehash = (string) ($gate->contenthash ?? '');
        if ($gatehash !== '' && $gatehash !== $file->get_contenthash()) {
            return false;
        }
        $gatefilename = (string) ($gate->filename ?? '');
        if ($gatefilename !== '' && $gatefilename !== $file->get_filename()) {
            return false;
        }
        return true;
    }
}
