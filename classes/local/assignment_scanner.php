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
 * Assignment submission consumer for the VirusTotal scan engine.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

use antivirus_verdict\scan_source;
use mod_assign\event\assessable_submitted;


/**
 * Queues learner assignment files through the existing scan service.
 *
 * Does not call VirusTotal, hash files, or write scan rows directly.
 * Failures are swallowed so assignment submission is never blocked.
 */
class assignment_scanner {
    /** File API component for learner assignment submission files. */
    public const FILE_COMPONENT = 'assignsubmission_file';

    /** File area matching ASSIGNSUBMISSION_FILE_FILEAREA in Moodle 5.2. */
    public const FILE_AREA = 'submission_files';

    /** Assignment submission status that is eligible for scanning. */
    public const SUBMISSION_STATUS_SUBMITTED = 'submitted';

    /** @var scan_service Scan engine. */
    private scan_service $scanservice;

    /** @var plugin_config Operational settings. */
    private plugin_config $config;

    /**
     * Create an assignment integration service.
     *
     * @param scan_service $scanservice Scan engine.
     * @param plugin_config $config Operational settings.
     */
    public function __construct(scan_service $scanservice, plugin_config $config) {
        $this->scanservice = $scanservice;
        $this->config = $config;
    }

    /**
     * Production scanner using site configuration.
     *
     * @return self
     */
    public static function from_site_config(): self {
        return new self(scan_service::from_site_config(), plugin_config::from_site_config());
    }

    /**
     * Queue eligible submission files from an assessable_submitted event.
     *
     * @param assessable_submitted $event Assignment submission event.
     * @return \stdClass[] Scan records created or reused.
     */
    public function scan_from_event(assessable_submitted $event): array {
        try {
            if (!$this->config->assignment_auto_scan_enabled()) {
                return [];
            }

            $bundle = $this->resolve_submitted_event_bundle($event);
            if ($bundle === null) {
                return [];
            }

            $submission = $bundle['submission'];
            $userid = (int) $bundle['userid'];
            $submissionid = (int) $submission->id;
            $initiator = (int) $event->userid;
            if ($initiator <= 0 || !\core_user::is_real_user($initiator, true)) {
                $initiator = 0;
            }
            $scans = [];
            foreach ($bundle['files'] as $file) {
                try {
                    $scans[] = $this->scanservice->enqueue_file_scan(
                        $file,
                        scan_source::ASSIGN,
                        $userid,
                        false,
                        0,
                        null,
                        $submissionid,
                        $initiator
                    );
                } catch (\Throwable $e) {
                    debugging(
                        'antivirus_verdict assignment file scan failed: ' . $e->getMessage(),
                        \DEBUG_DEVELOPER
                    );
                }
            }
            return $scans;
        } catch (\Throwable $e) {
            debugging('antivirus_verdict assignment scan failed: ' . $e->getMessage(), \DEBUG_DEVELOPER);
            return [];
        }
    }

    /**
     * Authoritative submission files and Moodle context for a submitted event.
     *
     * Used by assignment backfill scanning and gate correlation (independent of assignscan).
     *
     * @param assessable_submitted $event Assignment submission event.
     * @return array{
     *     context:\context_module,
     *     submission:\stdClass,
     *     userid:int,
     *     files:\stored_file[],
     *     eventtime:int
     * }|null
     */
    public function resolve_submitted_event_bundle(assessable_submitted $event): ?array {
        $submissionid = (int) $event->objectid;
        if ($submissionid <= 0) {
            return null;
        }

        $context = $event->get_context();
        if (!$context instanceof \context_module) {
            return null;
        }

        $submission = $this->load_submitted_submission($submissionid);
        if (!$submission) {
            return null;
        }

        return [
            'context' => $context,
            'submission' => $submission,
            'userid' => $this->learner_userid($event, $submission),
            'files' => $this->submission_files($context->id, $submissionid),
            'eventtime' => (int) $event->timecreated,
        ];
    }

    /**
     * Load a submitted assignment submission, or null when missing/not submitted.
     *
     * @param int $submissionid assign_submission.id
     * @return \stdClass|null
     */
    private function load_submitted_submission(int $submissionid): ?\stdClass {
        global $DB;

        if (!$DB->get_manager()->table_exists('assign_submission')) {
            return null;
        }

        $submission = $DB->get_record('assign_submission', ['id' => $submissionid]);
        if (!$submission) {
            return null;
        }
        if ($submission->status !== self::SUBMISSION_STATUS_SUBMITTED) {
            return null;
        }
        return $submission;
    }

    /**
     * Learner id from the Moodle submission record, then the event.
     *
     * Does not use $USER. Team submissions may store userid 0.
     *
     * @param assessable_submitted $event Assignment event.
     * @param \stdClass $submission assign_submission row.
     * @return int
     */
    private function learner_userid(assessable_submitted $event, \stdClass $submission): int {
        if ((int) $submission->userid > 0) {
            return (int) $submission->userid;
        }
        if (!empty($event->relateduserid) && (int) $event->relateduserid > 0) {
            return (int) $event->relateduserid;
        }
        return max(0, (int) $event->userid);
    }

    /**
     * Learner submission files from the Moodle File API.
     *
     * @param int $contextid Assignment module context id.
     * @param int $submissionid assign_submission.id (file itemid).
     * @return \stored_file[]
     */
    private function submission_files(int $contextid, int $submissionid): array {
        $fs = get_file_storage();
        $files = $fs->get_area_files(
            $contextid,
            self::FILE_COMPONENT,
            self::FILE_AREA,
            $submissionid,
            'id',
            false
        );

        $eligible = [];
        foreach ($files as $file) {
            if ($file->is_directory()) {
                continue;
            }
            if ($file->get_component() !== self::FILE_COMPONENT) {
                continue;
            }
            if ($file->get_filearea() !== self::FILE_AREA) {
                continue;
            }
            if ((int) $file->get_itemid() !== $submissionid) {
                continue;
            }
            $eligible[] = $file;
        }
        return $eligible;
    }
}
