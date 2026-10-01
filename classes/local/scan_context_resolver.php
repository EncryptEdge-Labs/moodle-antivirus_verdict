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
 * Moodle-native scan context resolution (capability-aware).
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

use antivirus_verdict\scan_source;
use antivirus_verdict\local\assignment_scanner;


/**
 * Resolves course, activity, user, and submission context for scan records.
 */
class scan_context_resolver {
    /** @var int Viewer user id. */
    private int $viewerid;

    /** @var array<int,string> User fullname cache. */
    private array $usercache = [];

    /** @var array<int,\stdClass|false> Course cache. */
    private array $coursecache = [];

    /** @var array<int,\course_modinfo> Modinfo cache by course id. */
    private array $modinfocache = [];

    /**
     * Internal helper.
     *
     * @param int|null $viewerid User viewing the data, or null for $USER.
     */
    public function __construct(?int $viewerid = null) {
        global $USER;
        $this->viewerid = $viewerid ?? (int) $USER->id;
    }

    /**
     * Resolve display context for one scan row.
     *
     * @param \stdClass $scan Scan record from the repository.
     * @return scan_context_result
     */
    public function resolve(\stdClass $scan): scan_context_result {
        $result = new scan_context_result();
        $na = get_string('contextnotavailable', 'antivirus_verdict');
        $source = (string) ($scan->source ?? '');

        $scancontext = scan_access::context_for_scan($scan);
        $courseid = (int) ($scan->courseid ?? 0);
        if ($courseid <= 0 && $scancontext->contextlevel >= CONTEXT_COURSE) {
            $courseid = (int) $scancontext->instanceid;
        }
        if ($courseid <= 0) {
            $coursectx = $scancontext->get_course_context(false);
            if ($coursectx) {
                $courseid = (int) $coursectx->instanceid;
            }
        }

        $cmid = $this->cmid_from_scan($scan, $scancontext);
        $submissionid = $this->submission_id_from_scan($scan);

        $initiatedby = (int) ($scan->initiatedby ?? 0);
        $associateduserid = (int) ($scan->userid ?? 0);

        $result->scannedbylabel = get_string('contextscannedby', 'antivirus_verdict');

        switch ($source) {
            case scan_source::MANUAL:
                // Older rows stored the initiator in userid and left initiatedby empty.
                $scannerid = $initiatedby > 0 ? $initiatedby : $associateduserid;
                $this->show_scanner($result, $scannerid, $scancontext, $na);
                if ($initiatedby > 0 && $associateduserid > 0 && $associateduserid !== $initiatedby) {
                    $this->show_content_user(
                        $result,
                        $associateduserid,
                        get_string('contextuploadedby', 'antivirus_verdict'),
                        $scancontext,
                        $na
                    );
                }
                break;
            case scan_source::BULK:
            case scan_source::RESTORE:
                if ($initiatedby > 0) {
                    $this->show_scanner($result, $initiatedby, $scancontext, $na);
                }
                if ($associateduserid > 0 && $associateduserid !== $initiatedby) {
                    $this->show_content_user(
                        $result,
                        $associateduserid,
                        get_string('contextfileassociateduser', 'antivirus_verdict'),
                        $scancontext,
                        $na
                    );
                } else if ($associateduserid > 0 && $initiatedby <= 0) {
                    $this->show_scanner($result, $associateduserid, $scancontext, $na);
                }
                break;
            case scan_source::ANTIVIRUS:
                $result->showfileowner = true;
                if ($submissionid > 0) {
                    $result->showuploadsession = true;
                    $result->uploadsessionlabel = get_string('contextuploadedby', 'antivirus_verdict');
                    $result->uploadsessionuser = $this->user_label($associateduserid, $scancontext, $na);
                    $result->fileownerlabel = get_string('contextsubmittedby', 'antivirus_verdict');
                    $result->fileowner = $result->uploadsessionuser;
                } else {
                    $result->fileownerlabel = get_string('contextuploadedby', 'antivirus_verdict');
                    $result->fileowner = $this->user_label($associateduserid, $scancontext, $na);
                }
                break;
            case scan_source::ASSIGN:
                $this->show_content_user(
                    $result,
                    $associateduserid,
                    get_string('contextsubmittedby', 'antivirus_verdict'),
                    $scancontext,
                    $na
                );
                if ($initiatedby > 0 && $initiatedby !== $associateduserid) {
                    $this->show_scanner($result, $initiatedby, $scancontext, $na);
                }
                break;
            case scan_source::WORKSHOP:
                if ($associateduserid > 0) {
                    $this->show_content_user(
                        $result,
                        $associateduserid,
                        get_string('contextsubmittedby', 'antivirus_verdict'),
                        $scancontext,
                        $na
                    );
                }
                break;
            case scan_source::ARCHIVE:
                if ($initiatedby > 0) {
                    $this->show_scanner($result, $initiatedby, $scancontext, $na);
                }
                if ($associateduserid > 0 && ($initiatedby <= 0 || $associateduserid !== $initiatedby)) {
                    $ownerlabel = $submissionid > 0
                        ? get_string('contextsubmittedby', 'antivirus_verdict')
                        : get_string('contextuploadedby', 'antivirus_verdict');
                    $this->show_content_user($result, $associateduserid, $ownerlabel, $scancontext, $na);
                }
                break;
            default:
                if ($associateduserid > 0) {
                    $this->show_content_user(
                        $result,
                        $associateduserid,
                        get_string('contextuploadedby', 'antivirus_verdict'),
                        $scancontext,
                        $na
                    );
                }
                break;
        }

        if ($courseid > 0) {
            $result->showcourse = true;
            [$coursename, $courseurl] = $this->course_display($courseid, $scancontext);
            $result->course = $coursename ?: $na;
            $result->courseurl = $courseurl;
        }

        if ($cmid > 0 && $courseid > 0) {
            $cm = $this->get_cm($courseid, $cmid);
            if ($cm) {
                $result->showactivity = true;
                $result->activity = format_string($cm->name, true, ['context' => $cm->context]);
                $result->activityurl = (new \moodle_url('/mod/' . $cm->modname . '/view.php', ['id' => $cmid]))->out(false);
                $result->showactivitytype = true;
                $result->activitytype = $this->module_type_label($cm->modname);
            } else {
                $result->showactivity = true;
                $result->activity = $na;
            }
        } else if ($courseid > 0 && (int) ($scan->contextid ?? 0) > 0) {
            $storedcontext = \context::instance_by_id((int) $scan->contextid, IGNORE_MISSING);
            if (!$storedcontext) {
                $result->showactivity = true;
                $result->activity = $na;
            }
        }

        if (
            $submissionid > 0
            && in_array($source, [scan_source::ASSIGN, scan_source::ANTIVIRUS, scan_source::ARCHIVE], true)
        ) {
            $result->showsubmission = true;
            $result->submission = get_string('contextsubmissionid', 'antivirus_verdict', $submissionid);
            if ($cmid > 0 && $associateduserid > 0 && $this->can_view_submission($courseid, $cmid)) {
                $result->submissionurl = (new \moodle_url('/mod/assign/view.php', [
                    'id' => $cmid,
                    'action' => 'grader',
                    'userid' => $associateduserid,
                ]))->out(false);
            }
        }

        $location = $this->file_location_label($scan);
        if ($location !== '') {
            $result->showfilelocation = true;
            $result->filelocation = $location;
        }

        if ($source === scan_source::ANTIVIRUS && $submissionid > 0) {
            $submissionlocation = $this->assignment_submission_file_location($scan);
            if ($submissionlocation !== '') {
                $result->showsubmissionfilelocation = true;
                $result->submissionfilelocation = $submissionlocation;
            }
        }

        $parts = [];
        if ($result->showcourse && $result->course !== $na) {
            $parts[] = $result->course;
        }
        if ($result->showactivity && $result->activity !== '' && $result->activity !== $na) {
            $parts[] = $result->activity;
        }
        $result->summaryline = $parts !== [] ? implode(' · ', $parts) : '';

        return $result;
    }

    /**
     * Compact summary for table rows.
     *
     * @param \stdClass $scan Scan row.
     * @return string
     */
    public function summary_line(\stdClass $scan): string {
        return $this->resolve($scan)->summaryline;
    }

    /**
     * Derive course-module id from scan context / file metadata.
     *
     * @param \stdClass $scan Scan row.
     * @param \context $scancontext Scan context.
     * @return int
     */
    private function cmid_from_scan(\stdClass $scan, \context $scancontext): int {
        if ($scancontext->contextlevel === CONTEXT_MODULE) {
            return (int) $scancontext->instanceid;
        }
        $contextid = (int) ($scan->contextid ?? 0);
        if ($contextid <= 0) {
            return 0;
        }
        $ctx = \context::instance_by_id($contextid, IGNORE_MISSING);
        if ($ctx && $ctx->contextlevel === CONTEXT_MODULE) {
            return (int) $ctx->instanceid;
        }
        return 0;
    }

    /**
     * Authoritative submission id for assignment files.
     *
     * @param \stdClass $scan Scan row.
     * @return int
     */
    private function submission_id_from_scan(\stdClass $scan): int {
        $stored = (int) ($scan->submissionid ?? 0);
        if ($stored > 0) {
            return $stored;
        }
        $component = (string) ($scan->component ?? '');
        $filearea = (string) ($scan->filearea ?? '');
        if ($component === assignment_scanner::FILE_COMPONENT && $filearea === assignment_scanner::FILE_AREA) {
            return (int) ($scan->itemid ?? 0);
        }
        return 0;
    }

    /**
     * Internal helper.
     *
     * @param int $userid Target user.
     * @param \context $context Context for capability check.
     * @return string Empty when not authorized.
     */
    private function user_display(int $userid, \context $context): string {
        if ($userid <= 0) {
            return '';
        }
        if (!scan_access::can_view_user_identity($this->viewerid, $userid, $context)) {
            return '';
        }
        if (!isset($this->usercache[$userid])) {
            try {
                $user = \core_user::get_user($userid, '*', IGNORE_MISSING);
                $this->usercache[$userid] = $user ? fullname($user) : '';
            } catch (\Throwable $e) {
                $this->usercache[$userid] = '';
            }
        }
        return $this->usercache[$userid];
    }

    /**
     * Show the person who started this scan event.
     *
     * @param scan_context_result $result Display result.
     * @param int $userid Initiator.
     * @param \context $context Capability context.
     * @param string $na Fallback when the user cannot be shown.
     */
    private function show_scanner(scan_context_result $result, int $userid, \context $context, string $na): void {
        if ($userid <= 0) {
            return;
        }
        $result->showscannedby = true;
        $result->scannedby = $this->user_label($userid, $context, $na);
    }

    /**
     * Show the content owner or submitter.
     *
     * @param scan_context_result $result Display result.
     * @param int $userid Content user.
     * @param string $label Moodle-native label.
     * @param \context $context Capability context.
     * @param string $na Fallback when the user cannot be shown.
     */
    private function show_content_user(
        scan_context_result $result,
        int $userid,
        string $label,
        \context $context,
        string $na
    ): void {
        $result->showfileowner = true;
        $result->fileownerlabel = $label;
        $result->fileowner = $this->user_label($userid, $context, $na);
    }

    /**
     * Visible name, or the unavailable fallback.
     *
     * @param int $userid User id.
     * @param \context $context Capability context.
     * @param string $na Fallback.
     * @return string
     */
    private function user_label(int $userid, \context $context, string $na): string {
        if ($userid <= 0) {
            return $na;
        }
        $display = $this->user_display($userid, $context);
        return $display !== '' ? $display : $na;
    }

    /**
     * Internal helper.
     *
     * @param int $courseid Course id.
     * @param \context $scancontext Scan context for capability.
     * @return array{0:string,1:string} Name and URL.
     */
    private function course_display(int $courseid, \context $scancontext): array {
        if (!scan_access::can_view_course_identity($this->viewerid, $courseid)) {
            return ['', ''];
        }
        if (!isset($this->coursecache[$courseid])) {
            try {
                $this->coursecache[$courseid] = get_course($courseid);
            } catch (\Throwable $e) {
                $this->coursecache[$courseid] = false;
            }
        }
        $course = $this->coursecache[$courseid];
        if (!$course) {
            return [get_string('contextnotavailable', 'antivirus_verdict'), ''];
        }
        $coursecontext = \context_course::instance($courseid, IGNORE_MISSING);
        try {
            $name = format_string(
                $course->shortname,
                true,
                ['context' => $coursecontext ?: \context_system::instance()]
            );
        } catch (\Throwable $e) {
            $name = get_string('contextnotavailable', 'antivirus_verdict');
        }
        $url = $coursecontext
            ? (new \moodle_url('/course/view.php', ['id' => $courseid]))->out(false)
            : '';
        return [$name, $url];
    }

    /**
     * Internal helper.
     *
     * @param int $courseid Course id.
     * @param int $cmid Course-module id.
     * @return \cm_info|null
     */
    private function get_cm(int $courseid, int $cmid): ?\cm_info {
        if (!isset($this->modinfocache[$courseid])) {
            try {
                $this->modinfocache[$courseid] = get_fast_modinfo($courseid);
            } catch (\Throwable $e) {
                return null;
            }
        }
        $modinfo = $this->modinfocache[$courseid];
        if (!$modinfo->cms || !isset($modinfo->cms[$cmid])) {
            return null;
        }
        $cm = $modinfo->cms[$cmid];
        if (scan_access::can_manage_site($this->viewerid)) {
            return $cm;
        }
        $modulecontext = \context_module::instance($cmid, IGNORE_MISSING);
        if (
            $modulecontext && (
            has_capability('moodle/course:viewhiddenactivities', $modulecontext, $this->viewerid)
            || has_capability('antivirus/verdict:viewreports', $modulecontext, $this->viewerid)
            || has_capability('antivirus/verdict:viewhistory', $modulecontext, $this->viewerid)
            )
        ) {
            return $cm;
        }
        if ($cm->uservisible) {
            return $cm;
        }
        return null;
    }

    /**
     * Internal helper.
     *
     * @param string $modname Module component name.
     * @return string
     */
    private function module_type_label(string $modname): string {
        if ($modname === '') {
            return '';
        }
        $component = 'mod_' . $modname;
        if (get_string_manager()->string_exists('modulename', $component)) {
            return get_string('modulename', $component);
        }
        return $modname;
    }

    /**
     * Internal helper.
     *
     * @param int $courseid Course id.
     * @param int $cmid Course-module id.
     * @return bool
     */
    private function can_view_submission(int $courseid, int $cmid): bool {
        $context = \context_module::instance($cmid, IGNORE_MISSING);
        if (!$context) {
            return false;
        }
        return has_capability('mod/assign:grade', $context, $this->viewerid)
            || has_capability('mod/assign:view', $context, $this->viewerid);
    }

    /**
     * Human-readable file location from File API fields.
     *
     * @param \stdClass $scan Scan row.
     * @return string
     */
    private function file_location_label(\stdClass $scan): string {
        $component = (string) ($scan->component ?? '');
        $filearea = (string) ($scan->filearea ?? '');
        if ($component === '' || $filearea === '') {
            return '';
        }
        if ($component === 'antivirus_verdict' && $filearea === manual_scan::FILEAREA) {
            return get_string('contextfilemanualcopy', 'antivirus_verdict');
        }
        if ($component === 'antivirus_verdict' && $filearea === plugin_file_lifecycle::GATE_FILEAREA) {
            return get_string('contextfilegatecopy', 'antivirus_verdict');
        }
        if ($component === assignment_scanner::FILE_COMPONENT && $filearea === assignment_scanner::FILE_AREA) {
            return assignment_scanner::FILE_COMPONENT . ' / ' . assignment_scanner::FILE_AREA;
        }
        return $component . ' / ' . $filearea;
    }

    /**
     * Live Moodle submission file location when a gate scan is linked to assign_submission.
     *
     * @param \stdClass $scan Gate scan with submissionid and contenthash.
     * @return string
     */
    private function assignment_submission_file_location(\stdClass $scan): string {
        $submissionid = (int) ($scan->submissionid ?? 0);
        $contextid = (int) ($scan->contextid ?? 0);
        $contenthash = (string) ($scan->contenthash ?? '');
        $filename = (string) ($scan->filename ?? '');
        if ($submissionid <= 0 || $contextid <= 0 || $contenthash === '') {
            return '';
        }

        $context = \context::instance_by_id($contextid, IGNORE_MISSING);
        if (!$context || $context->contextlevel !== CONTEXT_MODULE) {
            return '';
        }

        $fs = get_file_storage();
        foreach (
            $fs->get_area_files(
                $contextid,
                assignment_scanner::FILE_COMPONENT,
                assignment_scanner::FILE_AREA,
                $submissionid,
                'id',
                false
            ) as $file
        ) {
            if ($file->is_directory()) {
                continue;
            }
            if ($file->get_contenthash() !== $contenthash) {
                continue;
            }
            if ($filename !== '' && $file->get_filename() !== $filename) {
                continue;
            }
            return assignment_scanner::FILE_COMPONENT . ' / ' . assignment_scanner::FILE_AREA;
        }
        return '';
    }
}
