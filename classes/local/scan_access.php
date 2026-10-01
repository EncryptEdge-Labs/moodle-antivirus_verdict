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
 * Scan record authorisation for history and detail pages.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

use antivirus_verdict\scan_source;


/**
 * Capability and context checks for scan records. Role names are never used.
 */
class scan_access {
    /**
     * Whether the user can manage site-wide scan records.
     *
     * @param int|null $userid User id, or null for the current user.
     * @return bool
     */
    public static function can_manage_site(?int $userid = null): bool {
        return has_capability('antivirus/verdict:manage', \context_system::instance(), $userid);
    }

    /**
     * Whether the user may open the overview.
     *
     * Site managers see every course. Teachers see courses they can scan or review.
     *
     * @param int|null $userid User id, or null for the current user.
     * @return bool
     */
    public static function can_view_overview(?int $userid = null): bool {
        return teacher_access::allows('overview', $userid);
    }

    /**
     * Whether the user teaches at least one course for scanning or history.
     *
     * @param int|null $userid User id, or null for the current user.
     * @return bool
     */
    public static function has_teaching_access(?int $userid = null): bool {
        return self::courseids_for('antivirus/verdict:scan', $userid) !== []
            || self::courseids_for('antivirus/verdict:viewhistory', $userid) !== [];
    }

    /**
     * Whether the user may open quarantine for courses they can review.
     *
     * @param int|null $userid User id, or null for the current user.
     * @return bool
     */
    public static function can_view_quarantine(?int $userid = null): bool {
        return self::can_manage_site($userid)
            || self::courseids_for('antivirus/verdict:viewhistory', $userid) !== [];
    }

    /**
     * Whether a course-level capability is allowed in at least one course.
     *
     * Site management is not treated as that course capability.
     *
     * @param string $capability Plugin capability name.
     * @param int|null $userid User id, or null for the current user.
     * @return bool
     */
    public static function has_capability_in_any_course(string $capability, ?int $userid = null): bool {
        if (
            !in_array($capability, [
                'antivirus/verdict:scan',
                'antivirus/verdict:viewreports',
                'antivirus/verdict:viewhistory',
                'antivirus/verdict:rescan',
            ], true)
        ) {
            return false;
        }
        return self::courseids_for($capability, $userid) !== [];
    }

    /**
     * Courses a non-manager may bulk-scan, or every course for a site manager.
     *
     * @param int|null $userid User id, or null for the current user.
     * @return array<int,string> Course id => full name.
     */
    public static function bulk_course_menu(?int $userid = null): array {
        global $DB;

        if (self::can_manage_site($userid)) {
            return $DB->get_records_sql_menu(
                'SELECT id, fullname FROM {course} WHERE id <> :site ORDER BY fullname ASC',
                ['site' => SITEID],
                0,
                500
            );
        }

        $courses = get_user_capability_course(
            'antivirus/verdict:scan',
            $userid,
            false,
            'fullname',
            'fullname ASC'
        );
        if (empty($courses)) {
            return [];
        }
        $menu = [];
        foreach ($courses as $course) {
            $id = (int) $course->id;
            if ($id <= 0 || $id === (int) SITEID) {
                continue;
            }
            $menu[$id] = (string) $course->fullname;
        }
        return $menu;
    }

    /**
     * Whether the user may request a manual scan in this page context.
     *
     * @param \context $context Page context.
     * @param int|null $userid User id, or null for the current user.
     * @return bool
     */
    public static function can_scan(\context $context, ?int $userid = null): bool {
        if (self::can_manage_site($userid)) {
            return true;
        }
        if ($context->contextlevel === \CONTEXT_SYSTEM) {
            return self::courseids_for('antivirus/verdict:scan', $userid) !== [];
        }
        return has_capability('antivirus/verdict:scan', $context, $userid);
    }

    /**
     * Whether the user may open the history page in this context.
     *
     * System context is allowed when the user has viewhistory in any course.
     *
     * @param \context $context Page context.
     * @param int|null $userid User id, or null for the current user.
     * @return bool
     */
    public static function can_view_history_page(\context $context, ?int $userid = null): bool {
        if (self::can_manage_site($userid) || has_capability('antivirus/verdict:viewhistory', $context, $userid)) {
            return true;
        }
        if ($context->contextlevel === \CONTEXT_SYSTEM) {
            return self::viewhistory_courseids($userid) !== [];
        }
        return false;
    }

    /**
     * Whether the user may see one scan record.
     *
     * @param \stdClass $scan Scan row.
     * @param int|null $userid User id, or null for the current user.
     * @return bool
     */
    public static function can_view_scan(\stdClass $scan, ?int $userid = null): bool {
        global $USER;

        if ($userid === null) {
            $userid = (int) $USER->id;
        }
        if (self::can_manage_site($userid)) {
            return true;
        }

        if (self::can_view_own_manual_scan($scan, $userid)) {
            return true;
        }

        $courseid = (int) ($scan->courseid ?? 0);
        if ($courseid > 0) {
            if (self::has_capability_at_course('antivirus/verdict:viewreports', $courseid, $userid)) {
                return true;
            }
            if (self::has_capability_at_course('antivirus/verdict:viewhistory', $courseid, $userid)) {
                return true;
            }
        }

        $context = self::context_for_scan($scan);
        return has_capability('antivirus/verdict:viewreports', $context, $userid)
            || has_capability('antivirus/verdict:viewhistory', $context, $userid);
    }

    /**
     * Whether the user may view a manual scan they queued (including site-level scans).
     *
     * Manual scans from Scan a file often use system context; :scan is course-level.
     *
     * @param \stdClass $scan Scan row.
     * @param int|null $userid User id, or null for the current user.
     * @return bool
     */
    public static function can_view_own_manual_scan(\stdClass $scan, ?int $userid = null): bool {
        global $USER;
        if ($userid === null) {
            $userid = (int) $USER->id;
        }
        if ($scan->source !== scan_source::MANUAL) {
            return false;
        }
        if ((int) $scan->userid !== $userid && (int) ($scan->initiatedby ?? 0) !== $userid) {
            return false;
        }
        $context = self::context_for_scan($scan);
        if (has_capability('antivirus/verdict:scan', $context, $userid)) {
            return true;
        }
        return self::courseids_for('antivirus/verdict:scan', $userid) !== [];
    }

    /**
     * Whether the user may request a new scan of this record's file.
     *
     * Viewing a scan is not sufficient. The user must also have rescan in the
     * scan context, or site manage.
     *
     * @param \stdClass $scan Scan row.
     * @param int|null $userid User id, or null for the current user.
     * @return bool
     */
    public static function can_rescan(\stdClass $scan, ?int $userid = null): bool {
        global $USER;
        if ($userid === null) {
            $userid = (int) $USER->id;
        }
        if (!self::can_view_scan($scan, $userid)) {
            return false;
        }
        if (self::can_manage_site($userid)) {
            return true;
        }
        $courseid = (int) ($scan->courseid ?? 0);
        if ($courseid > 0 && self::has_capability_at_course('antivirus/verdict:rescan', $courseid, $userid)) {
            return true;
        }
        $context = self::context_for_scan($scan);
        if (has_capability('antivirus/verdict:rescan', $context, $userid)) {
            return true;
        }
        if (self::can_view_own_manual_scan($scan, $userid)) {
            return self::courseids_for('antivirus/verdict:rescan', $userid) !== [];
        }
        return false;
    }

    /**
     * SQL fragment limiting history to records the user may see.
     *
     * @param int $userid User id.
     * @param int $pagecourseid Optional course restriction from the page URL.
     * @return array{0:string,1:array} Where clause and params.
     */
    public static function history_visibility_sql(int $userid, int $pagecourseid = 0): array {
        global $DB;

        if (self::can_manage_site($userid)) {
            if ($pagecourseid > 0) {
                return ['courseid = :pagecourseid', ['pagecourseid' => $pagecourseid]];
            }
            return ['1=1', []];
        }

        $ownmanual = '((userid = :ownerid OR initiatedby = :initiatorid) AND source = :manualsource)';
        $ownparams = [
            'ownerid' => $userid,
            'initiatorid' => $userid,
            'manualsource' => scan_source::MANUAL,
        ];
        $courseids = self::viewhistory_courseids($userid);

        if ($pagecourseid > 0) {
            $courseparams = ['pagecourseid' => $pagecourseid];
            if (
                in_array($pagecourseid, $courseids, true)
                || has_capability('antivirus/verdict:viewhistory', \context_course::instance($pagecourseid), $userid)
            ) {
                return ['courseid = :pagecourseid', $courseparams];
            }
            return ["{$ownmanual} AND courseid = :pagecourseid", $ownparams + $courseparams];
        }

        if ($courseids === []) {
            return [$ownmanual, $ownparams];
        }

        [$insql, $inparams] = $DB->get_in_or_equal($courseids, \SQL_PARAMS_NAMED, 'cid');
        return ["({$ownmanual} OR courseid {$insql})", $ownparams + $inparams];
    }

    /**
     * Whether a course-level plugin capability applies for the user.
     *
     * @param string $capability Capability name.
     * @param int $courseid Course id.
     * @param int $userid User id.
     * @return bool
     */
    public static function has_capability_at_course(string $capability, int $courseid, int $userid): bool {
        if ($courseid <= 0) {
            return false;
        }
        try {
            $context = \context_course::instance($courseid);
        } catch (\Exception $e) {
            return false;
        }
        return has_capability($capability, $context, $userid);
    }

    /**
     * Moodle context used to authorise a scan row.
     *
     * @param \stdClass $scan Scan row.
     * @return \context
     */
    public static function context_for_scan(\stdClass $scan): \context {
        $contextid = (int) ($scan->contextid ?? 0);
        if ($contextid > 0) {
            $context = \context::instance_by_id($contextid, IGNORE_MISSING);
            if ($context) {
                return $context;
            }
        }
        if (!empty($scan->courseid)) {
            $coursecontext = \context_course::instance((int) $scan->courseid, \IGNORE_MISSING);
            if ($coursecontext) {
                return $coursecontext;
            }
        }
        return \context_system::instance();
    }

    /**
     * Whether the viewer may see a Moodle user's name in scan context.
     *
     * @param int $viewerid Viewer user id.
     * @param int $targetuserid Target user id.
     * @param \context $context Scan or course context.
     * @return bool
     */
    public static function can_view_user_identity(int $viewerid, int $targetuserid, \context $context): bool {
        if ($targetuserid <= 0) {
            return false;
        }
        if ($viewerid === $targetuserid) {
            return true;
        }
        if (self::can_manage_site($viewerid)) {
            return true;
        }
        $coursecontext = $context->get_course_context(false);
        if (!$coursecontext) {
            return false;
        }
        return has_capability('moodle/course:viewparticipants', $coursecontext, $viewerid)
            || has_capability('antivirus/verdict:viewreports', $context, $viewerid)
            || has_capability('antivirus/verdict:viewhistory', $coursecontext, $viewerid);
    }

    /**
     * Whether the viewer may see course names/links for a scan.
     *
     * @param int $viewerid Viewer user id.
     * @param int $courseid Course id.
     * @return bool
     */
    public static function can_view_course_identity(int $viewerid, int $courseid): bool {
        if ($courseid <= 0) {
            return false;
        }
        if (self::can_manage_site($viewerid)) {
            return true;
        }
        $context = \context_course::instance($courseid, IGNORE_MISSING);
        if (!$context) {
            return false;
        }
        return has_capability('moodle/course:view', $context, $viewerid)
            || has_capability('antivirus/verdict:viewhistory', $context, $viewerid)
            || has_capability('antivirus/verdict:viewreports', $context, $viewerid);
    }

    /**
     * Course ids where the user has viewhistory. Site admin override is not used.
     *
     * @param int|null $userid User id.
     * @return int[]
     */
    public static function viewhistory_courseids(?int $userid = null): array {
        return self::courseids_for('antivirus/verdict:viewhistory', $userid);
    }

    /**
     * Course ids where the capability is allowed. Site admin override is not used.
     *
     * @param string $capability Capability name.
     * @param int|null $userid User id, or null for the current user.
     * @return int[]
     */
    public static function courseids_for(string $capability, ?int $userid = null): array {
        global $USER;

        if ($userid === null) {
            $userid = (int) $USER->id;
        }
        $courses = get_user_capability_course($capability, $userid, false, '', 'id ASC');
        if (empty($courses)) {
            return [];
        }
        $ids = [];
        foreach ($courses as $course) {
            $id = (int) $course->id;
            if ($id > 0 && $id !== (int) SITEID) {
                $ids[] = $id;
            }
        }
        return $ids;
    }
}
