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
 * Privacy API provider for the antivirus_verdict plugin.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\privacy;

use core_privacy\local\metadata\collection;
use core_privacy\local\request\approved_contextlist;
use core_privacy\local\request\approved_userlist;
use core_privacy\local\request\contextlist;
use core_privacy\local\request\transform;
use core_privacy\local\request\userlist;
use core_privacy\local\request\writer;
use antivirus_verdict\local\plugin_file_lifecycle;
use antivirus_verdict\local\scan_presenter;
use antivirus_verdict\scan_status;


/**
 * Describes stored scan metadata and the VirusTotal external location.
 *
 * Plugin-owned records can be exported and deleted. Privacy deletion does
 * not remove original Moodle activity files. A later malicious verdict may
 * quarantine and delete a verified matching Moodle file as a security action.
 * Data already submitted to VirusTotal cannot be retracted by this plugin.
 */
class provider implements
    \core_privacy\local\metadata\provider,
    \core_privacy\local\request\core_userlist_provider,
    \core_privacy\local\request\plugin\provider {
    /**
     * Describe stored personal data and the external VirusTotal destination.
     *
     * @param collection $collection Item collection.
     * @return collection
     */
    public static function get_metadata(collection $collection): collection {
        $collection->add_database_table('antivirus_verdict_scans', [
            'userid' => 'privacy:metadata:scans:userid',
            'initiatedby' => 'privacy:metadata:scans:initiatedby',
            'submissionid' => 'privacy:metadata:scans:submissionid',
            'contextid' => 'privacy:metadata:scans:contextid',
            'courseid' => 'privacy:metadata:scans:courseid',
            'filename' => 'privacy:metadata:scans:filename',
            'filepath' => 'privacy:metadata:scans:filepath',
            'parentscanid' => 'privacy:metadata:scans:parentscanid',
            'archiveoutcome' => 'privacy:metadata:scans:archiveoutcome',
            'component' => 'privacy:metadata:scans:component',
            'filearea' => 'privacy:metadata:scans:filearea',
            'itemid' => 'privacy:metadata:scans:itemid',
            'contenthash' => 'privacy:metadata:scans:contenthash',
            'pathnamehash' => 'privacy:metadata:scans:pathnamehash',
            'fileid' => 'privacy:metadata:scans:fileid',
            'sha256' => 'privacy:metadata:scans:sha256',
            'filesize' => 'privacy:metadata:scans:filesize',
            'mimetype' => 'privacy:metadata:scans:mimetype',
            'source' => 'privacy:metadata:scans:source',
            'status' => 'privacy:metadata:scans:status',
            'phase' => 'privacy:metadata:scans:phase',
            'vtanalysisid' => 'privacy:metadata:scans:vtanalysisid',
            'vtfileid' => 'privacy:metadata:scans:vtfileid',
            'malicious' => 'privacy:metadata:scans:malicious',
            'suspicious' => 'privacy:metadata:scans:suspicious',
            'undetected' => 'privacy:metadata:scans:undetected',
            'harmless' => 'privacy:metadata:scans:harmless',
            'timeout' => 'privacy:metadata:scans:timeout',
            'totalengines' => 'privacy:metadata:scans:totalengines',
            'errorcode' => 'privacy:metadata:scans:errorcode',
            'enforcement' => 'privacy:metadata:scans:enforcement',
            'pollattempts' => 'privacy:metadata:scans:pollattempts',
            'timelastpoll' => 'privacy:metadata:scans:timelastpoll',
            'timecreated' => 'privacy:metadata:scans:timecreated',
            'timemodified' => 'privacy:metadata:scans:timemodified',
            'timesubmitted' => 'privacy:metadata:scans:timesubmitted',
            'timecompleted' => 'privacy:metadata:scans:timecompleted',
        ], 'privacy:metadata:scans');

        $collection->add_external_location_link('virustotal', [
            'filecontent' => 'privacy:metadata:virustotal:filecontent',
            'filename' => 'privacy:metadata:virustotal:filename',
            'sha256' => 'privacy:metadata:virustotal:sha256',
            'filesize' => 'privacy:metadata:virustotal:filesize',
        ], 'privacy:metadata:virustotal');

        $collection->add_subsystem_link('core_files', [], 'privacy:metadata:core_files');

        return $collection;
    }

    /**
     * Get contexts that contain user data.
     *
     * @param int $userid User id.
     * @return contextlist
     */
    public static function get_contexts_for_userid(int $userid): contextlist {
        global $DB;

        $contextlist = new contextlist();
        $sql = "SELECT DISTINCT contextid
                  FROM {antivirus_verdict_scans}
                 WHERE userid = :userid OR initiatedby = :initiatedby";
        $contextlist->add_from_sql($sql, ['userid' => $userid, 'initiatedby' => $userid]);

        [$areasql, $areaparams] = $DB->get_in_or_equal(
            plugin_file_lifecycle::copy_fileareas(),
            \SQL_PARAMS_NAMED,
            'farea'
        );
        $filesql = "SELECT DISTINCT contextid
                      FROM {files}
                     WHERE component = :component
                       AND filearea {$areasql}
                       AND userid = :fileuserid
                       AND filename <> :dot";
        $contextlist->add_from_sql($filesql, $areaparams + [
            'component' => plugin_file_lifecycle::COMPONENT,
            'fileuserid' => $userid,
            'dot' => '.',
        ]);
        return $contextlist;
    }

    /**
     * Get users who have data in a context.
     *
     * @param userlist $userlist User list to populate.
     */
    public static function get_users_in_context(userlist $userlist): void {
        global $DB;

        $context = $userlist->get_context();
        $sql = "SELECT userid AS userid
                  FROM {antivirus_verdict_scans}
                 WHERE contextid = :contextid
                   AND userid <> 0";
        $userlist->add_from_sql('userid', $sql, ['contextid' => $context->id]);
        $initiatedsql = "SELECT initiatedby AS userid
                           FROM {antivirus_verdict_scans}
                          WHERE contextid = :contextid2
                            AND initiatedby <> 0";
        $userlist->add_from_sql('userid', $initiatedsql, ['contextid2' => $context->id]);

        [$areasql, $areaparams] = $DB->get_in_or_equal(
            plugin_file_lifecycle::copy_fileareas(),
            \SQL_PARAMS_NAMED,
            'farea'
        );
        $filesql = "SELECT userid
                      FROM {files}
                     WHERE contextid = :filecontextid
                       AND component = :component
                       AND filearea {$areasql}
                       AND userid <> 0
                       AND filename <> :dot";
        $userlist->add_from_sql('userid', $filesql, $areaparams + [
            'filecontextid' => $context->id,
            'component' => plugin_file_lifecycle::COMPONENT,
            'dot' => '.',
        ]);
    }

    /**
     * Export user data for the approved contexts.
     *
     * @param approved_contextlist $contextlist Approved contexts.
     */
    public static function export_user_data(approved_contextlist $contextlist): void {
        global $DB;

        if ($contextlist->count() === 0) {
            return;
        }

        $userid = $contextlist->get_user()->id;
        $contextids = $contextlist->get_contextids();
        [$insql, $params] = $DB->get_in_or_equal($contextids, \SQL_PARAMS_NAMED);
        $params['userid'] = $userid;

        $records = $DB->get_records_select(
            'antivirus_verdict_scans',
            "(userid = :userid OR initiatedby = :initiatedby) AND contextid {$insql}",
            $params + ['initiatedby' => $userid],
            'timecreated ASC'
        );

        $copyareas = plugin_file_lifecycle::copy_fileareas();
        $exporteditemids = [];
        foreach ($records as $record) {
            $context = \context::instance_by_id($record->contextid, \IGNORE_MISSING);
            if (!$context) {
                continue;
            }

            $subcontext = [get_string('privacy:path:scans', 'antivirus_verdict'), $record->id];
            writer::with_context($context)->export_data($subcontext, self::exportable_scan($record));
            $filearea = (string) $record->filearea;
            if ($record->component === plugin_file_lifecycle::COMPONENT && in_array($filearea, $copyareas, true)) {
                writer::with_context($context)->export_area_files(
                    $subcontext,
                    plugin_file_lifecycle::COMPONENT,
                    $filearea,
                    (int) $record->itemid
                );
                $exporteditemids[$filearea][(int) $record->itemid] = true;
            }
        }

        self::export_leftover_copies($contextlist, $userid, $exporteditemids);
    }

    /**
     * Delete all plugin data for a context.
     *
     * @param \context $context Context.
     */
    public static function delete_data_for_all_users_in_context(\context $context): void {
        self::delete_scans_and_members('contextid = :contextid', ['contextid' => $context->id]);
        foreach (plugin_file_lifecycle::copy_fileareas() as $filearea) {
            try {
                get_file_storage()->delete_area_files(
                    $context->id,
                    plugin_file_lifecycle::COMPONENT,
                    $filearea
                );
            } catch (\Throwable $e) {
                debugging($e->getMessage(), \DEBUG_DEVELOPER);
            }
        }
    }

    /**
     * Delete a user's plugin data in the approved contexts.
     *
     * @param approved_contextlist $contextlist Approved contexts.
     */
    public static function delete_data_for_user(approved_contextlist $contextlist): void {
        if ($contextlist->count() === 0) {
            return;
        }

        $userid = $contextlist->get_user()->id;
        foreach ($contextlist->get_contexts() as $context) {
            self::delete_scans_and_members(
                'contextid = :contextid AND (userid = :userid OR initiatedby = :initiatedby)',
                [
                    'contextid' => $context->id,
                    'userid' => $userid,
                    'initiatedby' => $userid,
                ]
            );
            self::delete_copies_for_user($context, $userid);
        }
    }

    /**
     * Delete plugin data for multiple users in a context.
     *
     * @param approved_userlist $userlist Approved users.
     */
    public static function delete_data_for_users(approved_userlist $userlist): void {
        global $DB;

        $userids = $userlist->get_userids();
        if (empty($userids)) {
            return;
        }

        $context = $userlist->get_context();
        [$insql, $params] = $DB->get_in_or_equal($userids, \SQL_PARAMS_NAMED);
        $params['contextid'] = $context->id;
        self::delete_scans_and_members(
            "contextid = :contextid AND (userid {$insql} OR initiatedby {$insql})",
            $params
        );
        foreach ($userids as $userid) {
            self::delete_copies_for_user($context, (int) $userid);
        }
    }

    /**
     * Export user-facing scan metadata without secrets or internals.
     *
     * @param \stdClass $record Scan row.
     * @return \stdClass
     */
    private static function exportable_scan(\stdClass $record): \stdClass {
        $data = (object) [
            'filename' => $record->filename,
            'submissionid' => !empty($record->submissionid) ? (int) $record->submissionid : null,
            'source' => scan_presenter::source_label((string) $record->source),
            'status' => scan_presenter::status_label((string) $record->status),
            'filesize' => $record->filesize,
            'mimetype' => $record->mimetype,
            'sha256' => $record->sha256,
            'timecreated' => transform::datetime($record->timecreated),
            'timemodified' => transform::datetime($record->timemodified),
            'timesubmitted' => !empty($record->timesubmitted) ? transform::datetime($record->timesubmitted) : '',
            'timecompleted' => !empty($record->timecompleted) ? transform::datetime($record->timecompleted) : '',
        ];

        $counts = ['malicious', 'suspicious', 'undetected', 'harmless', 'timeout', 'totalengines'];
        foreach ($counts as $field) {
            if ($record->{$field} !== null) {
                $data->{$field} = $record->{$field};
            }
        }

        $detection = scan_presenter::detection_label($record);
        if ($detection !== '') {
            $data->result = $detection;
        }

        $outcome = scan_presenter::outcome_message($record);
        if ($outcome !== '' && $record->status !== scan_status::PENDING) {
            $data->error = $outcome;
        }

        $enforcement = scan_presenter::enforcement_label((string) ($record->enforcement ?? ''));
        if ($enforcement !== '') {
            $data->enforcement = $enforcement;
        }

        if (!empty($record->initiatedby)) {
            $data->initiatedby = transform::user($record->initiatedby);
        }

        if ((int) ($record->parentscanid ?? 0) > 0) {
            $data->parentscanid = (int) $record->parentscanid;
        }
        $archiveoutcome = trim((string) ($record->archiveoutcome ?? ''));
        if ($archiveoutcome !== '') {
            $data->archiveoutcome = $archiveoutcome;
        }

        return $data;
    }

    /**
     * Delete the selected scans and any member rows that belong to them.
     *
     * Member rows are stored in the system context, so deleting only the
     * container's course context would leave them behind.
     *
     * @param string $select SQL select for the parent rows.
     * @param array $params Select parameters.
     */
    private static function delete_scans_and_members(string $select, array $params): void {
        global $DB;

        $parentids = $DB->get_fieldset_select('antivirus_verdict_scans', 'id', $select, $params);
        if (!$parentids) {
            return;
        }
        self::delete_member_rows($parentids);
        [$insql, $inparams] = $DB->get_in_or_equal($parentids, \SQL_PARAMS_NAMED, 'scanid');
        $DB->delete_records_select('antivirus_verdict_scans', "id {$insql}", $inparams);
    }

    /**
     * Delete member scans for the given container ids, including their plugin copies.
     *
     * @param int[] $parentids Container scan ids.
     */
    private static function delete_member_rows(array $parentids): void {
        global $DB;

        [$insql, $params] = $DB->get_in_or_equal($parentids, \SQL_PARAMS_NAMED, 'pid');
        $children = $DB->get_records_select('antivirus_verdict_scans', "parentscanid {$insql}", $params);
        foreach ($children as $child) {
            try {
                plugin_file_lifecycle::delete_copy_for_scan($child);
            } catch (\Throwable $e) {
                debugging($e->getMessage(), \DEBUG_DEVELOPER);
            }
        }
        if ($children) {
            $DB->delete_records_select('antivirus_verdict_scans', "parentscanid {$insql}", $params);
        }
    }

    /**
     * Export plugin-owned copies that are not already attached to a scan row.
     *
     * Covers every area in plugin_file_lifecycle::copy_fileareas(), so manual
     * scan copies and gate copies of in-flight uploads are both exported.
     * Copies owned by other users are skipped.
     *
     * @param approved_contextlist $contextlist Approved contexts.
     * @param int $userid User id.
     * @param array<string,array<int,bool>> $exporteditemids Item ids already exported with a scan, keyed by file area.
     */
    private static function export_leftover_copies(
        approved_contextlist $contextlist,
        int $userid,
        array $exporteditemids
    ): void {
        $fs = get_file_storage();
        $path = get_string('privacy:path:copies', 'antivirus_verdict');
        foreach ($contextlist->get_contexts() as $context) {
            foreach (plugin_file_lifecycle::copy_fileareas() as $filearea) {
                $files = $fs->get_area_files(
                    $context->id,
                    plugin_file_lifecycle::COMPONENT,
                    $filearea,
                    false,
                    'id',
                    false
                );
                foreach ($files as $file) {
                    if ((int) $file->get_userid() !== $userid || $file->is_directory()) {
                        continue;
                    }
                    $itemid = (int) $file->get_itemid();
                    if (isset($exporteditemids[$filearea][$itemid])) {
                        continue;
                    }
                    writer::with_context($context)->export_area_files(
                        [$path, $filearea],
                        plugin_file_lifecycle::COMPONENT,
                        $filearea,
                        $itemid
                    );
                    $exporteditemids[$filearea][$itemid] = true;
                }
            }
        }
    }

    /**
     * Delete plugin-owned copies for one user in a context.
     *
     * Covers manual scan copies and gate copies. Assignment submission files
     * and other Moodle component files are never deleted here, and copies
     * owned by another user or by no user are left alone. Missing copies are
     * ignored.
     *
     * @param \context $context Context.
     * @param int $userid User id.
     */
    private static function delete_copies_for_user(\context $context, int $userid): void {
        $fs = get_file_storage();
        foreach (plugin_file_lifecycle::copy_fileareas() as $filearea) {
            $files = $fs->get_area_files(
                $context->id,
                plugin_file_lifecycle::COMPONENT,
                $filearea,
                false,
                'id',
                false
            );
            foreach ($files as $file) {
                if ((int) $file->get_userid() !== $userid || $file->is_directory()) {
                    continue;
                }
                try {
                    $file->delete();
                } catch (\Throwable $e) {
                    debugging($e->getMessage(), \DEBUG_DEVELOPER);
                }
            }
        }
    }
}
