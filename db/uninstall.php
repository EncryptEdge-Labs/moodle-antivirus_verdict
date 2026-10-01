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
 * Uninstall steps for antivirus_verdict.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */


/**
 * Remove plugin-owned File API copies. Moodle drops plugin tables separately.
 *
 * Assignment submission files and other Moodle component files are not deleted.
 *
 * @return bool
 */
function xmldb_antivirus_verdict_uninstall() {
    global $DB;

    if (!$DB->get_manager()->table_exists('files')) {
        return true;
    }

    $fs = get_file_storage();
    $component = \antivirus_verdict\local\plugin_file_lifecycle::COMPONENT;
    $sql = "SELECT DISTINCT contextid
              FROM {files}
             WHERE component = :component
               AND filearea = :filearea";
    foreach (\antivirus_verdict\local\plugin_file_lifecycle::copy_fileareas() as $filearea) {
        $contextids = $DB->get_fieldset_sql($sql, [
            'component' => $component,
            'filearea' => $filearea,
        ]);
        foreach ($contextids as $contextid) {
            $fs->delete_area_files((int) $contextid, $component, $filearea);
        }
    }

    return true;
}
