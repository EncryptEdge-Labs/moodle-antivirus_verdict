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
 * Plugin upgrade steps for antivirus_verdict.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */


/**
 * Upgrade the antivirus_verdict plugin.
 *
 * @param int $oldversion The version we are upgrading from.
 * @return bool
 */
function xmldb_antivirus_verdict_upgrade($oldversion) {
    global $CFG, $DB;

    $dbman = $DB->get_manager();

    if ($oldversion < 2026092100) {
        // Records the outcome of post-upload enforcement for a malicious
        // verdict. Existing rows keep the empty state, which is correct:
        // verdicts reached before this release were never enforced.
        $table = new xmldb_table('antivirus_verdict_scans');
        $field = new xmldb_field('enforcement', XMLDB_TYPE_CHAR, '20', null, XMLDB_NOTNULL, null, 'none', 'errorcode');
        if (!$dbman->field_exists($table, $field)) {
            $dbman->add_field($table, $field);
        }
        $index = new xmldb_index('enforcement', XMLDB_INDEX_NOTUNIQUE, ['enforcement']);
        if (!$dbman->index_exists($table, $index)) {
            $dbman->add_index($table, $index);
        }

        upgrade_plugin_savepoint(true, 2026092100, 'antivirus', 'verdict');
    }

    if ($oldversion < 2026092200) {
        $table = new xmldb_table('antivirus_verdict_scans');
        $index = new xmldb_index('timecompleted', XMLDB_INDEX_NOTUNIQUE, ['timecompleted']);
        if (!$dbman->index_exists($table, $index)) {
            $dbman->add_index($table, $index);
        }

        upgrade_plugin_savepoint(true, 2026092200, 'antivirus', 'verdict');
    }

    if ($oldversion < 2026092300) {
        // Commercial 1.0 wave: coverage registry consumers, bulk/restore sweeps,
        // archive member scanning, and Moodle message providers. No schema change.
        upgrade_plugin_savepoint(true, 2026092300, 'antivirus', 'verdict');
    }

    if ($oldversion < 2026092400) {
        upgrade_plugin_savepoint(true, 2026092400, 'antivirus', 'verdict');
    }

    if ($oldversion < 2026092410) {
        $table = new xmldb_table('antivirus_verdict_scans');
        $parent = new xmldb_field(
            'parentscanid',
            XMLDB_TYPE_INTEGER,
            '10',
            null,
            XMLDB_NOTNULL,
            null,
            '0',
            'timecompleted'
        );
        if (!$dbman->field_exists($table, $parent)) {
            $dbman->add_field($table, $parent);
        }
        $outcome = new xmldb_field(
            'archiveoutcome',
            XMLDB_TYPE_CHAR,
            '20',
            null,
            null,
            null,
            null,
            'parentscanid'
        );
        if (!$dbman->field_exists($table, $outcome)) {
            $dbman->add_field($table, $outcome);
        }
        $index = new xmldb_index('parentscanid', XMLDB_INDEX_NOTUNIQUE, ['parentscanid']);
        if (!$dbman->index_exists($table, $index)) {
            $dbman->add_index($table, $index);
        }

        upgrade_plugin_savepoint(true, 2026092410, 'antivirus', 'verdict');
    }

    if ($oldversion < 2026092500) {
        $table = new xmldb_table('antivirus_verdict_scans');
        $initiatedby = new xmldb_field(
            'initiatedby',
            XMLDB_TYPE_INTEGER,
            '10',
            null,
            XMLDB_NOTNULL,
            null,
            '0',
            'userid'
        );
        if (!$dbman->field_exists($table, $initiatedby)) {
            $dbman->add_field($table, $initiatedby);
        }
        $submissionid = new xmldb_field(
            'submissionid',
            XMLDB_TYPE_INTEGER,
            '10',
            null,
            XMLDB_NOTNULL,
            null,
            '0',
            'initiatedby'
        );
        if (!$dbman->field_exists($table, $submissionid)) {
            $dbman->add_field($table, $submissionid);
        }
        $index = new xmldb_index('submissionid', XMLDB_INDEX_NOTUNIQUE, ['submissionid']);
        if (!$dbman->index_exists($table, $index)) {
            $dbman->add_index($table, $index);
        }

        upgrade_plugin_savepoint(true, 2026092500, 'antivirus', 'verdict');
    }

    if ($oldversion < 2026092501) {
        // Raise the previous 32 MB site default to 100 MB. Administrators who
        // already chose a different limit keep that value (clamped to 1–100).
        $current = get_config('antivirus_verdict', 'maxfilesize');
        if ($current === false || $current === '' || (int) $current === 32) {
            set_config('maxfilesize', \antivirus_verdict\local\plugin_config::DEFAULT_MAX_MB, 'antivirus_verdict');
        } else {
            set_config(
                'maxfilesize',
                \antivirus_verdict\local\plugin_config::normalise_max_mb((int) $current),
                'antivirus_verdict'
            );
        }

        upgrade_plugin_savepoint(true, 2026092501, 'antivirus', 'verdict');
    }

    if ($oldversion < 2026092800) {
        $table = new xmldb_table('antivirus_verdict_opcounts');
        if (!$dbman->table_exists($table)) {
            $dbman->install_one_table_from_xmldb_file(
                $CFG->dirroot . '/lib/antivirus/verdict/db/install.xml',
                'antivirus_verdict_opcounts'
            );
        }
        \antivirus_verdict\local\operation_counts::install_row();

        upgrade_plugin_savepoint(true, 2026092800, 'antivirus', 'verdict');
    }

    if ($oldversion < 2026092801) {
        $table = new xmldb_table('antivirus_verdict_opreserve');
        if (!$dbman->table_exists($table)) {
            $dbman->install_one_table_from_xmldb_file(
                $CFG->dirroot . '/lib/antivirus/verdict/db/install.xml',
                'antivirus_verdict_opreserve'
            );
        }
        \antivirus_verdict\local\operation_reservation::install_row();

        upgrade_plugin_savepoint(true, 2026092801, 'antivirus', 'verdict');
    }

    return true;
}
