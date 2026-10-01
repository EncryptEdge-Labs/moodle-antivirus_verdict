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
 * Tests for the enforcement column upgrade step.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\scan_repository;


/**
 * The enforcement column is added by upgrade and matches install.xml.
 *
 * @covers ::xmldb_antivirus_verdict_upgrade
 */
final class enforcement_upgrade_test extends \advanced_testcase {
    /** Version that introduced the enforcement column. */
    private const ENFORCEMENT_VERSION = 2026092100;

    /**
     * An existing installation gains the column, and existing rows keep
     * the empty state rather than claiming an enforcement outcome.
     */
    public function test_upgrade_adds_the_enforcement_column(): void {
        global $CFG, $DB;
        $this->resetAfterTest();
        require_once($CFG->libdir . '/upgradelib.php');
        require_once($CFG->dirroot . '/lib/antivirus/verdict/db/upgrade.php');

        $dbman = $DB->get_manager();
        $table = new \xmldb_table(scan_repository::TABLE);
        $field = new \xmldb_field('enforcement', XMLDB_TYPE_CHAR, '20', null, XMLDB_NOTNULL, null, 'none', 'errorcode');
        $index = new \xmldb_index('enforcement', XMLDB_INDEX_NOTUNIQUE, ['enforcement']);

        try {
            if ($dbman->index_exists($table, $index)) {
                $dbman->drop_index($table, $index);
            }
            $dbman->drop_field($table, $field);
            $this->assertFalse($dbman->field_exists($table, $field));

            $rowid = $DB->insert_record(scan_repository::TABLE, $this->pre_upgrade_row());

            set_config('version', self::ENFORCEMENT_VERSION - 1, 'antivirus_verdict');
            $this->assertTrue(xmldb_antivirus_verdict_upgrade(self::ENFORCEMENT_VERSION - 1));

            $this->assertTrue($dbman->field_exists($table, $field));
            $this->assertTrue($dbman->index_exists($table, $index));
            $this->assertSame(
                enforcement_state::NONE,
                $DB->get_field(scan_repository::TABLE, 'enforcement', ['id' => $rowid])
            );
        } finally {
            // Never leave the shared test schema in a downgraded state.
            if (!$dbman->field_exists($table, $field)) {
                $dbman->add_field($table, $field);
            }
            if (!$dbman->index_exists($table, $index)) {
                $dbman->add_index($table, $index);
            }
        }
    }

    /**
     * Re-running the step on an already upgraded installation is harmless.
     */
    public function test_upgrade_step_is_repeatable(): void {
        global $CFG, $DB;
        $this->resetAfterTest();
        require_once($CFG->libdir . '/upgradelib.php');
        require_once($CFG->dirroot . '/lib/antivirus/verdict/db/upgrade.php');

        set_config('version', self::ENFORCEMENT_VERSION - 1, 'antivirus_verdict');
        $this->assertTrue(xmldb_antivirus_verdict_upgrade(self::ENFORCEMENT_VERSION - 1));

        $dbman = $DB->get_manager();
        $table = new \xmldb_table(scan_repository::TABLE);
        $this->assertTrue($dbman->field_exists($table, new \xmldb_field('enforcement')));
    }

    /**
     * Every enforcement outcome fits the stored column.
     */
    public function test_all_enforcement_states_persist(): void {
        global $DB;
        $this->resetAfterTest();

        foreach (enforcement_state::all() as $state) {
            $row = $this->pre_upgrade_row();
            $row->enforcement = $state;
            $id = $DB->insert_record(scan_repository::TABLE, $row);
            $this->assertSame($state, $DB->get_field(scan_repository::TABLE, 'enforcement', ['id' => $id]));
        }
    }

    /**
     * install.xml declares the same version as version.php.
     */
    public function test_install_xml_version_matches_version_php(): void {
        global $CFG;
        $plugin = new \stdClass();
        require($CFG->dirroot . '/lib/antivirus/verdict/version.php');

        $xml = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/db/install.xml');
        $this->assertSame(1, preg_match('/VERSION="(\d+)"/', $xml, $matches));
        $this->assertSame((int) $plugin->version, (int) $matches[1]);
    }

    /**
     * A scan row as it existed before the enforcement column.
     *
     * @return \stdClass
     */
    private function pre_upgrade_row(): \stdClass {
        $now = time();
        return (object) [
            'fileid' => 0,
            'contenthash' => '',
            'pathnamehash' => '',
            'contextid' => \context_system::instance()->id,
            'courseid' => 0,
            'component' => 'antivirus_verdict',
            'filearea' => 'gate',
            'itemid' => 0,
            'filepath' => '/',
            'filename' => 'legacy.bin',
            'userid' => 0,
            'source' => scan_source::ANTIVIRUS,
            'sha256' => str_repeat('d', 64),
            'filesize' => 10,
            'status' => scan_status::CLEAN,
            'phase' => scan_phase::COMPLETED,
            'pollattempts' => 0,
            'timelastpoll' => 0,
            'timesubmitted' => 0,
            'timecreated' => $now,
            'timemodified' => $now,
            'timecompleted' => $now,
        ];
    }
}
