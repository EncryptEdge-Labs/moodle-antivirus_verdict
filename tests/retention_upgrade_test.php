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
 * Tests for the retention-related upgrade step.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\scan_repository;


/**
 * timecompleted index upgrade.
 *
 * @covers ::xmldb_antivirus_verdict_upgrade
 */
final class retention_upgrade_test extends \advanced_testcase {
    /** Version that added the timecompleted index. */
    private const RETENTION_VERSION = 2026092200;

    /**
     * Upgrade adds the timecompleted index when missing.
     */
    public function test_upgrade_adds_timecompleted_index(): void {
        global $CFG, $DB;

        $this->resetAfterTest();
        require_once($CFG->libdir . '/upgradelib.php');
        require_once($CFG->dirroot . '/lib/antivirus/verdict/db/upgrade.php');

        $dbman = $DB->get_manager();
        $table = new \xmldb_table(scan_repository::TABLE);
        $index = new \xmldb_index('timecompleted', XMLDB_INDEX_NOTUNIQUE, ['timecompleted']);

        try {
            if ($dbman->index_exists($table, $index)) {
                $dbman->drop_index($table, $index);
            }
            $this->assertFalse($dbman->index_exists($table, $index));

            set_config('version', self::RETENTION_VERSION - 1, 'antivirus_verdict');
            $this->assertTrue(xmldb_antivirus_verdict_upgrade(self::RETENTION_VERSION - 1));
            $this->assertTrue($dbman->index_exists($table, $index));
        } finally {
            if (!$dbman->index_exists($table, $index)) {
                $dbman->add_index($table, $index);
            }
        }
    }
}
