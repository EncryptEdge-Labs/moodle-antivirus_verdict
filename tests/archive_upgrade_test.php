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

namespace antivirus_verdict;

use antivirus_verdict\local\scan_repository;


/**
 * Tests for archive-related upgrade steps.
 *
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @covers ::xmldb_antivirus_verdict_upgrade
 */
final class archive_upgrade_test extends \advanced_testcase {
    /**
     * Fresh installs and upgrades include archive parent/child columns.
     */
    public function test_archive_columns_exist(): void {
        global $DB;
        $this->resetAfterTest();
        $dbman = $DB->get_manager();
        $table = new \xmldb_table(scan_repository::TABLE);
        $parent = new \xmldb_field('parentscanid', XMLDB_TYPE_INTEGER, '10', null, XMLDB_NOTNULL, null, '0', 'timecompleted');
        $outcome = new \xmldb_field('archiveoutcome', XMLDB_TYPE_CHAR, '20', null, null, null, null, 'parentscanid');
        $index = new \xmldb_index('parentscanid', XMLDB_INDEX_NOTUNIQUE, ['parentscanid']);

        $this->assertTrue($dbman->field_exists($table, $parent));
        $this->assertTrue($dbman->field_exists($table, $outcome));
        $this->assertTrue($dbman->index_exists($table, $index));
    }
}
