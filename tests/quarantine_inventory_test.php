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
 * Tests for quarantine inventory.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\quarantine_inventory;
use antivirus_verdict\local\scan_repository;
use antivirus_verdict\output\quarantine_page;


/**
 * Inventory heading must match the table query.
 *
 * @covers \antivirus_verdict\local\quarantine_inventory
 * @covers \antivirus_verdict\output\quarantine_page
 */
final class quarantine_inventory_test extends \advanced_testcase {
    /**
     * Summary returns expected keys.
     */
    public function test_summary_shape(): void {
        $this->resetAfterTest();
        $summary = quarantine_inventory::from_site_config()->summary();
        $this->assertArrayHasKey('quarantined', $summary);
        $this->assertArrayHasKey('malicious', $summary);
        $this->assertArrayHasKey('coreenabled', $summary);
    }

    /**
     * Heading count matches the inventory table dataset, including reported outcomes.
     */
    public function test_heading_count_matches_inventory_rows(): void {
        global $PAGE;

        $this->resetAfterTest();
        $repo = new scan_repository();
        $repo->insert($this->inventory_row('reported.bin', enforcement_state::REPORTED));
        $repo->insert($this->inventory_row('clean.bin', enforcement_state::NONE, scan_status::CLEAN));

        $inventory = new quarantine_inventory($repo);
        $rows = $inventory->rows(100);
        $summary = $inventory->summary();
        $this->assertCount(1, $rows);
        $this->assertSame(1, $summary['quarantined']);
        $this->assertSame('reported.bin', $rows[0]['filename']);

        $PAGE->set_url(new \moodle_url('/lib/antivirus/verdict/quarantine.php'));
        $PAGE->set_context(\context_system::instance());
        $exported = (new quarantine_page($inventory))->export_for_template($PAGE->get_renderer('antivirus_verdict'));
        $this->assertSame(1, $exported['quarantinedcount']);
        $this->assertFalse($exported['isempty']);
        $this->assertCount(1, $exported['rows']);
    }

    /**
     * Minimal scan row for inventory tests.
     *
     * @param string $filename Filename.
     * @param string $enforcement Enforcement state.
     * @param string $status Scan status.
     * @return \stdClass
     */
    private function inventory_row(
        string $filename,
        string $enforcement,
        string $status = scan_status::MALICIOUS
    ): \stdClass {
        $now = time();
        $row = new \stdClass();
        $row->fileid = 0;
        $row->contenthash = null;
        $row->pathnamehash = '';
        $row->contextid = \context_system::instance()->id;
        $row->courseid = 0;
        $row->component = 'user';
        $row->filearea = 'draft';
        $row->itemid = 0;
        $row->filepath = '/';
        $row->filename = $filename;
        $row->userid = 2;
        $row->source = scan_source::MANUAL;
        $row->sha256 = hash('sha256', $filename);
        $row->filesize = 4;
        $row->mimetype = null;
        $row->status = $status;
        $row->phase = scan_phase::COMPLETED;
        $row->vtanalysisid = null;
        $row->vtfileid = null;
        $row->malicious = $status === scan_status::MALICIOUS ? 1 : 0;
        $row->suspicious = 0;
        $row->undetected = 0;
        $row->harmless = 0;
        $row->timeout = 0;
        $row->totalengines = 0;
        $row->errorcode = null;
        $row->enforcement = $enforcement;
        $row->pollattempts = 0;
        $row->timelastpoll = 0;
        $row->timesubmitted = 0;
        $row->timecreated = $now;
        $row->timemodified = $now;
        $row->timecompleted = $now;
        $row->parentscanid = 0;
        return $row;
    }
}
