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
 * Quarantine inventory templatable.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\output;

use antivirus_verdict\local\quarantine_inventory;
use renderer_base;


/**
 * Administrator view of Verdict enforcement correlated with core quarantine.
 */
class quarantine_page implements \renderable, \templatable {
    /** @var quarantine_inventory Inventory service. */
    private quarantine_inventory $inventory;

    /**
     * Internal helper.
     *
     * @param quarantine_inventory $inventory Inventory service.
     */
    public function __construct(quarantine_inventory $inventory) {
        $this->inventory = $inventory;
    }

    /**
     * Internal helper.
     *
     * @param renderer_base $output Renderer.
     * @return array
     */
    public function export_for_template(renderer_base $output): array {
        $summary = $this->inventory->summary();
        $rows = $this->inventory->rows(100);
        return [
            'pagetitle' => get_string('quarantineheading', 'antivirus_verdict'),
            'pagesubtitle' => get_string('quarantinesubtitle', 'antivirus_verdict'),
            'coreenabled' => $summary['coreenabled'],
            'coredisabledmessage' => get_string('quarantinecoredisabled', 'antivirus_verdict'),
            'corereportlabel' => get_string('quarantinecorereport', 'antivirus_verdict'),
            'corereporturl' => $this->inventory->core_report_url()->out(false),
            'quarantinedcount' => $summary['quarantined'],
            'maliciouscount' => $summary['malicious'],
            'rows' => $rows,
            'isempty' => $rows === [],
            'emptymessage' => get_string('quarantineempty', 'antivirus_verdict'),
            'columnfile' => get_string('columnfilename', 'antivirus_verdict'),
            'columnstatus' => get_string('columnstatus', 'antivirus_verdict'),
            'columnenforcement' => get_string('enforcementheading', 'antivirus_verdict'),
            'columntime' => get_string('columntimecompleted', 'antivirus_verdict'),
            'columncore' => get_string('quarantinecorematch', 'antivirus_verdict'),
            'viewlabel' => get_string('viewdetails', 'antivirus_verdict'),
        ];
    }
}
