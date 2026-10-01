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
 * Confirm a deliberate rescan from Scan detail.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\form;

defined('MOODLE_INTERNAL') || die();

global $CFG;
require_once($CFG->libdir . '/formslib.php');

/**
 * POST + sesskey action. Submits only the existing scan id.
 */
class rescan_form extends \moodleform {
    /**
     * Form definition.
     */
    protected function definition(): void {
        $mform = $this->_form;
        $id = (int) ($this->_customdata['id'] ?? 0);
        $mform->setDisableShortforms(true);
        $mform->updateAttributes(['class' => 'mform antivirus-verdict-scan-mform']);

        $mform->addElement(
            'html',
            \html_writer::tag('p', get_string('rescanintro', 'antivirus_verdict'), [
                'class' => 'antivirus-verdict-copy',
            ])
        );
        $mform->addElement('hidden', 'id', $id);
        $mform->setType('id', \PARAM_INT);
        $this->add_action_buttons(false, get_string('rescanfile', 'antivirus_verdict'));
    }
}
