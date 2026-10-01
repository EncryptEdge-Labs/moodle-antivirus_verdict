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
 * Scan history filter form.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\form;

defined('MOODLE_INTERNAL') || die();

use antivirus_verdict\scan_source;
use antivirus_verdict\scan_status;


global $CFG;
require_once($CFG->libdir . '/formslib.php');

/**
 * GET filters for status, source, and filename.
 */
class history_filter_form extends \moodleform {
    /**
     * Form definition.
     */
    protected function definition(): void {
        $mform = $this->_form;
        $mform->setDisableShortforms(true);
        $mform->updateAttributes(['class' => 'mform full-width-labels antivirus-verdict-filter-mform']);

        $statuses = ['' => get_string('filterall', 'antivirus_verdict')];
        foreach (scan_status::all() as $status) {
            $statuses[$status] = get_string('status_' . $status, 'antivirus_verdict');
        }
        $sources = ['' => get_string('filterall', 'antivirus_verdict')];
        foreach (scan_source::all() as $source) {
            $sources[$source] = get_string('source_' . $source, 'antivirus_verdict');
        }

        $fields = [];
        $fields[] = $mform->createElement('select', 'status', get_string('filterstatus', 'antivirus_verdict'), $statuses);
        $fields[] = $mform->createElement('select', 'source', get_string('filtersource', 'antivirus_verdict'), $sources);
        $fields[] = $mform->createElement('text', 'filename', get_string('filterfilename', 'antivirus_verdict'), [
            'placeholder' => get_string('filterfilenameplaceholder', 'antivirus_verdict'),
        ]);
        $fields[] = $mform->createElement('submit', 'submitbutton', get_string('filterapply', 'antivirus_verdict'));
        $mform->addGroup($fields, 'filterrow', '', '', false);
        $mform->setType('status', \PARAM_ALPHA);
        $mform->setType('source', \PARAM_ALPHA);
        $mform->setType('filename', \PARAM_NOTAGS);

        if (!empty($this->_customdata['courseid'])) {
            $mform->addElement('hidden', 'courseid', (int) $this->_customdata['courseid']);
            $mform->setType('courseid', \PARAM_INT);
        }
    }
}
