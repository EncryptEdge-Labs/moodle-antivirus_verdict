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
 * Bulk retrospective scan form.
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
 * Course picker for bulk scanning.
 */
class bulk_scan_form extends \moodleform {
    /**
     * Define form fields.
     */
    protected function definition() {
        $mform = $this->_form;
        $courses = $this->_customdata['courses'] ?? [];
        $mform->setDisableShortforms(true);
        $mform->updateAttributes(['class' => 'mform antivirus-verdict-scan-mform']);

        if ($courses === []) {
            $mform->addElement(
                'html',
                \html_writer::div(get_string('bulkscanempty', 'antivirus_verdict'), 'antivirus-verdict-banner', [
                    'role' => 'status',
                ])
            );
            return;
        }
        $mform->addElement('select', 'courseid', get_string('bulkscancourse', 'antivirus_verdict'), $courses);
        $mform->addElement(
            'html',
            \html_writer::tag(
                'p',
                get_string('bulkscancoursecount', 'antivirus_verdict', count($courses)),
                ['class' => 'antivirus-verdict-field-hint']
            )
        );
        $mform->addElement(
            'advcheckbox',
            'onlymissing',
            '',
            get_string('bulkscanonlymissing', 'antivirus_verdict'),
            ['group' => 1],
            [0, 1]
        );
        $mform->setDefault('onlymissing', 1);
        $mform->addElement(
            'html',
            \html_writer::tag(
                'p',
                get_string('bulkscanonlymissing_desc', 'antivirus_verdict'),
                ['class' => 'antivirus-verdict-field-hint']
            )
        );

        $this->add_action_buttons(false, get_string('bulkscanqueue', 'antivirus_verdict'));
    }

    /**
     * Require a course when any courses are available to scan.
     *
     * @param array $data Submitted values.
     * @param array $files Unused Moodle files array.
     * @return array
     */
    public function validation($data, $files): array {
        $errors = parent::validation($data, $files);
        $courses = $this->_customdata['courses'] ?? [];
        if ($courses !== [] && (int) ($data['courseid'] ?? 0) <= 0) {
            $errors['courseid'] = get_string('error_invalidrequest', 'antivirus_verdict');
        }
        return $errors;
    }
}
