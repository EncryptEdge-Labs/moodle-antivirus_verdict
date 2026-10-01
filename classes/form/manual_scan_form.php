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
 * Manual scan request form.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\form;

defined('MOODLE_INTERNAL') || die();

global $CFG;
require_once($CFG->libdir . '/formslib.php');
require_once($CFG->dirroot . '/repository/lib.php');

/**
 * Moodle file picker for a single stored file. POST + sesskey.
 */
class manual_scan_form extends \moodleform {
    /**
     * Form definition.
     */
    protected function definition(): void {
        $mform = $this->_form;
        $maxbytes = (int) ($this->_customdata['maxbytes'] ?? 0);
        $mform->setDisableShortforms(true);
        $mform->updateAttributes(['class' => 'mform antivirus-verdict-scan-mform']);

        $mform->addElement(
            'html',
            \html_writer::tag('p', get_string('manualscan_intro', 'antivirus_verdict'), [
                'class' => 'antivirus-verdict-field-hint',
            ])
        );
        $mform->addElement('html', $this->dropzone_html());
        $mform->addElement(
            'filepicker',
            'scanfile',
            get_string('scanfile', 'antivirus_verdict'),
            null,
            [
                'maxbytes' => $maxbytes,
                'accepted_types' => '*',
                'return_types' => \FILE_INTERNAL,
            ]
        );
        $mform->addElement(
            'html',
            \html_writer::div(
                \html_writer::span('●', 'antivirus-verdict-req-dot') . ' ' .
                    get_string('scanfilerequired', 'antivirus_verdict'),
                'antivirus-verdict-required-flag'
            ) . \html_writer::empty_tag('hr', ['class' => 'antivirus-verdict-rule-line'])
        );
        $this->add_action_buttons(false, get_string('scanfilebutton', 'antivirus_verdict'));
    }

    /**
     * Decorative drop-zone copy. The filepicker remains the real control.
     *
     * @return string
     */
    private function dropzone_html(): string {
        $icon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">' .
            '<path d="M12 4v11M7 10l5 5 5-5"/>' .
            '<path d="M5 20h14"/>' .
            '</svg>';
        return \html_writer::div(
            $icon .
            \html_writer::div(
                \html_writer::span(get_string('dropzoneprefix', 'antivirus_verdict'), 'antivirus-verdict-dz-drag') . ' ' .
                \html_writer::tag('button', get_string('dropzonechoose', 'antivirus_verdict'), [
                    'type' => 'button',
                    'class' => 'antivirus-verdict-dz-choose',
                    'tabindex' => '-1',
                ]),
                'antivirus-verdict-dz-main'
            ) .
            \html_writer::div(get_string('dropzonesub', 'antivirus_verdict'), 'antivirus-verdict-dz-sub'),
            'antivirus-verdict-dropzone',
            [
                'role' => 'button',
                'tabindex' => '0',
                'aria-label' => get_string('dropzonemain', 'antivirus_verdict'),
            ]
        );
    }

    /**
     * Server-side validation that a Moodle draft file was selected.
     *
     * @param array $data Submitted values.
     * @param array $files Unused Moodle files array.
     * @return array
     */
    public function validation($data, $files): array {
        $errors = parent::validation($data, $files);
        $draftid = (int) ($data['scanfile'] ?? 0);
        if ($draftid <= 0) {
            $errors['scanfile'] = get_string('error_invalidfile', 'antivirus_verdict');
        }
        return $errors;
    }
}
