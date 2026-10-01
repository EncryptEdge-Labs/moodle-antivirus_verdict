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
 * Bulk / retrospective course scan page.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

// phpcs:disable moodle.Files.MoodleInternal
require_once(__DIR__ . '/locatemoodle.php');
// phpcs:enable moodle.Files.MoodleInternal
defined('MOODLE_INTERNAL') || die();

global $USER;

$context = \antivirus_verdict\local\page::setup('bulk.php', 'bulkscanheading', 'antivirus/verdict:scan');

$service = \antivirus_verdict\local\bulk_scan_service::from_site_config();
$url = new moodle_url('/lib/antivirus/verdict/bulk.php');
$courses = \antivirus_verdict\local\scan_access::bulk_course_menu();
$form = new \antivirus_verdict\form\bulk_scan_form($url->out(false), ['courses' => $courses]);

if ($data = $form->get_data()) {
    require_sesskey();
    $courseid = (int) $data->courseid;
    $allowed = array_map('intval', array_keys($courses));
    if (!in_array($courseid, $allowed, true)) {
        throw new required_capability_exception(
            \context_course::instance($courseid),
            'antivirus/verdict:scan',
            'nopermissions',
            ''
        );
    }
    $onlymissing = !empty($data->onlymissing);
    if ($service->queue_course_sweep($courseid, (int) $USER->id, $onlymissing)) {
        redirect(
            $url,
            get_string('bulkscanqueued', 'antivirus_verdict'),
            null,
            \core\output\notification::NOTIFY_SUCCESS
        );
    }
    redirect(
        $url,
        get_string('bulkscanunavailable', 'antivirus_verdict'),
        null,
        \core\output\notification::NOTIFY_ERROR
    );
}

$renderer = $PAGE->get_renderer('antivirus_verdict');
echo $OUTPUT->header();
echo $renderer->plugin_tabs('bulkscan', $context);
echo html_writer::start_div('antivirus-verdict-page');
echo html_writer::start_div('antivirus-verdict-topline');
$bulktitle = html_writer::span('', 'antivirus-verdict-rule') . s(get_string('bulkscanheading', 'antivirus_verdict'));
echo html_writer::div(
    html_writer::tag('h1', $bulktitle, [
        'class' => 'antivirus-verdict-title',
    ]) .
    html_writer::tag('p', s(get_string('bulkscansubtitle', 'antivirus_verdict')), [
        'class' => 'antivirus-verdict-subtitle antivirus-verdict-subtitle--full',
    ]),
    'antivirus-verdict-titleblock'
);
echo html_writer::end_div();
echo html_writer::start_div('antivirus-verdict-panel antivirus-verdict-scanform');
echo html_writer::tag('p', s(get_string('bulkscanwarning', 'antivirus_verdict')), [
    'class' => 'antivirus-verdict-copy antivirus-verdict-note',
    'role' => 'note',
]);
if (!$service->can_start()) {
    echo html_writer::div(
        s(get_string('bulkscanunavailable', 'antivirus_verdict')),
        'antivirus-verdict-banner',
        ['role' => 'status']
    );
} else {
    $form->display();
}
echo html_writer::end_div();
echo html_writer::end_div();
echo $renderer->product_end();
echo $OUTPUT->footer();
