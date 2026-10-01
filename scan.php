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
 * Manual scan page for the antivirus_verdict plugin.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

// phpcs:disable moodle.Files.MoodleInternal
require_once(__DIR__ . '/locatemoodle.php');
// phpcs:enable moodle.Files.MoodleInternal
defined('MOODLE_INTERNAL') || die();
require_login();

$existingid = optional_param('id', 0, PARAM_INT);
if ($existingid > 0 && empty($_POST)) {
    redirect(new moodle_url('/lib/antivirus/verdict/view.php', ['id' => $existingid]));
}

$context = \antivirus_verdict\local\page::setup('scan.php', 'manualscan', 'antivirus/verdict:scan');
$returnurl = $PAGE->url;
$manual = \antivirus_verdict\local\manual_scan::from_site_config();
$config = \antivirus_verdict\local\plugin_config::from_site_config();
$form = new \antivirus_verdict\form\manual_scan_form($returnurl, ['maxbytes' => $config->maxbytes]);
$renderer = $PAGE->get_renderer('antivirus_verdict');

if ($form->is_cancelled()) {
    redirect($returnurl);
}

if ($data = $form->get_data()) {
    require_sesskey();
    if (!$manual->can_queue()) {
        redirect(
            $returnurl,
            get_string($manual->unavailable_reason(), 'antivirus_verdict'),
            null,
            \core\output\notification::NOTIFY_ERROR
        );
    }
    try {
        $scan = $manual->queue_from_draft((int) $data->scanfile, $context, (int) $USER->id);
        $detailurl = new moodle_url('/lib/antivirus/verdict/view.php', ['id' => $scan->id]);
        [$message, $level] = \antivirus_verdict\local\scan_presenter::manual_submit_notification($scan);
        redirect($detailurl, $message, null, $level);
    } catch (required_capability_exception $e) {
        throw $e;
    } catch (moodle_exception $e) {
        redirect(
            $returnurl,
            \antivirus_verdict\local\scan_presenter::exception_message($e),
            null,
            \core\output\notification::NOTIFY_ERROR
        );
    }
}

echo $OUTPUT->header();
echo $renderer->plugin_tabs('manualscan', $context);
echo html_writer::start_div('antivirus-verdict-page');
echo html_writer::start_div('antivirus-verdict-topline');
echo html_writer::div(
    html_writer::tag('h1', html_writer::span('', 'antivirus-verdict-rule') . s(get_string('manualscan', 'antivirus_verdict')), [
        'class' => 'antivirus-verdict-title',
    ]) .
    html_writer::tag('p', s(get_string('scansubtitle', 'antivirus_verdict')), ['class' => 'antivirus-verdict-subtitle'])
);
echo html_writer::end_div();
echo html_writer::start_div('antivirus-verdict-panel antivirus-verdict-scanform');
echo html_writer::tag('p', s(get_string('scanintro', 'antivirus_verdict')), ['class' => 'antivirus-verdict-copy']);
if (!$manual->can_queue()) {
    echo html_writer::div(s(get_string($manual->unavailable_reason(), 'antivirus_verdict')), 'antivirus-verdict-banner');
} else {
    $form->display();
}
echo html_writer::end_div();
echo html_writer::end_div();
echo $renderer->product_end();
echo $OUTPUT->footer();
