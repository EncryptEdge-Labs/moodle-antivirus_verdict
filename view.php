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
 * Scan detail page for Verdict for Moodle.
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

$id = required_param('id', PARAM_INT);
$repo = new \antivirus_verdict\local\scan_repository();
$scan = $repo->get_by_id($id);
if (!$scan || !\antivirus_verdict\local\scan_access::can_view_scan($scan)) {
    $system = context_system::instance();
    throw new required_capability_exception($system, 'antivirus/verdict:viewreports', 'nopermissions', '');
}
\antivirus_verdict\local\teacher_access::require_page('scanhistory');

$PAGE->set_url(new moodle_url('/lib/antivirus/verdict/view.php', ['id' => $id]));
\antivirus_verdict\local\page::apply_site_application_chrome('scandetail');
$PAGE->navbar->add(
    get_string('pluginbrand', 'antivirus_verdict'),
    new moodle_url('/lib/antivirus/verdict/index.php')
);
$PAGE->navbar->add(
    get_string('scanhistory', 'antivirus_verdict'),
    new moodle_url('/lib/antivirus/verdict/history.php')
);
$PAGE->navbar->add(get_string('scandetail', 'antivirus_verdict'));

$renderer = $PAGE->get_renderer('antivirus_verdict');
$tabcontext = context_system::instance();

$rescan = \antivirus_verdict\local\rescan::from_site_config();
$canrescan = \antivirus_verdict\local\scan_access::can_rescan($scan);
$form = null;
if ($canrescan && $rescan->is_eligible($scan)) {
    $form = new \antivirus_verdict\form\rescan_form($PAGE->url, ['id' => (int) $scan->id]);
    if ($data = $form->get_data()) {
        require_sesskey();
        if ((int) $data->id !== (int) $scan->id) {
            throw new moodle_exception('error_invalidrequest', 'antivirus_verdict');
        }
        try {
            $queued = $rescan->queue($scan, (int) $USER->id);
            $message = ((int) $queued->id === (int) $scan->id)
                ? get_string('rescaninprogress', 'antivirus_verdict')
                : get_string('rescanqueued', 'antivirus_verdict');
            redirect(new moodle_url('/lib/antivirus/verdict/view.php', ['id' => $queued->id]), $message);
        } catch (required_capability_exception $e) {
            throw $e;
        } catch (moodle_exception $e) {
            redirect(
                $PAGE->url,
                \antivirus_verdict\local\scan_presenter::exception_message($e),
                null,
                \core\output\notification::NOTIFY_ERROR
            );
        }
    }
}

echo $OUTPUT->header();
echo $renderer->product_start(
    'scanhistory',
    $tabcontext,
    get_string('scanhistory', 'antivirus_verdict') . ' / ' . get_string('scandetail', 'antivirus_verdict')
);
echo $renderer->render(new \antivirus_verdict\output\scan_detail($scan, [
    'showrescanunavailable' => $canrescan
        && \antivirus_verdict\scan_status::is_terminal($scan->status)
        && !$rescan->file_available($scan),
]));
if ($form) {
    echo html_writer::start_div('antivirus-verdict-panel antivirus-verdict-scanform');
    $form->display();
    echo html_writer::end_div();
}
echo $renderer->product_end();
echo $OUTPUT->footer();
