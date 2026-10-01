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
 * Scan history page for the antivirus_verdict plugin.
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

$courseid = optional_param('courseid', 0, PARAM_INT);
$coursecontext = null;
if ($courseid > 0) {
    $course = get_course($courseid);
    $coursecontext = \context_course::instance($courseid);
    if (!can_access_course($course, null, '', true)) {
        throw new require_login_exception(get_string('requireloginerror', 'error'));
    }
}

$PAGE->set_url(new moodle_url('/lib/antivirus/verdict/history.php', $courseid > 0 ? ['courseid' => $courseid] : []));
\antivirus_verdict\local\page::apply_site_application_chrome('scanhistory');
$PAGE->navbar->add(
    get_string('pluginbrand', 'antivirus_verdict'),
    new moodle_url('/lib/antivirus/verdict/index.php')
);
$PAGE->navbar->add(get_string('scanhistory', 'antivirus_verdict'));

$context = $coursecontext ?? \context_system::instance();
if (!\antivirus_verdict\local\scan_access::can_view_history_page($context)) {
    throw new required_capability_exception($context, 'antivirus/verdict:viewhistory', 'nopermissions', '');
}
\antivirus_verdict\local\teacher_access::require_page('scanhistory');

$filters = [
    'status' => optional_param('status', '', PARAM_ALPHA),
    'source' => optional_param('source', '', PARAM_ALPHA),
    'filename' => optional_param('filename', '', PARAM_NOTAGS),
];
if ($coursecontext) {
    $filters['courseid'] = $courseid;
}

$filterurl = new moodle_url('/lib/antivirus/verdict/history.php');
if (!empty($filters['courseid'])) {
    $filterurl->param('courseid', $filters['courseid']);
}
$filterform = new \antivirus_verdict\form\history_filter_form($filterurl, ['courseid' => $filters['courseid'] ?? 0], 'get');
$filterform->set_data($filters);

$repo = new \antivirus_verdict\local\scan_repository();
$total = $repo->count_visible_history((int) $USER->id, $filters);
$renderer = $PAGE->get_renderer('antivirus_verdict');

echo $OUTPUT->header();
echo $renderer->plugin_tabs('scanhistory', $context);
echo html_writer::start_div('antivirus-verdict-page');
echo html_writer::start_div('antivirus-verdict-topline');
echo html_writer::div(
    html_writer::tag('h1', html_writer::span('', 'antivirus-verdict-rule') . s(get_string('scanhistory', 'antivirus_verdict')), [
        'class' => 'antivirus-verdict-title',
    ]) .
    html_writer::tag('p', s(get_string('historysubtitle', 'antivirus_verdict')), ['class' => 'antivirus-verdict-subtitle'])
);
echo html_writer::end_div();
echo html_writer::start_div('antivirus-verdict-filterbar');
$filterform->display();
echo html_writer::end_div();

$hasfilters = ($filters['status'] !== '' || $filters['source'] !== '' || trim((string) $filters['filename']) !== '');
if ($total === 0) {
    $scanurl = null;
    if (\antivirus_verdict\local\teacher_access::can_use_page('manualscan', $context)) {
        $scanparams = [];
        if (!empty($filters['courseid'])) {
            $scanparams['courseid'] = $filters['courseid'];
        }
        $scanurl = new moodle_url('/lib/antivirus/verdict/scan.php', $scanparams);
    }
    echo $renderer->history_empty($hasfilters, $scanurl);
} else {
    $baseurl = new moodle_url('/lib/antivirus/verdict/history.php');
    foreach (['courseid', 'status', 'source', 'filename'] as $key) {
        if (!empty($filters[$key])) {
            $baseurl->param($key, $filters[$key]);
        }
    }
    echo html_writer::start_div(
        'antivirus-verdict-panel antivirus-verdict-panel--flush antivirus-verdict-datatable antivirus-verdict-history-table'
    );
    $table = new \antivirus_verdict\output\history_table('antivirus_verdict_history');
    $table->define_baseurl($baseurl);
    $table->set_visible_sql((int) $USER->id, $filters);
    $table->out(\antivirus_verdict\output\history_table::PAGESIZE, false);
    echo html_writer::end_div();
}
echo html_writer::end_div();
echo $renderer->product_end();
echo $OUTPUT->footer();
