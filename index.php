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
 * Security overview page for the antivirus_verdict plugin.
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

$context = \antivirus_verdict\local\page::setup('index.php', 'overview');
$renderer = $PAGE->get_renderer('antivirus_verdict');

echo $OUTPUT->header();
echo $renderer->plugin_tabs('overview', $context);
if (\antivirus_verdict\local\scan_access::can_view_overview()) {
    $service = \antivirus_verdict\local\overview_service::from_site_config();
    if (!\antivirus_verdict\local\scan_access::can_manage_site()) {
        $service = $service->for_viewer((int) $USER->id);
    }
    $overview = new \antivirus_verdict\output\overview($service, $context);
    echo $renderer->render($overview);
} else {
    echo html_writer::start_div('antivirus-verdict-page');
    echo html_writer::start_div('antivirus-verdict-topline');
    echo html_writer::div(
        html_writer::tag('h1', html_writer::span('', 'antivirus-verdict-rule') . s(get_string('overview', 'antivirus_verdict')), [
            'class' => 'antivirus-verdict-title',
        ])
    );
    echo html_writer::end_div();
    echo html_writer::div(get_string('overviewcourse', 'antivirus_verdict'), 'antivirus-verdict-banner', [
        'role' => 'status',
    ]);
    echo $renderer->launch_links($context);
    echo html_writer::end_div();
}
echo $renderer->product_end();
echo $OUTPUT->footer();
