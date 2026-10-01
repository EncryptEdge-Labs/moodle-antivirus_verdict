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
 * Administrator-only VirusTotal connection test.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

// phpcs:disable moodle.Files.MoodleInternal
require_once(__DIR__ . '/locatemoodle.php');
// phpcs:enable moodle.Files.MoodleInternal
defined('MOODLE_INTERNAL') || die();

$context = \antivirus_verdict\local\page::prepare('test_connection.php', 'testconnection');
require_capability('moodle/site:config', context_system::instance());

$settingsurl = \antivirus_verdict\local\page::settings_url();
$form = new \antivirus_verdict\form\test_connection_form();

if ($form->is_cancelled()) {
    redirect($settingsurl);
}

$renderer = $PAGE->get_renderer('antivirus_verdict');
echo $OUTPUT->header();
echo $renderer->plugin_tabs('settings', $context);
echo html_writer::start_div('antivirus-verdict-page');
echo html_writer::start_div('antivirus-verdict-topline');
echo html_writer::div(
    html_writer::tag('h1', html_writer::span('', 'antivirus-verdict-rule') . s(get_string('testconnection', 'antivirus_verdict')), [
        'class' => 'antivirus-verdict-title',
    ])
);
echo html_writer::end_div();
echo html_writer::start_div('antivirus-verdict-panel antivirus-verdict-scanform');

if ($form->get_data()) {
    try {
        $client = \antivirus_verdict\provider\virustotal\client::from_site_config();
        $result = $client->test_connection();
        $message = \antivirus_verdict\local\scan_presenter::lang_message($result->code);
        $bannerclass = $result->success
            ? 'antivirus-verdict-banner antivirus-verdict-banner--ok'
            : 'antivirus-verdict-banner antivirus-verdict-banner--error';
        echo html_writer::div(s($message), $bannerclass, ['role' => 'status']);
    } catch (\antivirus_verdict\provider\provider_exception $e) {
        echo html_writer::div(
            s(\antivirus_verdict\local\scan_presenter::exception_message($e)),
            'antivirus-verdict-banner antivirus-verdict-banner--error',
            ['role' => 'alert']
        );
    }
}

$form->display();
echo html_writer::end_div();
echo html_writer::end_div();
echo $renderer->product_end();
echo $OUTPUT->footer();
