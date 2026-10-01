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
 * File coverage registry page.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

// phpcs:disable moodle.Files.MoodleInternal
require_once(__DIR__ . '/locatemoodle.php');
// phpcs:enable moodle.Files.MoodleInternal
defined('MOODLE_INTERNAL') || die();

$coveragecapability = \antivirus_verdict\local\scan_access::can_manage_site()
    ? 'antivirus/verdict:manage'
    : 'antivirus/verdict:viewreports';
$context = \antivirus_verdict\local\page::setup('coverage.php', 'coverageheading', $coveragecapability);

$renderer = $PAGE->get_renderer('antivirus_verdict');
echo $OUTPUT->header();
echo $renderer->plugin_tabs('coverage', $context);
echo $renderer->render_from_template(
    'antivirus_verdict/coverage',
    (new \antivirus_verdict\output\coverage_page())->export_for_template($renderer)
);
echo $renderer->product_end();
echo $OUTPUT->footer();
