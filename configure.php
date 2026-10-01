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
 * Dark-shell settings page for Verdict for Moodle.
 *
 * Moodle still registers native admin settings from settings.php.
 * This page is the in-app Settings UI and uses the same config keys.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

// phpcs:disable moodle.Files.MoodleInternal
require_once(__DIR__ . '/locatemoodle.php');
// phpcs:enable moodle.Files.MoodleInternal
defined('MOODLE_INTERNAL') || die();

$context = \antivirus_verdict\local\page::prepare('configure.php', 'settingsheading');
require_capability('moodle/site:config', context_system::instance());

$keyrevealed = false;
if (data_submitted()) {
    require_sesskey();
    $settingsaction = optional_param('settingsaction', '', PARAM_ALPHA);
    if ($settingsaction === 'save') {
        $assignscan = optional_param('assignscan', 0, PARAM_INT) ? 1 : 0;
        $forumscan = optional_param('forumscan', 0, PARAM_INT) ? 1 : 0;
        $workshopscan = optional_param('workshopscan', 0, PARAM_INT) ? 1 : 0;
        $glossaryscan = optional_param('glossaryscan', 0, PARAM_INT) ? 1 : 0;
        $restorescan = optional_param('restorescan', 0, PARAM_INT) ? 1 : 0;
        $archivescan = optional_param('archivescan', 0, PARAM_INT) ? 1 : 0;
        $scanscope = \antivirus_verdict\local\scan_scope::normalise(
            optional_param('scanscope', \antivirus_verdict\local\scan_scope::EVERY_UPLOAD, PARAM_ALPHANUMEXT)
        );
        $datascan = optional_param('datascan', 0, PARAM_INT) ? 1 : 0;
        $wikiscan = optional_param('wikiscan', 0, PARAM_INT) ? 1 : 0;
        $scormscan = optional_param('scormscan', 0, PARAM_INT) ? 1 : 0;
        $questionscan = optional_param('questionscan', 0, PARAM_INT) ? 1 : 0;
        $privatescan = optional_param('privatescan', 0, PARAM_INT) ? 1 : 0;
        $notifymalicious = optional_param('notifymalicious', 0, PARAM_INT) ? 1 : 0;
        $notifysuspicious = optional_param('notifysuspicious', 0, PARAM_INT) ? 1 : 0;
        $notifyerror = optional_param('notifyerror', 0, PARAM_INT) ? 1 : 0;
        $mb = \antivirus_verdict\local\plugin_config::normalise_max_mb(
            optional_param('maxfilesize', \antivirus_verdict\local\plugin_config::DEFAULT_MAX_MB, PARAM_INT)
        );
        $unknownpolicy = \antivirus_verdict\local\scan_policy::normalise_allow_block(
            optional_param('unknownpolicy', 'allow', PARAM_ALPHA),
            \antivirus_verdict\local\scan_policy::UNKNOWN_DEFAULT
        );
        $suspiciouspolicy = \antivirus_verdict\local\scan_policy::normalise_allow_block(
            optional_param('suspiciouspolicy', 'allow', PARAM_ALPHA),
            \antivirus_verdict\local\scan_policy::SUSPICIOUS_DEFAULT
        );
        $providererrorpolicy = \antivirus_verdict\local\scan_policy::normalise_provider_error(
            optional_param('providererrorpolicy', 'block', PARAM_ALPHA)
        );
        $asyncenforcement = \antivirus_verdict\local\scan_policy::normalise_async_enforcement(
            optional_param('asyncenforcement', 'quarantine', PARAM_ALPHA)
        );
        set_config('assignscan', $assignscan, 'antivirus_verdict');
        set_config('forumscan', $forumscan, 'antivirus_verdict');
        set_config('workshopscan', $workshopscan, 'antivirus_verdict');
        set_config('glossaryscan', $glossaryscan, 'antivirus_verdict');
        set_config('restorescan', $restorescan, 'antivirus_verdict');
        set_config('archivescan', $archivescan, 'antivirus_verdict');
        set_config('scanscope', $scanscope, 'antivirus_verdict');
        set_config(
            'archivemaxmembers',
            \antivirus_verdict\local\archive_limits::normalise_max_members(
                optional_param('archivemaxmembers', \antivirus_verdict\local\archive_limits::DEFAULT_MAX_MEMBERS, PARAM_INT)
            ),
            'antivirus_verdict'
        );
        set_config(
            'archivemaxdepth',
            \antivirus_verdict\local\archive_limits::normalise_max_depth(
                optional_param('archivemaxdepth', \antivirus_verdict\local\archive_limits::DEFAULT_MAX_DEPTH, PARAM_INT)
            ),
            'antivirus_verdict'
        );
        set_config(
            'archivemaxextractedmb',
            \antivirus_verdict\local\archive_limits::normalise_max_extracted_mb(
                optional_param(
                    'archivemaxextractedmb',
                    \antivirus_verdict\local\archive_limits::DEFAULT_MAX_EXTRACTED_MB,
                    PARAM_INT
                )
            ),
            'antivirus_verdict'
        );
        set_config('datascan', $datascan, 'antivirus_verdict');
        set_config('wikiscan', $wikiscan, 'antivirus_verdict');
        set_config('scormscan', $scormscan, 'antivirus_verdict');
        set_config('questionscan', $questionscan, 'antivirus_verdict');
        set_config('privatescan', $privatescan, 'antivirus_verdict');
        set_config('notifymalicious', $notifymalicious, 'antivirus_verdict');
        set_config('notifysuspicious', $notifysuspicious, 'antivirus_verdict');
        set_config('notifyerror', $notifyerror, 'antivirus_verdict');
        set_config('maxfilesize', $mb, 'antivirus_verdict');
        set_config('unknownpolicy', $unknownpolicy, 'antivirus_verdict');
        set_config('suspiciouspolicy', $suspiciouspolicy, 'antivirus_verdict');
        set_config('providererrorpolicy', $providererrorpolicy, 'antivirus_verdict');
        set_config('asyncenforcement', $asyncenforcement, 'antivirus_verdict');
        $retentiondays = \antivirus_verdict\local\scan_retention::normalise_days(
            optional_param('scanretentiondays', \antivirus_verdict\local\scan_retention::DEFAULT_DAYS, PARAM_INT)
        );
        set_config('scanretentiondays', $retentiondays, 'antivirus_verdict');
        set_config(
            'teacheraccess',
            optional_param('teacheraccess', 0, PARAM_INT) ? 1 : 0,
            'antivirus_verdict'
        );
        foreach (\antivirus_verdict\local\teacher_access::config_names() as $teacherpage) {
            set_config(
                $teacherpage,
                optional_param($teacherpage, 0, PARAM_INT) ? 1 : 0,
                'antivirus_verdict'
            );
        }
        $newkey = trim((string) optional_param('apikey', '', PARAM_RAW));
        if ($newkey !== '') {
            set_config('apikey', $newkey, 'antivirus_verdict');
        }
        redirect(
            \antivirus_verdict\local\page::settings_url(),
            get_string('settingssaved', 'antivirus_verdict'),
            null,
            \core\output\notification::NOTIFY_SUCCESS
        );
    }
    if ($settingsaction === 'reveal') {
        $keyrevealed = true;
    }
}

$renderer = $PAGE->get_renderer('antivirus_verdict');
echo $OUTPUT->header();
echo $renderer->plugin_tabs('settings', $context);
echo $renderer->render(new \antivirus_verdict\output\settings_page($keyrevealed));
echo $renderer->product_end();
echo $OUTPUT->footer();
