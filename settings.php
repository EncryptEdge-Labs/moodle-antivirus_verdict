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
 * Admin settings for the antivirus_verdict plugin.
 *
 * Moodle supplies $settings (admin_settingpage) when this file is included.
 * Core hides that page while the plugin is not listed in $CFG->antiviruses.
 * Verdict replaces it with a visible page so administrators can configure
 * VirusTotal credentials and reach Moodle's native enable control.
 *
 * @package    antivirus_verdict
 * @category   admin
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license    https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

if (!empty($plugininfo) && !empty($settings)) {
    $settings = new admin_settingpage(
        $plugininfo->get_settings_section_name(),
        $plugininfo->displayname,
        'moodle/site:config',
        false
    );
}

if (!empty($ADMIN) && $ADMIN->fulltree && !empty($settings)) {
    $manageurl = (new moodle_url('/admin/settings.php', ['section' => 'manageantiviruses']))->out(false);
    $configured = (new \antivirus_verdict\local\config_credentials())->has_api_key();
    $enabled = \antivirus_verdict\local\plugin_config::is_antivirus_enabled();
    $status = ($configured
            ? get_string('scannerstate_configured', 'antivirus_verdict')
            : get_string('scannerstate_notconfigured', 'antivirus_verdict'))
        . ' / '
        . ($enabled
            ? get_string('scannerstate_enabled', 'antivirus_verdict')
            : get_string('scannerstate_disabled', 'antivirus_verdict'));

    $settings->add(new admin_setting_heading(
        'antivirus_verdict/nativestatus',
        new lang_string('nativestatusheading', 'antivirus_verdict'),
        get_string('nativestatus_desc', 'antivirus_verdict', (object) [
            'status' => $status,
            'manageurl' => $manageurl,
        ])
    ));

    $settings->add(new admin_setting_heading(
        'antivirus_verdict/privacyheading',
        new lang_string('privacyheading', 'antivirus_verdict'),
        new lang_string('privacyheading_desc', 'antivirus_verdict')
    ));

    $settings->add(new admin_setting_heading(
        'antivirus_verdict/credentialsheading',
        new lang_string('credentialsheading', 'antivirus_verdict'),
        new lang_string('credentialsheading_desc', 'antivirus_verdict')
    ));

    $settings->add(new admin_setting_configpasswordunmask(
        'antivirus_verdict/apikey',
        new lang_string('apikey', 'antivirus_verdict'),
        new lang_string('apikey_desc', 'antivirus_verdict'),
        ''
    ));

    $testurl = new moodle_url('/lib/antivirus/verdict/test_connection.php');
    $settings->add(new admin_setting_description(
        'antivirus_verdict/testconnectionlink',
        new lang_string('testconnection', 'antivirus_verdict'),
        html_writer::div(
            html_writer::link($testurl, get_string('testconnection_go', 'antivirus_verdict'))
        )
    ));

    $settings->add(new admin_setting_heading(
        'antivirus_verdict/operationheading',
        new lang_string('operationheading', 'antivirus_verdict'),
        new lang_string('operationheading_desc', 'antivirus_verdict')
    ));

    $settings->add(new admin_setting_heading(
        'antivirus_verdict/scanningheading',
        new lang_string('scanningheading', 'antivirus_verdict'),
        new lang_string('scanningheading_desc', 'antivirus_verdict')
    ));

    $settings->add(new admin_setting_configselect(
        'antivirus_verdict/scanscope',
        new lang_string('scanscope', 'antivirus_verdict'),
        new lang_string('scanscope_desc', 'antivirus_verdict'),
        \antivirus_verdict\local\scan_scope::EVERY_UPLOAD,
        [
            \antivirus_verdict\local\scan_scope::EVERY_UPLOAD => new lang_string('scanscope_everyupload', 'antivirus_verdict'),
            \antivirus_verdict\local\scan_scope::SELECTED_AREAS => new lang_string('scanscope_selectedareas', 'antivirus_verdict'),
        ]
    ));

    $settings->add(new admin_setting_configcheckbox(
        'antivirus_verdict/assignscan',
        new lang_string('assignscan', 'antivirus_verdict'),
        new lang_string('assignscan_desc', 'antivirus_verdict'),
        0
    ));

    $settings->add(new admin_setting_configcheckbox(
        'antivirus_verdict/forumscan',
        new lang_string('forumscan', 'antivirus_verdict'),
        new lang_string('forumscan_desc', 'antivirus_verdict'),
        0
    ));

    $settings->add(new admin_setting_configcheckbox(
        'antivirus_verdict/workshopscan',
        new lang_string('workshopscan', 'antivirus_verdict'),
        new lang_string('workshopscan_desc', 'antivirus_verdict'),
        0
    ));

    $settings->add(new admin_setting_configcheckbox(
        'antivirus_verdict/glossaryscan',
        new lang_string('glossaryscan', 'antivirus_verdict'),
        new lang_string('glossaryscan_desc', 'antivirus_verdict'),
        0
    ));

    $settings->add(new admin_setting_configcheckbox(
        'antivirus_verdict/restorescan',
        new lang_string('restorescan', 'antivirus_verdict'),
        new lang_string('restorescan_desc', 'antivirus_verdict'),
        1
    ));

    $settings->add(new admin_setting_configcheckbox(
        'antivirus_verdict/archivescan',
        new lang_string('archivescan', 'antivirus_verdict'),
        new lang_string('archivescan_desc', 'antivirus_verdict'),
        1
    ));

    $settings->add(new admin_setting_configtext(
        'antivirus_verdict/archivemaxmembers',
        new lang_string('archivemaxmembers', 'antivirus_verdict'),
        new lang_string('archivemaxmembers_desc', 'antivirus_verdict'),
        (string) \antivirus_verdict\local\archive_limits::DEFAULT_MAX_MEMBERS,
        PARAM_INT
    ));

    $settings->add(new admin_setting_configtext(
        'antivirus_verdict/archivemaxdepth',
        new lang_string('archivemaxdepth', 'antivirus_verdict'),
        new lang_string('archivemaxdepth_desc', 'antivirus_verdict'),
        (string) \antivirus_verdict\local\archive_limits::DEFAULT_MAX_DEPTH,
        PARAM_INT
    ));

    $settings->add(new admin_setting_configtext(
        'antivirus_verdict/archivemaxextractedmb',
        new lang_string('archivemaxextractedmb', 'antivirus_verdict'),
        new lang_string('archivemaxextractedmb_desc', 'antivirus_verdict'),
        (string) \antivirus_verdict\local\archive_limits::DEFAULT_MAX_EXTRACTED_MB,
        PARAM_INT
    ));

    $settings->add(new admin_setting_configcheckbox(
        'antivirus_verdict/datascan',
        new lang_string('datascan', 'antivirus_verdict'),
        new lang_string('datascan_desc', 'antivirus_verdict'),
        0
    ));

    $settings->add(new admin_setting_configcheckbox(
        'antivirus_verdict/wikiscan',
        new lang_string('wikiscan', 'antivirus_verdict'),
        new lang_string('wikiscan_desc', 'antivirus_verdict'),
        0
    ));

    $settings->add(new admin_setting_configcheckbox(
        'antivirus_verdict/scormscan',
        new lang_string('scormscan', 'antivirus_verdict'),
        new lang_string('scormscan_desc', 'antivirus_verdict'),
        0
    ));

    $settings->add(new admin_setting_configcheckbox(
        'antivirus_verdict/questionscan',
        new lang_string('questionscan', 'antivirus_verdict'),
        new lang_string('questionscan_desc', 'antivirus_verdict'),
        0
    ));

    $settings->add(new admin_setting_configcheckbox(
        'antivirus_verdict/privatescan',
        new lang_string('privatescan', 'antivirus_verdict'),
        new lang_string('privatescan_desc', 'antivirus_verdict'),
        0
    ));

    $settings->add(new admin_setting_configcheckbox(
        'antivirus_verdict/notifymalicious',
        new lang_string('notifymalicious', 'antivirus_verdict'),
        new lang_string('notifymalicious_desc', 'antivirus_verdict'),
        1
    ));

    $settings->add(new admin_setting_configcheckbox(
        'antivirus_verdict/notifysuspicious',
        new lang_string('notifysuspicious', 'antivirus_verdict'),
        new lang_string('notifysuspicious_desc', 'antivirus_verdict'),
        0
    ));

    $settings->add(new admin_setting_configcheckbox(
        'antivirus_verdict/notifyerror',
        new lang_string('notifyerror', 'antivirus_verdict'),
        new lang_string('notifyerror_desc', 'antivirus_verdict'),
        0
    ));

    $settings->add(new admin_setting_configtext(
        'antivirus_verdict/maxfilesize',
        new lang_string('maxfilesize', 'antivirus_verdict'),
        new lang_string('maxfilesize_desc', 'antivirus_verdict'),
        100,
        PARAM_INT
    ));

    $allowblock = [
        'allow' => new lang_string('policy_allow', 'antivirus_verdict'),
        'block' => new lang_string('policy_block', 'antivirus_verdict'),
    ];
    $settings->add(new admin_setting_configselect(
        'antivirus_verdict/unknownpolicy',
        new lang_string('unknownpolicy', 'antivirus_verdict'),
        new lang_string('unknownpolicy_desc', 'antivirus_verdict'),
        'allow',
        $allowblock
    ));
    $settings->add(new admin_setting_configselect(
        'antivirus_verdict/suspiciouspolicy',
        new lang_string('suspiciouspolicy', 'antivirus_verdict'),
        new lang_string('suspiciouspolicy_desc', 'antivirus_verdict'),
        'allow',
        $allowblock
    ));
    $settings->add(new admin_setting_configselect(
        'antivirus_verdict/providererrorpolicy',
        new lang_string('providererrorpolicy', 'antivirus_verdict'),
        new lang_string('providererrorpolicy_desc', 'antivirus_verdict'),
        'block',
        [
            'block' => new lang_string('policy_block', 'antivirus_verdict'),
            'report' => new lang_string('policy_report', 'antivirus_verdict'),
        ]
    ));

    $settings->add(new admin_setting_configselect(
        'antivirus_verdict/asyncenforcement',
        new lang_string('asyncenforcement', 'antivirus_verdict'),
        new lang_string('asyncenforcement_desc', 'antivirus_verdict'),
        'quarantine',
        [
            'quarantine' => new lang_string('policy_quarantine', 'antivirus_verdict'),
            'report' => new lang_string('policy_reportonly', 'antivirus_verdict'),
        ]
    ));

    $settings->add(new admin_setting_configtext(
        'antivirus_verdict/lookupceiling',
        new lang_string('lookupceiling', 'antivirus_verdict'),
        new lang_string('lookupceiling_desc', 'antivirus_verdict'),
        0,
        PARAM_INT
    ));
    $settings->add(new admin_setting_configtext(
        'antivirus_verdict/uploadceiling',
        new lang_string('uploadceiling', 'antivirus_verdict'),
        new lang_string('uploadceiling_desc', 'antivirus_verdict'),
        0,
        PARAM_INT
    ));
    $settings->add(new admin_setting_configtext(
        'antivirus_verdict/pollceiling',
        new lang_string('pollceiling', 'antivirus_verdict'),
        new lang_string('pollceiling_desc', 'antivirus_verdict'),
        0,
        PARAM_INT
    ));

    $settings->add(new admin_setting_configtext(
        'antivirus_verdict/scanretentiondays',
        new lang_string('scanretentiondays', 'antivirus_verdict'),
        new lang_string('scanretentiondays_desc', 'antivirus_verdict'),
        (string) \antivirus_verdict\local\scan_retention::DEFAULT_DAYS,
        PARAM_INT
    ));

    $settings->add(new admin_setting_heading(
        'antivirus_verdict/teacheraccessheading',
        new lang_string('teacheraccessheading', 'antivirus_verdict'),
        new lang_string('teacheraccess_desc', 'antivirus_verdict')
    ));
    $settings->add(new admin_setting_configcheckbox(
        'antivirus_verdict/teacheraccess',
        new lang_string('teacheraccess', 'antivirus_verdict'),
        new lang_string('teacheraccess_desc', 'antivirus_verdict'),
        0
    ));
    $teacherpages = [
        'teacherpageoverview' => ['navoverview', 1],
        'teacherpagescan' => ['manualscan', 1],
        'teacherpagebulk' => ['bulkscanheading', 1],
        'teacherpagehistory' => ['scanhistory', 1],
        'teacherpagecoverage' => ['coverageheading', 0],
        'teacherpagequarantine' => ['quarantineheading', 1],
    ];
    foreach ($teacherpages as $teacherpage => [$teacherlabel, $teacherdefault]) {
        $settings->add(new admin_setting_configcheckbox(
            'antivirus_verdict/' . $teacherpage,
            new lang_string($teacherlabel, 'antivirus_verdict'),
            new lang_string('teacherpages_desc', 'antivirus_verdict'),
            $teacherdefault
        ));
        $settings->hide_if('antivirus_verdict/' . $teacherpage, 'antivirus_verdict/teacheraccess');
    }

    $settings->add(new admin_setting_description(
        'antivirus_verdict/productshell',
        new lang_string('productshell', 'antivirus_verdict'),
        html_writer::div(
            html_writer::link(
                new moodle_url('/lib/antivirus/verdict/configure.php'),
                get_string('opensettings', 'antivirus_verdict')
            )
        )
    ));
}
