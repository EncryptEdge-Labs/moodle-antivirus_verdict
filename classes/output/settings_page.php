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
 * Dark-shell settings templatable.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\output;

use antivirus_verdict\local\config_credentials;
use antivirus_verdict\local\page;
use antivirus_verdict\local\plugin_config;
use antivirus_verdict\local\scan_retention;
use antivirus_verdict\local\teacher_access;
use renderer_base;


/**
 * Exports site settings for the Verdict settings screen.
 *
 * The API key is included only after a sesskey-confirmed reveal POST.
 */
class settings_page implements \renderable, \templatable {
    /** @var bool Whether the saved API key may be shown. */
    private bool $keyrevealed;

    /**
     * Create the settings view.
     *
     * @param bool $keyrevealed Whether the current request may display the key.
     */
    public function __construct(bool $keyrevealed = false) {
        $this->keyrevealed = $keyrevealed;
    }

    /**
     * Template context. The API key is omitted unless revealed.
     *
     * @param renderer_base $output Renderer.
     * @return array
     */
    public function export_for_template(renderer_base $output): array {
        $config = plugin_config::from_site_config();
        $credentials = new config_credentials();
        $haskey = $credentials->has_api_key();
        $apikey = '';
        if ($this->keyrevealed && $haskey) {
            $apikey = $credentials->get_api_key();
        }

        return [
            'pagetitle' => get_string('settingsheading', 'antivirus_verdict'),
            'actionurl' => page::settings_url()->out(false),
            'sesskey' => sesskey(),
            'privacyheading' => get_string('privacyheading', 'antivirus_verdict'),
            'privacydesc' => get_string('privacyheading_page', 'antivirus_verdict'),
            'apidocslead' => get_string('apidocslead', 'antivirus_verdict'),
            'apidocs' => get_string('apidocs', 'antivirus_verdict'),
            'apidocsurl' => get_string('apidocsurl', 'antivirus_verdict'),
            'credentialsheading' => get_string('credentialsheading', 'antivirus_verdict'),
            'credentialsdesc' => get_string('credentialsheading_page', 'antivirus_verdict'),
            'operationheading' => get_string('operationheading', 'antivirus_verdict'),
            'operationdesc' => get_string('operationheading_page', 'antivirus_verdict'),
            'scanningheading' => get_string('scanningheading', 'antivirus_verdict'),
            'jumpnavlabel' => get_string('settingsjumpnav', 'antivirus_verdict'),
            'jumpprivacy' => get_string('jumpprivacy', 'antivirus_verdict'),
            'jumpcredentials' => get_string('jumpcredentials', 'antivirus_verdict'),
            'jumphow' => get_string('jumphow', 'antivirus_verdict'),
            'jumpscanning' => get_string('jumpscanning', 'antivirus_verdict'),
            'jumparchive' => get_string('jumparchive', 'antivirus_verdict'),
            'jumppolicies' => get_string('jumppolicies', 'antivirus_verdict'),
            'jumpnotifications' => get_string('jumpnotifications', 'antivirus_verdict'),
            'jumpstorage' => get_string('jumpstorage', 'antivirus_verdict'),
            'jumpaccess' => get_string('jumpaccess', 'antivirus_verdict'),
            'settingsgroup_archive' => get_string('settingsgroup_archive', 'antivirus_verdict'),
            'settingsgroup_archive_desc' => get_string('settingsgroup_archive_desc', 'antivirus_verdict'),
            'settingsgroup_policies' => get_string('settingsgroup_policies', 'antivirus_verdict'),
            'settingsgroup_policies_desc' => get_string('settingsgroup_policies_desc', 'antivirus_verdict'),
            'settingsgroup_notifications' => get_string('settingsgroup_notifications', 'antivirus_verdict'),
            'settingsgroup_notifications_desc' => get_string('settingsgroup_notifications_desc', 'antivirus_verdict'),
            'settingsgroup_storage' => get_string('settingsgroup_storage', 'antivirus_verdict'),
            'settingsgroup_storage_desc' => get_string('settingsgroup_storage_desc', 'antivirus_verdict'),
            'apikeylabel' => get_string('apikey', 'antivirus_verdict'),
            'apikeyhelp' => get_string('apikeyhelp', 'antivirus_verdict'),
            'apikeyneverlogged' => get_string('apikeyneverlogged', 'antivirus_verdict'),
            'apikeymasked' => get_string('apikeymasked', 'antivirus_verdict'),
            'nokeyconfigured' => get_string('nokeyconfigured', 'antivirus_verdict'),
            'revealkey' => get_string('revealkey', 'antivirus_verdict'),
            'hidekey' => get_string('hidekey', 'antivirus_verdict'),
            'editkey' => get_string('editkey', 'antivirus_verdict'),
            'haskey' => $haskey,
            'keyrevealed' => $this->keyrevealed,
            'apikey' => $apikey,
            'testconnectionurl' => (new \moodle_url('/lib/antivirus/verdict/test_connection.php'))->out(false),
            'testconnectionlabel' => get_string('testconnection_go', 'antivirus_verdict'),
            'configuredlabel' => get_string('scannerstate_configuredlabel', 'antivirus_verdict'),
            'configureddesc' => get_string('scannerstate_configured_page', 'antivirus_verdict'),
            'configuredyes' => get_string('scannerstate_configured', 'antivirus_verdict'),
            'configuredno' => get_string('scannerstate_notconfigured', 'antivirus_verdict'),
            'antivirusenabled' => $config->enabled,
            'antivirusenabledlabel' => get_string('antivirusenabled', 'antivirus_verdict'),
            'antivirusenableddesc' => get_string('antivirusenabled_page', 'antivirus_verdict'),
            'antivirusmanageurl' => page::antivirus_manage_url()->out(false),
            'antivirusmanagelabel' => get_string('antivirusmanage', 'antivirus_verdict'),
            'unknownpolicylabel' => get_string('unknownpolicy', 'antivirus_verdict'),
            'unknownpolicydesc' => get_string('unknownpolicy_page', 'antivirus_verdict'),
            'unknownpolicykey' => 'antivirus_verdict | unknownpolicy',
            'unknownpolicy' => $config->unknownpolicy,
            'unknownpolicyallow' => $config->unknownpolicy === 'allow',
            'unknownpolicyblock' => $config->unknownpolicy === 'block',
            'suspiciouspolicylabel' => get_string('suspiciouspolicy', 'antivirus_verdict'),
            'suspiciouspolicydesc' => get_string('suspiciouspolicy_page', 'antivirus_verdict'),
            'suspiciouspolicykey' => 'antivirus_verdict | suspiciouspolicy',
            'suspiciouspolicy' => $config->suspiciouspolicy,
            'suspiciouspolicyallow' => $config->suspiciouspolicy === 'allow',
            'suspiciouspolicyblock' => $config->suspiciouspolicy === 'block',
            'providererrorpolicylabel' => get_string('providererrorpolicy', 'antivirus_verdict'),
            'providererrorpolicydesc' => get_string('providererrorpolicy_page', 'antivirus_verdict'),
            'providererrorpolicykey' => 'antivirus_verdict | providererrorpolicy',
            'providererrorpolicy' => $config->providererrorpolicy,
            'providererrorpolicyblock' => $config->providererrorpolicy === 'block',
            'providererrorpolicyreport' => $config->providererrorpolicy === 'report',
            'asyncenforcementlabel' => get_string('asyncenforcement', 'antivirus_verdict'),
            'asyncenforcementdesc' => get_string('asyncenforcement_page', 'antivirus_verdict'),
            'asyncenforcementkey' => 'antivirus_verdict | asyncenforcement',
            'asyncenforcement' => $config->asyncenforcement,
            'asyncenforcementquarantine' => $config->asyncenforcement === 'quarantine',
            'asyncenforcementreport' => $config->asyncenforcement === 'report',
            'policyallow' => get_string('policy_allow', 'antivirus_verdict'),
            'policyblock' => get_string('policy_block', 'antivirus_verdict'),
            'policyreport' => get_string('policy_report', 'antivirus_verdict'),
            'policyquarantine' => get_string('policy_quarantine', 'antivirus_verdict'),
            'policyreportonly' => get_string('policy_reportonly', 'antivirus_verdict'),
            'scanscopelabel' => get_string('scanscope', 'antivirus_verdict'),
            'scanscopedesc' => get_string('scanscope_desc', 'antivirus_verdict'),
            'scanscopekey' => 'antivirus_verdict | scanscope',
            'scanscopeevery' => get_string('scanscope_everyupload', 'antivirus_verdict'),
            'scopeselected' => get_string('scanscope_selectedareas', 'antivirus_verdict'),
            'scanscopeeveryupload' => $config->scanscope === \antivirus_verdict\local\scan_scope::EVERY_UPLOAD,
            'scopeselectedareas' => $config->scanscope === \antivirus_verdict\local\scan_scope::SELECTED_AREAS,
            'assignscanlabel' => get_string('assignscan', 'antivirus_verdict'),
            'assignscandesc' => get_string('assignscan_page', 'antivirus_verdict'),
            'assignscankey' => 'antivirus_verdict | assignscan',
            'assignscan' => $config->assignscan,
            'forumscanlabel' => get_string('forumscan', 'antivirus_verdict'),
            'forumscandesc' => get_string('forumscan_desc', 'antivirus_verdict'),
            'forumscan' => $config->forumscan,
            'workshopscanlabel' => get_string('workshopscan', 'antivirus_verdict'),
            'workshopscandesc' => get_string('workshopscan_desc', 'antivirus_verdict'),
            'workshopscan' => $config->workshopscan,
            'glossaryscanlabel' => get_string('glossaryscan', 'antivirus_verdict'),
            'glossaryscandesc' => get_string('glossaryscan_desc', 'antivirus_verdict'),
            'glossaryscan' => $config->glossaryscan,
            'datascanlabel' => get_string('datascan', 'antivirus_verdict'),
            'datascandesc' => get_string('datascan_desc', 'antivirus_verdict'),
            'datascan' => $config->datascan,
            'wikiscanlabel' => get_string('wikiscan', 'antivirus_verdict'),
            'wikiscandesc' => get_string('wikiscan_desc', 'antivirus_verdict'),
            'wikiscan' => $config->wikiscan,
            'scormscanlabel' => get_string('scormscan', 'antivirus_verdict'),
            'scormscandesc' => get_string('scormscan_desc', 'antivirus_verdict'),
            'scormscan' => $config->scormscan,
            'questionscanlabel' => get_string('questionscan', 'antivirus_verdict'),
            'questionscandesc' => get_string('questionscan_desc', 'antivirus_verdict'),
            'questionscan' => $config->questionscan,
            'privatescanlabel' => get_string('privatescan', 'antivirus_verdict'),
            'privatescandesc' => get_string('privatescan_desc', 'antivirus_verdict'),
            'privatescan' => $config->privatescan,
            'restorescanlabel' => get_string('restorescan', 'antivirus_verdict'),
            'restorescandesc' => get_string('restorescan_desc', 'antivirus_verdict'),
            'restorescan' => $config->restorescan,
            'archivescanlabel' => get_string('archivescan', 'antivirus_verdict'),
            'archivescandesc' => get_string('archivescan_desc', 'antivirus_verdict'),
            'archivescan' => $config->archivescan,
            'archivemaxmemberslabel' => get_string('archivemaxmembers', 'antivirus_verdict'),
            'archivemaxmembersdesc' => get_string('archivemaxmembers_desc', 'antivirus_verdict'),
            'archivemaxmembers' => $config->archivemaxmembers,
            'archivemaxdepthlabel' => get_string('archivemaxdepth', 'antivirus_verdict'),
            'archivemaxdepthdesc' => get_string('archivemaxdepth_desc', 'antivirus_verdict'),
            'archivemaxdepth' => $config->archivemaxdepth,
            'archivemaxextractedlabel' => get_string('archivemaxextractedmb', 'antivirus_verdict'),
            'archivemaxextracteddesc' => get_string('archivemaxextractedmb_desc', 'antivirus_verdict'),
            'archivemaxextractedmb' => $config->archivemaxextractedmb,
            'notifymaliciouslabel' => get_string('notifymalicious', 'antivirus_verdict'),
            'notifymaliciousdesc' => get_string('notifymalicious_desc', 'antivirus_verdict'),
            'notifymalicious' => $config->notifymalicious,
            'notifysuspiciouslabel' => get_string('notifysuspicious', 'antivirus_verdict'),
            'notifysuspiciousdesc' => get_string('notifysuspicious_desc', 'antivirus_verdict'),
            'notifysuspicious' => $config->notifysuspicious,
            'notifyerrorlabel' => get_string('notifyerror', 'antivirus_verdict'),
            'notifyerrordesc' => get_string('notifyerror_desc', 'antivirus_verdict'),
            'notifyerror' => $config->notifyerror,
            'maxfilesizelabel' => get_string('maxfilesize', 'antivirus_verdict'),
            'maxfilesizedesc' => get_string('maxfilesize_page', 'antivirus_verdict'),
            'maxfilesizekey' => 'antivirus_verdict | maxfilesize',
            'maxfilesize' => plugin_config::max_mb_from_config(),
            'maxfilesizecap' => plugin_config::DEFAULT_MAX_MB,
            'maxfilesizeunit' => get_string('maxfilesizeunit', 'antivirus_verdict'),
            'scanretentiondayslabel' => get_string('scanretentiondays', 'antivirus_verdict'),
            'scanretentiondaysdesc' => get_string('scanretentiondays_page', 'antivirus_verdict'),
            'scanretentiondayskey' => 'antivirus_verdict | scanretentiondays',
            'scanretentiondays' => scan_retention::days_from_config(),
            'scanretentiondaysunit' => get_string('days'),
            'savelabel' => get_string('savechanges', 'antivirus_verdict'),
            'teacheraccessheading' => get_string('teacheraccessheading', 'antivirus_verdict'),
            'teacheraccesslabel' => get_string('teacheraccess', 'antivirus_verdict'),
            'teacheraccessdesc' => get_string('teacheraccess_desc', 'antivirus_verdict'),
            'teacheraccess' => teacher_access::enabled(),
            'teacherpagesdesc' => get_string('teacherpages_desc', 'antivirus_verdict'),
            'teacherpages' => teacher_access::page_choices(),
        ];
    }
}
