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
 * Security overview templatable (site managers and teachers with access share this UI).
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\output;

use antivirus_verdict\local\overview_service;
use antivirus_verdict\local\page;
use antivirus_verdict\local\provider_health;
use antivirus_verdict\local\scan_access;
use antivirus_verdict\local\teacher_access;
use antivirus_verdict\local\scan_context_resolver;
use antivirus_verdict\local\scan_policy;
use antivirus_verdict\local\scan_presenter;
use antivirus_verdict\scan_phase;
use antivirus_verdict\scan_status;
use renderer_base;


/**
 * Exports configuration state and scan aggregates. Never includes the API key.
 */
class overview implements \renderable, \templatable {
    /** @var overview_service Overview data. */
    private overview_service $service;

    /** @var \context Page context for action links. */
    private \context $context;

    /**
     * Create the overview view.
     *
     * @param overview_service $service Overview data.
     * @param \context $context Page context.
     */
    public function __construct(overview_service $service, \context $context) {
        $this->service = $service;
        $this->context = $context;
    }

    /**
     * Template context. Values are escaped by Mustache unless marked raw.
     *
     * @param renderer_base $output Renderer.
     * @return array
     */
    public function export_for_template(renderer_base $output): array {
        $counts = $this->service->get_status_counts();
        $empty = get_string('valueempty', 'antivirus_verdict');
        $system = \context_system::instance();
        $cansettings = has_capability('moodle/site:config', $system);
        $settingsurl = $cansettings
            ? page::settings_url()->out(false)
            : '';
        $manageurl = $cansettings
            ? page::antivirus_manage_url()->out(false)
            : '';
        $showquarantinecard = teacher_access::can_use_page('quarantine', $this->context);
        $showcoveragecard = teacher_access::can_use_page('coverage', $this->context);
        $enforcementurl = $showquarantinecard
            ? (new \moodle_url('/lib/antivirus/verdict/quarantine.php'))->out(false)
            : '';
        $coverageurl = $showcoveragecard
            ? (new \moodle_url('/lib/antivirus/verdict/coverage.php'))->out(false)
            : '';
        $actions = $this->actions($counts, $settingsurl, $manageurl);
        $scannerstate = $this->service->scanner_state();
        [$setupprimaryurl, $setupprimarylabel, $setupprimaryonly] = $this->setup_primary_action(
            $scannerstate,
            $settingsurl,
            $manageurl,
            $cansettings
        );

        $protection = $this->service->protection_state();
        $coveragecounts = $this->service->coverage_state_counts();
        $coverageactive = $coveragecounts[\antivirus_verdict\local\file_coverage_registry::STATE_ACTIVE] ?? 0;

        $base = [
            'pagetitle' => get_string('overview', 'antivirus_verdict'),
            'pagesubtitle' => get_string('overviewsubtitle', 'antivirus_verdict'),
            'protectionheading' => get_string('protectionheading', 'antivirus_verdict'),
            'protectionlabel' => get_string('protectionstate_' . $protection, 'antivirus_verdict'),
            'protectionmessage' => get_string('protectionstate_' . $protection . '_desc', 'antivirus_verdict'),
            'protectionbadgeclass' => $this->protection_badge_class($protection),
            'showprotection' => true,
            'scannerheading' => get_string('scannerstatus', 'antivirus_verdict'),
            'scannerstatelabel' => get_string(
                'scannerstate_' . $this->service->scanner_state(),
                'antivirus_verdict'
            ),
            'scannerbadgeclass' => $this->scanner_badge_class(),
            'scannermessage' => $this->scanner_message(),
            'credentialslabel' => $this->service->has_api_key()
                ? get_string('credentialsconfigured', 'antivirus_verdict')
                : get_string('credentialsmissing', 'antivirus_verdict'),
            'assignheading' => get_string('assignscanstatus', 'antivirus_verdict'),
            'assignstatelabel' => get_string(
                'assignstate_' . $this->service->assignment_state(),
                'antivirus_verdict'
            ),
            'assignbadgeclass' => $this->assign_badge_class(),
            'assignmessage' => $this->assignment_message(),
            'needssetup' => !$this->service->is_operational() && $cansettings,
            'setupheading' => get_string('setupheading', 'antivirus_verdict'),
            'setupsteps' => $this->setup_steps(),
            'hassettings' => $settingsurl !== '',
            'settingsurl' => $settingsurl,
            'settingslabel' => get_string('opensettings', 'antivirus_verdict'),
            'hasmanageurl' => $manageurl !== '',
            'manageurl' => $manageurl,
            'managelabel' => get_string('antivirusmanage', 'antivirus_verdict'),
            'setupprimaryonly' => $setupprimaryonly,
            'setupprimaryurl' => $setupprimaryurl,
            'setupprimarylabel' => $setupprimarylabel,
            'hasenforcement' => $this->service->count_quarantine_related() > 0,
            'enforcementheading' => get_string('enforcementheading', 'antivirus_verdict'),
            'enforcementcount' => $this->service->count_quarantine_related(),
            'showquarantinecard' => $showquarantinecard,
            'enforcementurl' => $enforcementurl,
            'enforcementopenlabel' => get_string('ov_openquarantine', 'antivirus_verdict'),
            'quarantinecount' => $this->service->count_quarantine_related(),
            'bannerok' => $protection === 'operational',
            'scannerenabled' => $this->service->scanner_radar_active(),
            'scannerpillon' => $this->service->scanner_radar_active(),
            'scannerradaractive' => $this->service->scanner_radar_active(),
            'coverageopenlabel' => get_string('ov_opencoverage', 'antivirus_verdict'),
            'summaryheading' => get_string('scansummary', 'antivirus_verdict'),
            'isempty' => empty($counts['total']),
            'emptymessage' => get_string('noscansoverview', 'antivirus_verdict'),
            'stats' => $this->stat_cards($counts),
            'last24label' => get_string('scanslast24hours', 'antivirus_verdict'),
            'last24' => $this->service->count_last_24_hours(),
            'last7label' => get_string('scanslast7days', 'antivirus_verdict'),
            'last7' => $this->service->count_last_7_days(),
            'recentheading' => get_string('recentscans', 'antivirus_verdict'),
            'hasrecent' => $counts['total'] > 0,
            'recent' => $this->recent_rows($empty),
            'recenttable' => $this->recent_table_html(),
            'viewallhistory' => get_string('viewfullhistory', 'antivirus_verdict'),
            'historyurl' => (new \moodle_url('/lib/antivirus/verdict/history.php'))->out(false),
            'actionsheading' => get_string('quickactions', 'antivirus_verdict'),
            'actions' => $actions,
            'hasactions' => $actions !== [],
            'canscan' => teacher_access::can_use_page('manualscan', $this->context),
            'scanurl' => (new \moodle_url('/lib/antivirus/verdict/scan.php'))->out(false),
            'scanlabel' => get_string('manualscan', 'antivirus_verdict'),
            'providerheading' => get_string('providerhealthheading', 'antivirus_verdict'),
            'providerstate' => $this->provider_state_label(),
            'providerbadgeclass' => $this->provider_badge_class(),
            'providermessage' => $this->provider_message(),
            'activejobslabel' => get_string('activejobs', 'antivirus_verdict'),
            'activejobs' => $this->service->count_active_scans(),
            'coverageheading' => get_string('coveragesummary', 'antivirus_verdict'),
            'coverageactive' => $coverageactive,
            'showcoveragecard' => $showcoveragecard,
            'coverageurl' => $coverageurl,
        ];
        return array_merge($base, $this->dashboard_export($counts));
    }

    /**
     * Real operational dashboard sections (no demo data).
     *
     * @param array<string,int> $counts Status counts.
     * @return array
     */
    private function dashboard_export(array $counts): array {
        $health = $this->service->provider_health_snapshot();
        $policies = $this->service->live_policies();
        $phases = $this->service->phase_counts();
        $dedup = $this->service->deduplication_snapshot();
        $archive = $this->service->archive_snapshot();
        $errorcode = $this->service->latest_error_code();
        $errorlabel = $errorcode !== '' ? $this->error_code_label($errorcode) : '';

        $data = [
            'dashhealthheading' => get_string('dash_systemhealth', 'antivirus_verdict'),
            'dashcoverageheading' => get_string('dash_coverage', 'antivirus_verdict'),
            'dashactivityheading' => get_string('dash_scanactivity', 'antivirus_verdict'),
            'dashefficiencyheading' => get_string('dash_efficiency', 'antivirus_verdict'),
            'dashenforcementheading' => get_string('dash_enforcement', 'antivirus_verdict'),
            'uploadgatelabel' => get_string('dash_uploadgate', 'antivirus_verdict'),
            'uploadgatevalue' => get_string(
                'scannerstate_' . $this->service->scanner_state(),
                'antivirus_verdict'
            ),
            'uploadgatedesc' => $this->scanner_message(),
            'circuitlabel' => get_string('dash_circuit', 'antivirus_verdict'),
            'circuitvalue' => $this->provider_state_label(),
            'circuitbadgeclass' => $this->provider_badge_class(),
            'circuitfailureslabel' => get_string('dash_circuitfailures', 'antivirus_verdict'),
            'circuitfailures' => (int) ($health['failures'] ?? 0),
            'circuitthresholdlabel' => get_string('dash_circuitthreshold', 'antivirus_verdict'),
            'circuitthreshold' => (int) ($health['failurethreshold'] ?? provider_health::FAILURE_THRESHOLD),
            'circuitcooldownlabel' => get_string('dash_circuitcooldown', 'antivirus_verdict'),
            'circuitcooldown' => (int) ($health['cooldownremaining'] ?? 0),
            'circuitwindowlabel' => get_string('dash_circuitwindow', 'antivirus_verdict'),
            'circuitwindow' => (int) ($health['openseconds'] ?? provider_health::OPEN_SECONDS),
            'haslasterror' => $errorlabel !== '',
            'lasterrorlabel' => get_string('dash_lasterror', 'antivirus_verdict'),
            'lasterror' => $errorlabel,
            'nolasterror' => get_string('dash_nolasterror', 'antivirus_verdict'),
            'livepoliciesheading' => get_string('dash_livepolicies', 'antivirus_verdict'),
            'livepolicies' => $this->policy_rows($policies),
            'providerpillon' => $this->service->provider_radar_active(),
            'providerradaractive' => $this->service->provider_radar_active(),
            'circuitfailuresdisplay' => (int) ($health['failures'] ?? 0)
                . ' / ' . (int) ($health['failurethreshold'] ?? provider_health::FAILURE_THRESHOLD),
            'circuitcooldownwindow' => get_string(
                'ov_cooldownwindow',
                'antivirus_verdict',
                (int) ($health['openseconds'] ?? provider_health::OPEN_SECONDS)
            ),
            'activejobslabelshort' => get_string('dash_activejobs', 'antivirus_verdict'),
            'volumesub' => get_string('dash_volumesub', 'antivirus_verdict'),
            'volumecaption' => get_string('dash_volumecaption', 'antivirus_verdict'),
            'trendtotal' => $this->service->count_last_7_days(),
            'mixsubtitle' => get_string('dash_mixsub', 'antivirus_verdict', (object) [
                'clean' => (int) ($counts[scan_status::CLEAN] ?? 0),
                'error' => (int) ($counts[scan_status::ERROR] ?? 0),
            ]),
            'donutcenterlabel' => get_string('dash_donutcenter', 'antivirus_verdict'),
            'donuttotal' => (int) ($counts['total'] ?? 0),
            'donutlegend' => $this->donut_legend($counts),
            'dedupheadline' => get_string('dash_dedupheadline', 'antivirus_verdict'),
            'dedupfillpct' => $this->dedup_fill_pct($dedup),
            'archivemaliciouslabel' => get_string('dash_archivemalicious', 'antivirus_verdict'),
            'archivemalicious' => (int) ($archive['maliciousmembers'] ?? 0),
            'archiveuninspectablewarn' => ((int) ($archive['uninspectable'] ?? 0)) > 0,
            'errorbreakdownheading' => get_string('dash_errorbreakdown', 'antivirus_verdict'),
            'errorrows' => $this->error_breakdown_rows((int) ($counts[scan_status::ERROR] ?? 0)),
            'periodgroup' => get_string('ov_periodgroup', 'antivirus_verdict'),
            'chip7d' => get_string('ov_chip7d', 'antivirus_verdict', $this->service->count_last_7_days()),
            'chip24h' => get_string('ov_chip24h', 'antivirus_verdict', $this->service->count_last_24_hours()),
            'recentintro' => get_string('ov_recentintro', 'antivirus_verdict'),
            'showncount' => min(7, (int) ($counts['total'] ?? 0)),
            'showinglabel' => get_string('ov_showing', 'antivirus_verdict', (object) [
                'shown' => min(7, (int) ($counts['total'] ?? 0)),
                'total' => $this->service->count_last_7_days(),
            ]),
            'showing24label' => get_string('ov_showing', 'antivirus_verdict', (object) [
                'shown' => min(7, (int) ($counts['total'] ?? 0)),
                'total' => $this->service->count_last_24_hours(),
            ]),
            'viewshort' => get_string('ov_view', 'antivirus_verdict'),
            'viewallhistoryarrow' => get_string('ov_viewallhistory', 'antivirus_verdict'),
            'colfilename' => get_string('colfilename', 'antivirus_verdict'),
            'colsource' => get_string('colsource', 'antivirus_verdict'),
            'colstatus' => get_string('colstatus', 'antivirus_verdict'),
            'coldetection' => get_string('colresult', 'antivirus_verdict'),
            'colqueued' => get_string('colqueued', 'antivirus_verdict'),
            'colcompleted' => get_string('colcompleted', 'antivirus_verdict'),
            'coveragecaveat' => get_string('dash_coveragecaveat', 'antivirus_verdict'),
            'nativesitesheading' => get_string('dash_nativesites', 'antivirus_verdict'),
            'nativesites' => [
                ['path' => 'repository/upload/lib.php'],
                ['path' => 'repository/lib.php (move_to_filepool)'],
                ['path' => 'webservice/upload.php'],
                ['path' => 'h5p/ajax.php'],
            ],
            'assigncoveragevalue' => get_string(
                'assignstate_' . $this->service->assignment_state(),
                'antivirus_verdict'
            ),
            'assigncoveragedesc' => $this->assignment_message(),
            'pendingphasesheading' => get_string('dash_pendingphases', 'antivirus_verdict'),
            'pendingphases' => [
                [
                    'label' => get_string('phase_queued', 'antivirus_verdict'),
                    'count' => (int) ($phases[scan_phase::QUEUED] ?? 0),
                ],
                [
                    'label' => get_string('phase_hashlookup', 'antivirus_verdict'),
                    'count' => (int) ($phases[scan_phase::HASHLOOKUP] ?? 0),
                ],
                [
                    'label' => get_string('phase_uploadrequired', 'antivirus_verdict'),
                    'count' => (int) ($phases[scan_phase::UPLOADREQUIRED] ?? 0),
                ],
                [
                    'label' => get_string('phase_submitted', 'antivirus_verdict'),
                    'count' => (int) ($phases[scan_phase::SUBMITTED] ?? 0),
                ],
                [
                    'label' => get_string('phase_polling', 'antivirus_verdict'),
                    'count' => (int) ($phases[scan_phase::POLLING] ?? 0),
                ],
            ],
            'volumelabel' => get_string('dash_volumetrend', 'antivirus_verdict'),
            'volumeempty' => array_sum($this->service->volume_by_day(7)) === 0,
            'volumeemptytext' => get_string('dash_volumeempty', 'antivirus_verdict'),
            'volumebars' => $this->volume_bars(),
            'donutlabel' => get_string('dash_detectiondonut', 'antivirus_verdict'),
            'donutempty' => empty($counts['total']),
            'donutemptytext' => get_string('dash_donutempty', 'antivirus_verdict'),
            'donutsegments' => $this->donut_segments($counts),
            'dedupheading' => get_string('dash_dedup', 'antivirus_verdict'),
            'dedupdesc' => get_string('dash_dedupdesc', 'antivirus_verdict'),
            'dedupcompletedlabel' => get_string('dash_dedupcompleted', 'antivirus_verdict'),
            'dedupcompleted' => $dedup['completed'],
            'dedupuniquelabel' => get_string('dash_dedupunique', 'antivirus_verdict'),
            'dedupunique' => $dedup['uniquehashes'],
            'dedupreusedlabel' => get_string('dash_dedupreused', 'antivirus_verdict'),
            'dedupreused' => $dedup['reused'],
            'archiveheading' => get_string('dash_archive', 'antivirus_verdict'),
            'archivecontainerslabel' => get_string('dash_archivecontainers', 'antivirus_verdict'),
            'archivecontainers' => $archive['containers'],
            'archivememberslabel' => get_string('dash_archivemembers', 'antivirus_verdict'),
            'archivemembers' => $archive['members'],
            'archiveuninspectablelabel' => get_string('dash_archiveuninspectable', 'antivirus_verdict'),
            'archiveuninspectable' => $archive['uninspectable'],
            'archivelimits' => get_string('dash_archivelimits', 'antivirus_verdict', (object) [
                'members' => $archive['maxmembers'],
                'depth' => $archive['maxdepth'],
                'size' => $archive['maxextractedmb'],
            ]),
            'enforcementevents' => $this->enforcement_event_rows(),
            'enforcementemptytext' => get_string('dash_enforcementempty', 'antivirus_verdict'),
            'enforcementemptyhint' => get_string('dash_enforcementemptyhint', 'antivirus_verdict'),
        ];
        $data['hasenforcementevents'] = $data['enforcementevents'] !== [];
        $data['haserrorbreakdown'] = $data['errorrows'] !== [];
        $errorcount = (int) ($counts[scan_status::ERROR] ?? 0);
        $data['errorbreakdownnote'] = $errorcount > 0
            ? get_string('dash_errorbreakdownnote', 'antivirus_verdict', $errorcount)
            : '';
        $data['errorbreakdownempty'] = get_string('dash_errorbreakdownempty', 'antivirus_verdict');
        $top = $data['errorrows'][0]['count'] ?? 0;
        $data['errorbreakdowntop'] = ($errorcount > 0 && $top > 0)
            ? get_string('dash_errorbreakdowntop', 'antivirus_verdict', (object) [
                'top' => $top,
                'total' => $errorcount,
            ])
            : '';
        return $data;
    }

    /**
     * Policy rows with swatch flags for the overview.
     *
     * @param array $policies Live gate policy values from overview_service::live_policies().
     * @return array
     */
    private function policy_rows(array $policies): array {
        return [
            $this->policy_row(
                get_string('unknownpolicy', 'antivirus_verdict'),
                'unknownpolicy',
                $policies['unknownpolicy']
            ),
            $this->policy_row(
                get_string('suspiciouspolicy', 'antivirus_verdict'),
                'suspiciouspolicy',
                $policies['suspiciouspolicy']
            ),
            $this->policy_row(
                get_string('providererrorpolicy', 'antivirus_verdict'),
                'providererrorpolicy',
                $policies['providererrorpolicy']
            ),
            $this->policy_row(
                get_string('scanscope', 'antivirus_verdict'),
                'scanscope',
                $policies['scanscope']
            ),
            $this->policy_row(
                get_string('asyncenforcement', 'antivirus_verdict'),
                'asyncenforcement',
                $policies['asyncenforcement']
            ),
        ];
    }

    /**
     * One live-policy row.
     *
     * @param string $label Policy name.
     * @param string $kind Config key for scan_policy::config_value_label.
     * @param string $value Stored policy.
     * @return array
     */
    private function policy_row(string $label, string $kind, string $value): array {
        $swatch = 'allow';
        if ($kind === 'providererrorpolicy') {
            $swatch = scan_policy::normalise_provider_error($value) === scan_policy::REPORT ? 'report' : 'block';
        } else if ($kind === 'unknownpolicy' || $kind === 'suspiciouspolicy') {
            $default = $kind === 'unknownpolicy'
                ? scan_policy::UNKNOWN_DEFAULT
                : scan_policy::SUSPICIOUS_DEFAULT;
            $swatch = scan_policy::normalise_allow_block($value, $default) === scan_policy::BLOCK ? 'block' : 'allow';
        } else if ($kind === 'scanscope') {
            $swatch = \antivirus_verdict\local\scan_scope::normalise($value) === \antivirus_verdict\local\scan_scope::SELECTED_AREAS
                ? 'block'
                : 'allow';
        } else if ($kind === 'asyncenforcement') {
            $swatch = scan_policy::normalise_async_enforcement($value) === scan_policy::REPORT ? 'report' : 'block';
        }
        return [
            'label' => $label,
            'value' => $this->overview_live_policy_value($kind, $value),
            'swatch' => $swatch,
        ];
    }

    /**
     * Live gate policy value labels for the overview card (short copy where needed).
     *
     * @param string $kind Config key.
     * @param string $value Stored value.
     * @return string
     */
    private function overview_live_policy_value(string $kind, string $value): string {
        if ($kind === 'providererrorpolicy') {
            return scan_policy::normalise_provider_error($value) === scan_policy::REPORT
                ? get_string('dash_policy_report', 'antivirus_verdict')
                : get_string('policy_block', 'antivirus_verdict');
        }
        if ($kind === 'asyncenforcement') {
            return scan_policy::normalise_async_enforcement($value) === scan_policy::REPORT
                ? get_string('dash_policy_reportonly', 'antivirus_verdict')
                : get_string('policy_quarantine', 'antivirus_verdict');
        }
        return scan_policy::config_value_label($kind, $value);
    }

    /**
     * Dedup bar width: distinct hashes as a share of completed hashed verdicts.
     *
     * @param array{completed:int,uniquehashes:int,reused:int} $dedup Snapshot.
     * @return int
     */
    private function dedup_fill_pct(array $dedup): int {
        $completed = (int) ($dedup['completed'] ?? 0);
        if ($completed <= 0) {
            return 0;
        }
        return (int) round(((int) ($dedup['uniquehashes'] ?? 0) / $completed) * 100);
    }

    /**
     * Donut legend rows, including zero counts.
     *
     * @param array<string,int> $counts Status counts.
     * @return array
     */
    private function donut_legend(array $counts): array {
        return [
            [
                'label' => get_string('statclean', 'antivirus_verdict'),
                'count' => (int) ($counts[scan_status::CLEAN] ?? 0),
                'tone' => 'clean',
            ],
            [
                'label' => get_string('staterror', 'antivirus_verdict'),
                'count' => (int) ($counts[scan_status::ERROR] ?? 0),
                'tone' => 'error',
            ],
            [
                'label' => get_string('statsuspicious', 'antivirus_verdict'),
                'count' => (int) ($counts[scan_status::SUSPICIOUS] ?? 0),
                'tone' => 'suspicious',
            ],
            [
                'label' => get_string('statmalicious', 'antivirus_verdict'),
                'count' => (int) ($counts[scan_status::MALICIOUS] ?? 0),
                'tone' => 'malicious',
            ],
        ];
    }

    /**
     * Error-code histogram for the overview.
     *
     * @param int $errortotal Error status count.
     * @return array
     */
    private function error_breakdown_rows(int $errortotal): array {
        $rows = [];
        foreach ($this->service->error_code_counts(5) as $item) {
            $width = $errortotal > 0
                ? (int) round(($item['count'] / $errortotal) * 100)
                : 0;
            $rows[] = [
                'label' => $this->error_code_label($item['errorcode']),
                'count' => $item['count'],
                'widthpct' => max(1, min(100, $width)),
            ];
        }
        return $rows;
    }

    /**
     * User-facing label for a stored error code. Never includes secrets.
     *
     * @param string $code Error code.
     * @return string
     */
    private function error_code_label(string $code): string {
        if (!get_string_manager()->string_exists($code, 'antivirus_verdict')) {
            return $code;
        }
        return get_string($code, 'antivirus_verdict', (object) [
            'item' => get_string('pluginname', 'antivirus_verdict'),
        ]);
    }

    /**
     * Sparkline bars from stored daily volume.
     *
     * @return array
     */
    private function volume_bars(): array {
        $byday = $this->service->volume_by_day(7);
        $max = max(1, max($byday ?: [0]));
        $bars = [];
        $index = 0;
        $last = count($byday) - 1;
        foreach ($byday as $daystart => $count) {
            $bars[] = [
                'count' => $count,
                'heightpct' => (int) round(($count / $max) * 100),
                'label' => userdate((int) $daystart, get_string('strftimedate', 'langconfig')),
                'day' => userdate((int) $daystart, '%a'),
                'isactive' => $index === $last,
            ];
            $index++;
        }
        return $bars;
    }

    /**
     * Donut segments from real status counts.
     *
     * @param array<string,int> $counts Status counts.
     * @return array
     */
    private function donut_segments(array $counts): array {
        $circumference = 301.6;
        $parts = [
            ['tone' => 'clean', 'count' => (int) ($counts[scan_status::CLEAN] ?? 0)],
            ['tone' => 'suspicious', 'count' => (int) ($counts[scan_status::SUSPICIOUS] ?? 0)],
            ['tone' => 'malicious', 'count' => (int) ($counts[scan_status::MALICIOUS] ?? 0)],
            ['tone' => 'error', 'count' => (int) ($counts[scan_status::ERROR] ?? 0)],
            ['tone' => 'pending', 'count' => (int) ($counts[scan_status::PENDING] ?? 0)],
        ];
        $total = 0;
        foreach ($parts as $part) {
            $total += $part['count'];
        }
        if ($total <= 0) {
            return [];
        }
        $offset = 0;
        $segments = [];
        foreach ($parts as $part) {
            if ($part['count'] <= 0) {
                continue;
            }
            $length = ($part['count'] / $total) * $circumference;
            $segments[] = [
                'dash' => round($length, 2),
                'gap' => round($circumference, 2),
                'offset' => round(-$offset, 2),
                'tone' => $part['tone'],
                'label' => $part['tone'] . ' ' . $part['count'],
            ];
            $offset += $length;
        }
        return $segments;
    }

    /**
     * Enforcement log rows for authorised overview viewers.
     *
     * @return array
     */
    private function enforcement_event_rows(): array {
        $rows = [];
        foreach ($this->service->get_enforcement_events(8) as $scan) {
            $course = '';
            if (!empty($scan->courseid)) {
                try {
                    $course = format_string(get_course((int) $scan->courseid)->fullname);
                } catch (\Throwable $unused) {
                    $course = '';
                }
            }
            $rows[] = [
                'time' => !empty($scan->timemodified)
                    ? scan_presenter::format_time((int) $scan->timemodified, true)
                    : get_string('valueempty', 'antivirus_verdict'),
                'filename' => (string) $scan->filename,
                'hascourse' => $course !== '',
                'course' => $course,
                'enforcement' => scan_presenter::enforcement_label((string) ($scan->enforcement ?? '')),
                'status' => scan_presenter::status_label((string) $scan->status),
                'viewurl' => (new \moodle_url('/lib/antivirus/verdict/view.php', ['id' => (int) $scan->id]))->out(false),
                'viewlabel' => get_string('viewdetails', 'antivirus_verdict'),
            ];
        }
        return $rows;
    }

    /**
     * Provider circuit label for the overview.
     *
     * @return string
     */
    private function provider_state_label(): string {
        $state = (string) ($this->service->provider_health_snapshot()['state'] ?? 'closed');
        $key = 'providerstate_' . $state;
        if (get_string_manager()->string_exists($key, 'antivirus_verdict')) {
            return get_string($key, 'antivirus_verdict');
        }
        return $state;
    }

    /**
     * Badge class for provider health.
     *
     * @return string
     */
    private function provider_badge_class(): string {
        $snapshot = $this->service->provider_health_snapshot();
        if (!empty($snapshot['isopen']) || ($snapshot['state'] ?? '') === provider_health::STATE_HALFOPEN) {
            return 'antivirus-verdict-status-chip antivirus-verdict-status-chip--warning';
        }
        return 'antivirus-verdict-status-chip antivirus-verdict-status-chip--enabled';
    }

    /**
     * Explanation of provider circuit state.
     *
     * @return string
     */
    private function provider_message(): string {
        $snapshot = $this->service->provider_health_snapshot();
        if (!empty($snapshot['isopen'])) {
            return get_string('providerstate_open_desc', 'antivirus_verdict');
        }
        return get_string('providerstate_closed_desc', 'antivirus_verdict');
    }

    /**
     * Badge class for dashboard protection headline.
     *
     * @param string $protection Protection state key.
     * @return string
     */
    private function protection_badge_class(string $protection): string {
        return match ($protection) {
            'operational' => 'antivirus-verdict-status-chip antivirus-verdict-status-chip--enabled',
            'provideropen' => 'antivirus-verdict-status-chip antivirus-verdict-status-chip--warning',
            default => 'antivirus-verdict-status-chip antivirus-verdict-status-chip--disabled',
        };
    }

    /**
     * Badge class for scanner state. Always paired with a text label.
     *
     * @return string
     */
    private function scanner_badge_class(): string {
        return match ($this->service->scanner_state()) {
            'enabled' => 'antivirus-verdict-status-chip antivirus-verdict-status-chip--enabled',
            'configrequired' => 'antivirus-verdict-status-chip antivirus-verdict-status-chip--warning',
            default => 'antivirus-verdict-status-chip antivirus-verdict-status-chip--disabled',
        };
    }

    /**
     * Badge class for assignment auto-scan state.
     *
     * @return string
     */
    private function assign_badge_class(): string {
        return match ($this->service->assignment_state()) {
            'enabled' => 'antivirus-verdict-status-chip antivirus-verdict-status-chip--enabled',
            'blockedmaster', 'blockedcredentials' => 'antivirus-verdict-status-chip antivirus-verdict-status-chip--warning',
            default => 'antivirus-verdict-status-chip antivirus-verdict-status-chip--disabled',
        };
    }

    /**
     * User-facing scanner explanation.
     *
     * @return string
     */
    private function scanner_message(): string {
        return match ($this->service->scanner_state()) {
            'enabled' => get_string('scannerstate_enabled_desc', 'antivirus_verdict'),
            'configrequired' => get_string('scannerstate_configrequired_desc', 'antivirus_verdict'),
            default => get_string('scannerstate_disabled_desc', 'antivirus_verdict'),
        };
    }

    /**
     * User-facing assignment auto-scan explanation.
     *
     * @return string
     */
    private function assignment_message(): string {
        return match ($this->service->assignment_state()) {
            'enabled' => get_string('assignstate_enabled_desc', 'antivirus_verdict'),
            'blockedmaster' => get_string('assignstate_blockedmaster_desc', 'antivirus_verdict'),
            'blockedcredentials' => get_string('assignstate_blockedcredentials_desc', 'antivirus_verdict'),
            default => get_string('assignstate_disabled_desc', 'antivirus_verdict'),
        };
    }

    /**
     * First-time configuration steps.
     *
     * @return array
     */
    private function setup_steps(): array {
        return [
            ['text' => get_string('setupstep_credentials', 'antivirus_verdict')],
            ['text' => get_string('setupstep_enable', 'antivirus_verdict')],
            ['text' => get_string('setupstep_assign', 'antivirus_verdict')],
        ];
    }

    /**
     * Single primary setup action for the dashboard banner.
     *
     * @param string $scannerstate disabled, configrequired, or enabled.
     * @param string $settingsurl Plugin settings URL or empty.
     * @param string $manageurl Native antivirus manage URL or empty.
     * @param bool $cansettings Site config capability.
     * @return array{0:string,1:string,2:bool} URL, label, and whether to hide secondary buttons.
     */
    private function setup_primary_action(
        string $scannerstate,
        string $settingsurl,
        string $manageurl,
        bool $cansettings
    ): array {
        if ($scannerstate === 'disabled' && $manageurl !== '') {
            return [$manageurl, get_string('antivirusmanage', 'antivirus_verdict'), true];
        }
        if ($scannerstate === 'configrequired' && $settingsurl !== '' && $cansettings) {
            return [$settingsurl, get_string('opensettings', 'antivirus_verdict'), true];
        }
        return ['', '', false];
    }

    /**
     * Summary cards with optional history links.
     *
     * @param array<string,int> $counts Status counts.
     * @return array
     */
    private function stat_cards(array $counts): array {
        $items = [
            [
                'key' => 'total',
                'label' => get_string('stattotal', 'antivirus_verdict'),
                'status' => '',
            ],
            [
                'key' => scan_status::PENDING,
                'label' => get_string('statpending', 'antivirus_verdict'),
                'status' => scan_status::PENDING,
            ],
            [
                'key' => scan_status::CLEAN,
                'label' => get_string('statclean', 'antivirus_verdict'),
                'status' => scan_status::CLEAN,
            ],
            [
                'key' => scan_status::SUSPICIOUS,
                'label' => get_string('statsuspicious', 'antivirus_verdict'),
                'status' => scan_status::SUSPICIOUS,
            ],
            [
                'key' => scan_status::MALICIOUS,
                'label' => get_string('statmalicious', 'antivirus_verdict'),
                'status' => scan_status::MALICIOUS,
            ],
            [
                'key' => scan_status::ERROR,
                'label' => get_string('staterror', 'antivirus_verdict'),
                'status' => scan_status::ERROR,
            ],
            [
                'key' => scan_status::NOTSCANNED,
                'label' => get_string('statnotscanned', 'antivirus_verdict'),
                'status' => scan_status::NOTSCANNED,
            ],
        ];
        $cards = [];
        foreach ($items as $item) {
            $count = (int) ($counts[$item['key']] ?? 0);
            $url = '';
            if ($item['status'] !== '' && $count > 0) {
                $url = (new \moodle_url('/lib/antivirus/verdict/history.php', ['status' => $item['status']]))->out(false);
            } else if ($item['key'] === 'total' && $count > 0) {
                $url = (new \moodle_url('/lib/antivirus/verdict/history.php'))->out(false);
            }
            $tone = '';
            $celltone = '';
            if ($item['key'] === scan_status::CLEAN) {
                $tone = 'tone-clean';
                $celltone = 'accent';
            } else if ($item['key'] === scan_status::SUSPICIOUS) {
                $tone = 'tone-suspicious';
                $celltone = 'warn';
            } else if ($item['key'] === scan_status::MALICIOUS) {
                $tone = 'tone-malicious';
                $celltone = 'danger';
            } else if ($item['key'] === scan_status::ERROR) {
                $celltone = 'grey';
            } else if ($item['key'] === scan_status::PENDING || $item['key'] === scan_status::NOTSCANNED) {
                $celltone = 'muted';
            }
            $cards[] = [
                'label' => $item['label'],
                'count' => $count,
                'url' => $url,
                'hasurl' => $url !== '',
                'cardclass' => $tone,
                'tone' => $tone,
                'celltone' => $celltone,
                'iszero' => $count === 0,
            ];
        }
        return $cards;
    }

    /**
     * Recent activity rows. Filenames are escaped by Mustache.
     *
     * @param string $empty Placeholder for unknown detection counts.
     * @return array
     */
    private function recent_rows(string $empty): array {
        $rows = [];
        $resolver = new scan_context_resolver();
        foreach ($this->service->get_recent_scans(7) as $scan) {
            $detection = scan_presenter::detection_compact($scan);
            $contextline = $resolver->summary_line($scan);
            $status = (string) $scan->status;
            $hasengines = $scan->totalengines !== null && $scan->totalengines !== ''
                && (int) $scan->totalengines > 0;
            $malicious = $scan->malicious !== null && $scan->malicious !== ''
                ? (int) $scan->malicious
                : null;
            $ext = strtolower(pathinfo((string) $scan->filename, PATHINFO_EXTENSION));
            $rows[] = [
                'filename' => (string) $scan->filename,
                'hascontext' => $contextline !== '',
                'contextline' => $contextline,
                'source' => scan_presenter::source_label((string) $scan->source),
                'status' => scan_presenter::status_label($status),
                'statusclass' => scan_presenter::status_css_class($status),
                'statuspill' => $this->status_pill_class($status),
                'result' => $detection === '' ? $empty : $detection,
                'hasdetection' => $hasengines && $malicious !== null,
                'detectmalicious' => $malicious ?? 0,
                'detecttotal' => $hasengines ? (int) $scan->totalengines : 0,
                'detectsort' => $hasengines && $malicious !== null ? $malicious : -1,
                'fileisarchive' => in_array($ext, ['zip', 'tar', 'gz', 'tgz', 'rar', '7z'], true),
                'fileisimage' => in_array($ext, ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp'], true),
                'queued' => !empty($scan->timecreated)
                    ? scan_presenter::format_time((int) $scan->timecreated)
                    : $empty,
                'completed' => !empty($scan->timecompleted)
                    ? scan_presenter::format_time((int) $scan->timecompleted)
                    : $empty,
                'queuedts' => !empty($scan->timecreated) ? (string) (int) $scan->timecreated : '',
                'completedts' => !empty($scan->timecompleted) ? (string) (int) $scan->timecompleted : '',
                'time' => !empty($scan->timecreated)
                    ? scan_presenter::format_time((int) $scan->timecreated)
                    : $empty,
                'viewurl' => (new \moodle_url('/lib/antivirus/verdict/view.php', ['id' => (int) $scan->id]))->out(false),
                'viewlabel' => get_string('viewdetails', 'antivirus_verdict'),
            ];
        }
        return $rows;
    }

    /**
     * Status pill modifier for the overview table.
     *
     * @param string $status Stored status.
     * @return string
     */
    private function status_pill_class(string $status): string {
        return match ($status) {
            scan_status::CLEAN => 'clean',
            scan_status::MALICIOUS => 'malicious',
            scan_status::SUSPICIOUS => 'suspicious',
            scan_status::PENDING => 'pending',
            default => 'error',
        };
    }

    /**
     * Render recent scans with the same flexible_table chrome as history.
     *
     * @return string
     */
    private function recent_table_html(): string {
        $records = $this->service->get_recent_scans();
        if ($records === []) {
            return '';
        }
        $params = [];
        if ($this->context->contextlevel === \CONTEXT_COURSE) {
            $params['courseid'] = $this->context->instanceid;
        }
        $table = new history_table('antivirus_verdict_recent');
        $table->set_caption(get_string('recentscans', 'antivirus_verdict'), ['class' => 'visually-hidden']);
        return $table->render_records($records, new \moodle_url('/lib/antivirus/verdict/index.php', $params));
    }

    /**
     * Quick action links the current user is allowed to use.
     *
     * @param array<string,int> $counts Status counts.
     * @param string $settingsurl Settings URL, or empty.
     * @param string $manageurl Native Antivirus manage URL, or empty.
     * @return array
     */
    private function actions(array $counts, string $settingsurl, string $manageurl = ''): array {
        $actions = [];
        if (teacher_access::can_use_page('manualscan', $this->context)) {
            $actions[] = [
                'url' => (new \moodle_url('/lib/antivirus/verdict/scan.php'))->out(false),
                'label' => get_string('manualscan', 'antivirus_verdict'),
                'primary' => true,
            ];
        }
        if (teacher_access::can_use_page('bulkscan', $this->context)) {
            $actions[] = [
                'url' => (new \moodle_url('/lib/antivirus/verdict/bulk.php'))->out(false),
                'label' => get_string('bulkscanheading', 'antivirus_verdict'),
            ];
        }
        if (teacher_access::can_use_page('scanhistory', $this->context)) {
            $actions[] = [
                'url' => (new \moodle_url('/lib/antivirus/verdict/history.php'))->out(false),
                'label' => get_string('scanhistory', 'antivirus_verdict'),
            ];
            if (!empty($counts[scan_status::PENDING])) {
                $actions[] = [
                    'url' => (new \moodle_url('/lib/antivirus/verdict/history.php', [
                        'status' => scan_status::PENDING,
                    ]))->out(false),
                    'label' => get_string('viewpending', 'antivirus_verdict'),
                ];
            }
            if (!empty($counts[scan_status::ERROR])) {
                $actions[] = [
                    'url' => (new \moodle_url('/lib/antivirus/verdict/history.php', [
                        'status' => scan_status::ERROR,
                    ]))->out(false),
                    'label' => get_string('viewerrors', 'antivirus_verdict'),
                ];
            }
        }
        if (teacher_access::can_use_page('quarantine', $this->context)) {
            $actions[] = [
                'url' => (new \moodle_url('/lib/antivirus/verdict/quarantine.php'))->out(false),
                'label' => get_string('quarantineheading', 'antivirus_verdict'),
            ];
        }
        if (teacher_access::can_use_page('coverage', $this->context)) {
            $actions[] = [
                'url' => (new \moodle_url('/lib/antivirus/verdict/coverage.php'))->out(false),
                'label' => get_string('coverageheading', 'antivirus_verdict'),
            ];
        }
        if ($settingsurl !== '') {
            $actions[] = [
                'url' => $settingsurl,
                'label' => get_string('opensettings', 'antivirus_verdict'),
            ];
            $actions[] = [
                'url' => (new \moodle_url('/lib/antivirus/verdict/test_connection.php'))->out(false),
                'label' => get_string('testconnection', 'antivirus_verdict'),
            ];
        }
        if ($manageurl !== '') {
            $actions[] = [
                'url' => $manageurl,
                'label' => get_string('antivirusmanage', 'antivirus_verdict'),
            ];
        }
        return $actions;
    }
}
