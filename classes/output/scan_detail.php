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
 * Scan detail templatable.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\output;

use antivirus_verdict\local\scan_context_resolver;
use antivirus_verdict\local\scan_correlation;
use antivirus_verdict\local\scan_presenter;
use antivirus_verdict\local\retry_policy;
use antivirus_verdict\scan_status;
use renderer_base;


/**
 * Exports a scan row for the detail Mustache template.
 */
class scan_detail implements \renderable, \templatable {
    /** @var \stdClass Scan row. */
    private \stdClass $scan;

    /** @var bool Whether to show the cannot-rescan banner. */
    private bool $showrescanunavailable;

    /**
     * Create the scan detail view.
     *
     * @param \stdClass $scan Scan row.
     * @param array $options Extra view flags.
     */
    public function __construct(\stdClass $scan, array $options = []) {
        $this->scan = $scan;
        $this->showrescanunavailable = !empty($options['showrescanunavailable']);
    }

    /**
     * Template context. Values are escaped by Mustache unless marked raw.
     *
     * @param renderer_base $output Renderer.
     * @return array
     */
    public function export_for_template(renderer_base $output): array {
        $scan = $this->scan;
        $detection = scan_presenter::detection_label($scan);
        $reporturl = scan_presenter::report_url($scan);
        $sha256 = trim((string) $scan->sha256);
        $hassha256 = (bool) preg_match('/^[a-f0-9]{64}$/', strtolower($sha256));

        $empty = get_string('valueempty', 'antivirus_verdict');
        $courseid = (int) ($scan->courseid ?? 0);
        $context = (new scan_context_resolver())->resolve($scan);
        $contextexport = $context->export_for_template();
        $contextexport['hascontextsection'] = $context->showscannedby
            || $context->showuploadsession
            || $context->showfileowner
            || $context->showcourse
            || $context->showactivity
            || $context->showactivitytype
            || $context->showsubmission
            || $context->showfilelocation
            || $context->showsubmissionfilelocation;
        $related = (new scan_correlation())->related_scan_link($scan);
        $coursename = $context->showcourse ? $context->course : '';
        $malicious = $scan->malicious === null ? null : (int) $scan->malicious;
        $total = $scan->totalengines === null ? null : (int) $scan->totalengines;
        $detectionpct = 1;
        if ($malicious !== null && $total !== null && $total > 0) {
            $detectionpct = max(1, min(100, (int) round(($malicious / $total) * 100)));
        }

        $enforcement = scan_presenter::enforcement_label((string) ($scan->enforcement ?? ''));

        $historyparams = [];
        if ($courseid > 0) {
            $historyparams['courseid'] = $courseid;
        }

        return [
            'filename' => (string) $scan->filename,
            'source' => scan_presenter::source_label((string) $scan->source),
            'sourcesubtitle' => scan_presenter::source_detail((string) $scan->source),
            'status' => scan_presenter::status_label((string) $scan->status),
            'statusclass' => scan_presenter::status_css_class((string) $scan->status),
            'hasdetection' => $detection !== '',
            'detection' => $detection,
            'detectionpct' => $detectionpct,
            'nodetection' => $detection === '',
            'hasenforcement' => $enforcement !== '',
            'enforcement' => $enforcement,
            'enforcementheading' => get_string('enforcementheading', 'antivirus_verdict'),
            'hasmimetype' => !empty($scan->mimetype),
            'mimetype' => (string) $scan->mimetype,
            'filesize' => display_size((int) $scan->filesize),
            'hassha256' => $hassha256,
            'sha256' => $hassha256 ? strtolower($sha256) : '',
            'queued' => !empty($scan->timecreated) ? scan_presenter::format_time((int) $scan->timecreated, true) : $empty,
            'submitted' => !empty($scan->timesubmitted) ? scan_presenter::format_time((int) $scan->timesubmitted, true) : $empty,
            'completed' => !empty($scan->timecompleted) ? scan_presenter::format_time((int) $scan->timecompleted, true) : $empty,
            'hasreport' => $reporturl !== null,
            'reporturl' => $reporturl ?? '',
            'reportlabel' => get_string('viewonvirustotal', 'antivirus_verdict'),
            'reportheading' => get_string('reportheading', 'antivirus_verdict'),
            'historyurl' => (new \moodle_url('/lib/antivirus/verdict/history.php', $historyparams))->out(false),
            'backlabel' => get_string('backtohistory', 'antivirus_verdict'),
            'hascourse' => $coursename !== '',
            'coursename' => $coursename,
            'context' => $contextexport,
            'outcomemessage' => scan_presenter::outcome_message($scan),
            'ispending' => $scan->status === scan_status::PENDING,
            'pendingmessage' => $scan->status === scan_status::PENDING
                ? (retry_policy::is_transient_unavailability((string) $scan->errorcode)
                    ? scan_presenter::outcome_message($scan)
                    : get_string('scanpendingdetail', 'antivirus_verdict'))
                : '',
            'iserror' => $scan->status === scan_status::ERROR,
            'isnotscanned' => $scan->status === scan_status::NOTSCANNED,
            'outcomeclass' => 'antivirus-verdict-banner',
            'copyhashtitle' => get_string('copyhash', 'antivirus_verdict'),
            'showrescanunavailable' => $this->showrescanunavailable,
            'rescanunavailable' => get_string('error_filenotavailable', 'antivirus_verdict'),
            'dismissbanner' => get_string('dismissbanner', 'antivirus_verdict'),
            'hasrelatedscan' => $related !== null,
            'relatedscanlabel' => $related !== null ? $related['label'] : '',
            'relatedscanurl' => $related !== null ? $related['url'] : '',
            'relatedisgate' => $related !== null && !empty($related['isgate']),
            'relatedisassign' => $related !== null && !empty($related['isassign']),
        ];
    }
}
