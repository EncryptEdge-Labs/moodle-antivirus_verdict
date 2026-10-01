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
 * Plain-text and HTML bodies for Verdict scan alert messages.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

use antivirus_verdict\scan_status;


/**
 * Builds professional notification copy from a persisted scan row.
 */
class scan_notification_content {
    /**
     * Compose subject and bodies for a terminal scan alert.
     *
     * @param \stdClass $record Scan row after persistence.
     * @return array{subject:string,bodyplain:string,bodyhtml:string,smallmessage:string,contextlabel:string}
     */
    public static function compose(\stdClass $record): array {
        global $SITE;

        $status = (string) $record->status;
        $context = self::template_context($record);
        $subjectkey = match ($status) {
            scan_status::MALICIOUS => 'notificationsubject_malicious',
            scan_status::SUSPICIOUS => 'notificationsubject_suspicious',
            scan_status::ERROR => 'notificationsubject_error',
            default => 'notificationsubject_malicious',
        };

        return [
            'subject' => get_string($subjectkey, 'antivirus_verdict', $context),
            'bodyplain' => get_string('notificationbody', 'antivirus_verdict', $context),
            'bodyhtml' => self::html_body($context, (string) format_string($SITE->fullname)),
            'smallmessage' => get_string('notificationsmall', 'antivirus_verdict', $context),
            'contextlabel' => get_string('notificationviewaction', 'antivirus_verdict'),
        ];
    }

    /**
     * Placeholders shared by plain and HTML templates.
     *
     * @param \stdClass $record Scan row.
     * @return \stdClass
     */
    private static function template_context(\stdClass $record): \stdClass {
        global $SITE;

        $status = (string) $record->status;
        $scanid = (int) $record->id;
        $url = (new \moodle_url('/lib/antivirus/verdict/view.php', ['id' => $scanid]))->out(false);
        $filename = (string) $record->filename;
        $statuslabel = scan_presenter::status_label($status);
        $sourcelabel = scan_presenter::source_label((string) $record->source);
        $coursename = self::course_label($record);
        $detectionvalue = self::detection_value($record);
        $enforcementvalue = scan_presenter::enforcement_label((string) ($record->enforcement ?? ''));
        $detectionline = $detectionvalue !== ''
            ? "\n" . get_string('notificationfield_detection_label', 'antivirus_verdict') . ': ' . $detectionvalue
            : '';
        $enforcementline = $enforcementvalue !== ''
            ? "\n" . get_string('notificationfield_enforcement_label', 'antivirus_verdict') . ': ' . $enforcementvalue
            : '';
        $headline = get_string('notificationheadline_' . $status, 'antivirus_verdict');
        $intro = get_string('notificationintro_' . $status, 'antivirus_verdict');

        return (object) [
            'sitename' => format_string($SITE->fullname),
            'product' => get_string('pluginbrand', 'antivirus_verdict'),
            'headline' => $headline,
            'intro' => $intro,
            'filename' => $filename,
            'status' => $statuslabel,
            'source' => $sourcelabel,
            'coursename' => $coursename,
            'detectionvalue' => $detectionvalue,
            'enforcementvalue' => $enforcementvalue,
            'detectionline' => $detectionline,
            'enforcementline' => $enforcementline,
            'url' => $url,
            'footer' => get_string('notificationfooter', 'antivirus_verdict', (object) [
                'sitename' => format_string($SITE->fullname),
                'product' => get_string('pluginbrand', 'antivirus_verdict'),
            ]),
            'labelfile' => get_string('notificationfield_file', 'antivirus_verdict'),
            'labelcourse' => get_string('notificationfield_course', 'antivirus_verdict'),
            'labelsource' => get_string('notificationfield_source', 'antivirus_verdict'),
            'labelstatus' => get_string('notificationfield_status', 'antivirus_verdict'),
            'labelreview' => get_string('notificationfield_review', 'antivirus_verdict'),
        ];
    }

    /**
     * Human-readable course name for the scan row.
     *
     * @param \stdClass $record Scan row.
     * @return string
     */
    private static function course_label(\stdClass $record): string {
        $courseid = (int) ($record->courseid ?? 0);
        if ($courseid <= 0 || $courseid === (int) SITEID) {
            return get_string('notificationcourse_site', 'antivirus_verdict');
        }
        $course = get_course($courseid, false);
        if (!$course) {
            return get_string('notificationcourse_unknown', 'antivirus_verdict');
        }
        $context = \context_course::instance($courseid, IGNORE_MISSING);
        if (!$context) {
            return format_string($course->fullname);
        }
        return format_string($course->fullname, true, ['context' => $context]);
    }

    /**
     * Optional engine summary line for plain-text templates.
     *
     * @param \stdClass $record Scan row.
     * @return string Empty when no engine data.
     */
    private static function detection_value(\stdClass $record): string {
        $total = (int) ($record->totalengines ?? 0);
        if ($total <= 0) {
            return '';
        }
        return get_string('notificationfield_detection', 'antivirus_verdict', (object) [
            'malicious' => (int) ($record->malicious ?? 0),
            'suspicious' => (int) ($record->suspicious ?? 0),
            'total' => $total,
        ]);
    }

    /**
     * HTML email body with inline styles for common clients.
     *
     * @param \stdClass $context Template placeholders (already language strings).
     * @param string $sitename Site full name, escaped for HTML.
     * @return string
     */
    private static function html_body(\stdClass $context, string $sitename): string {
        $accent = '#168f84';
        $rows = [
            [get_string('notificationfield_file', 'antivirus_verdict'), $context->filename],
            [get_string('notificationfield_course', 'antivirus_verdict'), $context->coursename],
            [get_string('notificationfield_source', 'antivirus_verdict'), $context->source],
            [get_string('notificationfield_status', 'antivirus_verdict'), $context->status],
        ];
        if ($context->detectionvalue !== '') {
            $rows[] = [get_string('notificationfield_detection_label', 'antivirus_verdict'), $context->detectionvalue];
        }
        if ($context->enforcementvalue !== '') {
            $rows[] = [get_string('notificationfield_enforcement_label', 'antivirus_verdict'), $context->enforcementvalue];
        }

        $tablecells = '';
        foreach ($rows as [$label, $value]) {
            $tablecells .= \html_writer::tag(
                'tr',
                \html_writer::tag('th', s($label), [
                    'scope' => 'row',
                    'style' => 'text-align:left;padding:8px 12px 8px 0;color:#4f6469;font-weight:600;vertical-align:top;width:34%;',
                ]) .
                \html_writer::tag('td', s($value), [
                    'style' => 'padding:8px 0;color:#163038;vertical-align:top;',
                ])
            );
        }

        $button = \html_writer::link(
            $context->url,
            get_string('notificationviewaction', 'antivirus_verdict'),
            [
                'style' => 'display:inline-block;margin-top:18px;padding:10px 18px;background:' . $accent .
                    ';color:#ffffff;text-decoration:none;border-radius:6px;font-weight:600;font-size:14px;',
            ]
        );

        $inner = \html_writer::tag('p', s($context->product), [
            'style' => 'margin:0 0 4px;font-size:12px;font-weight:600;letter-spacing:0.04em;text-transform:uppercase;color:' .
                $accent . ';',
        ]) .
        \html_writer::tag('h1', s($context->headline), [
            'style' => 'margin:0 0 12px;font-size:20px;line-height:1.35;color:#163038;font-weight:700;',
        ]) .
        \html_writer::tag('p', s($context->intro), [
            'style' => 'margin:0 0 18px;font-size:14px;line-height:1.55;color:#4f6469;',
        ]) .
        \html_writer::tag('table', $tablecells, [
            'style' => 'width:100%;border-collapse:collapse;font-size:14px;line-height:1.45;',
        ]) .
        $button .
        \html_writer::tag('p', s($context->footer), [
            'style' => 'margin:22px 0 0;font-size:12px;line-height:1.5;color:#6b7f84;',
        ]);

        return \html_writer::div($inner, '', [
            'style' => 'font-family:Segoe UI,Helvetica Neue,Helvetica,Arial,sans-serif;max-width:560px;padding:24px;' .
                'border:1px solid #e3e9ea;border-radius:10px;background:#ffffff;',
        ]);
    }
}
