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
 * Paginated scan history table.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\output;

use antivirus_verdict\local\scan_context_resolver;
use antivirus_verdict\local\scan_presenter;
use antivirus_verdict\local\scan_repository;


/**
 * SQL table that only queries rows already limited by scan_access.
 */
class history_table extends \table_sql {
    /** Default page size. */
    public const PAGESIZE = 25;

    /** @var string Visible toolbar heading, or empty when the table has none. */
    private string $toolbarheading = '';

    /** @var scan_context_resolver|null Request-level context resolver. */
    private ?scan_context_resolver $contextresolver = null;

    /**
     * Create the history table.
     *
     * @param string $uniqueid Table unique id.
     */
    public function __construct(string $uniqueid) {
        parent::__construct($uniqueid);
        $this->define_columns(['filename', 'source', 'status', 'result', 'timecreated', 'timecompleted', 'view']);
        $this->define_headers([
            get_string('colfilename', 'antivirus_verdict'),
            get_string('colsource', 'antivirus_verdict'),
            get_string('colstatus', 'antivirus_verdict'),
            get_string('colresult', 'antivirus_verdict'),
            get_string('colqueued', 'antivirus_verdict'),
            get_string('colcompleted', 'antivirus_verdict'),
            get_string('coldetails', 'antivirus_verdict'),
        ]);
        $this->sortable(true, 'timecreated', SORT_DESC);
        $this->no_sorting('result');
        $this->no_sorting('view');
        $this->collapsible(false);
        $this->column_class('filename', 'antivirus-verdict-filename');
        $this->column_class('result', 'antivirus-verdict-mono');
        $this->column_class('timecreated', 'antivirus-verdict-time');
        $this->column_class('timecompleted', 'antivirus-verdict-time');
        $this->column_class('view', 'antivirus-verdict-actions');
        $this->set_columnsattributes([
            'filename' => ['data-label' => get_string('colfilename', 'antivirus_verdict')],
            'source' => ['data-label' => get_string('colsource', 'antivirus_verdict')],
            'status' => ['data-label' => get_string('colstatus', 'antivirus_verdict')],
            'result' => ['data-label' => get_string('colresult', 'antivirus_verdict')],
            'timecreated' => ['data-label' => get_string('colqueued', 'antivirus_verdict')],
            'timecompleted' => ['data-label' => get_string('colcompleted', 'antivirus_verdict')],
            'view' => ['data-label' => get_string('coldetails', 'antivirus_verdict')],
        ]);
        $this->set_attribute('class', 'table generaltable antivirus-verdict-table');
        $this->set_caption(get_string('scanhistory', 'antivirus_verdict'), ['class' => 'visually-hidden']);
    }

    /**
     * Place Moodle's reset control on the same row as this heading.
     *
     * @param string $heading Toolbar heading.
     */
    public function set_toolbar_heading(string $heading): void {
        $this->toolbarheading = $heading;
    }

    /**
     * Render already-loaded scan rows with the same table chrome as history.
     *
     * Used by Recent Scans so overview does not invent a second table markup.
     *
     * @param \stdClass[] $records Scan records.
     * @param \moodle_url $baseurl Table base URL.
     * @return string HTML.
     */
    public function render_records(array $records, \moodle_url $baseurl): string {
        $this->define_baseurl($baseurl);
        $this->sortable(false);
        $this->pageable(false);
        $this->collapsible(false);
        $this->setup();
        ob_start();
        $this->format_and_add_array_of_rows($records, true);
        return (string) ob_get_clean();
    }

    /**
     * Keep Moodle's real reset control, aligned with the table heading.
     *
     * @return string
     */
    protected function render_reset_button() {
        $reset = parent::render_reset_button();
        if ($this->toolbarheading === '') {
            return $reset;
        }
        $heading = \html_writer::tag('h1', s($this->toolbarheading), [
            'class' => 'antivirus-verdict-table-heading',
        ]);
        return \html_writer::div($heading . $reset, 'antivirus-verdict-table-toolbar');
    }

    /**
     * Apply the authorised history query.
     *
     * @param int $userid User id.
     * @param array $filters Repository filters.
     */
    public function set_visible_sql(int $userid, array $filters): void {
        $repo = new scan_repository();
        [$where, $params] = $repo->visible_history_where($userid, $filters);
        $this->set_count_sql(
            'SELECT COUNT(1) FROM {' . scan_repository::TABLE . '} WHERE ' . $where,
            $params
        );
        $this->set_sql('*', '{' . scan_repository::TABLE . '}', $where, $params);
    }

    /**
     * Filename cell. User-supplied names are escaped.
     *
     * @param \stdClass $row Scan row.
     * @return string
     */
    public function col_filename(\stdClass $row): string {
        $name = \html_writer::span(s($row->filename), 'antivirus-verdict-history-filename', [
            'title' => (string) $row->filename,
        ]);
        $summary = $this->context_resolver()->summary_line($row);
        if ($summary !== '') {
            $name .= \html_writer::div(s($summary), 'antivirus-verdict-history-context');
        }
        return $name;
    }

    /**
     * Lazy resolver for history rows.
     *
     * @return scan_context_resolver
     */
    private function context_resolver(): scan_context_resolver {
        if ($this->contextresolver === null) {
            $this->contextresolver = new scan_context_resolver();
        }
        return $this->contextresolver;
    }

    /**
     * Source cell.
     *
     * @param \stdClass $row Scan row.
     * @return string
     */
    public function col_source(\stdClass $row): string {
        return s(scan_presenter::source_label((string) $row->source));
    }

    /**
     * Status cell with text and a supporting badge class.
     *
     * @param \stdClass $row Scan row.
     * @return string
     */
    public function col_status(\stdClass $row): string {
        $label = scan_presenter::status_label((string) $row->status);
        $class = scan_presenter::status_css_class((string) $row->status);
        return \html_writer::span(
            \html_writer::span('', 'antivirus-verdict-dot') . s($label),
            $class
        );
    }

    /**
     * Detection counts, or an em dash when unknown.
     *
     * @param \stdClass $row Scan row.
     * @return string
     */
    public function col_result(\stdClass $row): string {
        $label = scan_presenter::detection_compact($row);
        return $label === '' ? get_string('valueempty', 'antivirus_verdict') : s($label);
    }

    /**
     * Queued time.
     *
     * @param \stdClass $row Scan row.
     * @return string
     */
    public function col_timecreated(\stdClass $row): string {
        return scan_presenter::format_time((int) ($row->timecreated ?? 0));
    }

    /**
     * Completed time.
     *
     * @param \stdClass $row Scan row.
     * @return string
     */
    public function col_timecompleted(\stdClass $row): string {
        return scan_presenter::format_time((int) ($row->timecompleted ?? 0));
    }

    /**
     * Detail link.
     *
     * @param \stdClass $row Scan row.
     * @return string
     */
    public function col_view(\stdClass $row): string {
        $url = new \moodle_url('/lib/antivirus/verdict/view.php', ['id' => (int) $row->id]);
        return \html_writer::link($url, get_string('viewdetails', 'antivirus_verdict'));
    }
}
