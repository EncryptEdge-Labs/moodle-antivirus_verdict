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
 * Tests for scan presentation and page access.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\access;
use antivirus_verdict\local\page;
use antivirus_verdict\local\scan_access;
use antivirus_verdict\local\scan_presenter;
use antivirus_verdict\output\history_table;
use antivirus_verdict\output\scan_detail;


/**
 * UI presentation and capability gates.
 *
 * @covers \antivirus_verdict\local\scan_presenter
 * @covers \antivirus_verdict\output\scan_detail
 * @covers \antivirus_verdict\output\history_table
 * @covers \antivirus_verdict\local\page
 */
final class scan_ui_test extends \advanced_testcase {
    /**
     * Status labels, detection counts, SHA-256, and report links.
     */
    public function test_presenter_states_and_counts(): void {
        $this->resetAfterTest();
        $hash = str_repeat('a', 64);

        $pending = $this->scan_row(scan_status::PENDING, null, null, '');
        $this->assertSame(
            get_string('status_pending', 'antivirus_verdict'),
            scan_presenter::status_label(scan_status::PENDING)
        );
        $this->assertSame('', scan_presenter::detection_label($pending));
        $this->assertSame('', scan_presenter::detection_compact($pending));
        $this->assertNull(scan_presenter::report_url($pending));
        $this->assertStringContainsString('queued', scan_presenter::outcome_message($pending));

        $clean = $this->scan_row(scan_status::CLEAN, 0, 70, $hash);
        $this->assertSame(
            get_string('detectioncounts', 'antivirus_verdict', (object) ['malicious' => 0, 'total' => 70]),
            scan_presenter::detection_label($clean)
        );
        $this->assertSame(
            get_string('detectioncompact', 'antivirus_verdict', (object) ['malicious' => 0, 'total' => 70]),
            scan_presenter::detection_compact($clean)
        );
        $this->assertSame('https://www.virustotal.com/gui/file/' . $hash, scan_presenter::report_url($clean));

        $suspicious = $this->scan_row(scan_status::SUSPICIOUS, 0, 12, $hash);
        $suspicious->suspicious = 2;
        $this->assertSame(
            get_string('status_suspicious', 'antivirus_verdict'),
            scan_presenter::status_label(scan_status::SUSPICIOUS)
        );

        $malicious = $this->scan_row(scan_status::MALICIOUS, 4, 40, $hash);
        $this->assertSame(
            get_string('detectioncounts', 'antivirus_verdict', (object) ['malicious' => 4, 'total' => 40]),
            scan_presenter::detection_label($malicious)
        );

        $error = $this->scan_row(scan_status::ERROR, null, null, '');
        $error->errorcode = 'error_network';
        $this->assertSame(get_string('error_network', 'antivirus_verdict'), scan_presenter::outcome_message($error));

        $skipped = $this->scan_row(scan_status::NOTSCANNED, null, null, '');
        $skipped->errorcode = 'error_filetoolarge';
        $this->assertSame(
            get_string('error_filetoolarge', 'antivirus_verdict'),
            scan_presenter::outcome_message($skipped)
        );
        $this->assertNotEquals(
            get_string('status_clean', 'antivirus_verdict'),
            scan_presenter::status_label(scan_status::NOTSCANNED)
        );
    }

    /**
     * Manual submit copy matches the persisted scan state.
     */
    public function test_manual_submit_notification_matches_status(): void {
        $this->resetAfterTest();

        $pending = $this->scan_row(scan_status::PENDING, null, null, '');
        [$pendingmsg, $pendinglevel] = scan_presenter::manual_submit_notification($pending);
        $this->assertSame(get_string('scanqueued', 'antivirus_verdict'), $pendingmsg);
        $this->assertSame(\core\output\notification::NOTIFY_SUCCESS, $pendinglevel);

        $clean = $this->scan_row(scan_status::CLEAN, 0, 10, str_repeat('a', 64));
        [$cleanmsg, $cleanlevel] = scan_presenter::manual_submit_notification($clean);
        $this->assertSame(get_string('scanclean', 'antivirus_verdict'), $cleanmsg);
        $this->assertSame(\core\output\notification::NOTIFY_SUCCESS, $cleanlevel);
        $this->assertStringNotContainsString('queued for background scanning', $cleanmsg);

        $malicious = $this->scan_row(scan_status::MALICIOUS, 4, 40, str_repeat('a', 64));
        $malicious->filename = 'eicar.com';
        [$malmsg, $mallevel] = scan_presenter::manual_submit_notification($malicious);
        $this->assertSame(
            get_string('scanmalicious', 'antivirus_verdict', (object) ['filename' => 'eicar.com']),
            $malmsg
        );
        $this->assertSame(\core\output\notification::NOTIFY_ERROR, $mallevel);

        $error = $this->scan_row(scan_status::ERROR, null, null, '');
        $error->errorcode = 'error_maxattempts';
        [$errormsg, $errorlevel] = scan_presenter::manual_submit_notification($error);
        $this->assertSame(get_string('error_maxattempts', 'antivirus_verdict'), $errormsg);
        $this->assertSame(\core\output\notification::NOTIFY_ERROR, $errorlevel);
        $this->assertStringNotContainsString('queued for background scanning', $errormsg);

        $limited = $this->scan_row(scan_status::PENDING, null, null, '');
        $limited->errorcode = 'error_ratelimit';
        [$rlmsg, $rllevel] = scan_presenter::manual_submit_notification($limited);
        $this->assertSame(get_string('error_ratelimit_queued', 'antivirus_verdict'), $rlmsg);
        $this->assertSame(\core\output\notification::NOTIFY_INFO, $rllevel);
    }

    /**
     * Detail export uses stored SHA-256 and never includes credentials or contenthash.
     */
    public function test_detail_export_is_safe(): void {
        $this->resetAfterTest();
        $hash = str_repeat('b', 64);
        $row = $this->scan_row(scan_status::CLEAN, 0, 8, $hash);
        $row->contenthash = str_repeat('c', 40);
        $row->filename = '<script>alert(1)</script>.pdf';
        $detail = new scan_detail($row);
        $exported = $detail->export_for_template($this->page_renderer());
        $this->assertSame($hash, $exported['sha256']);
        $this->assertNotSame($row->contenthash, $exported['sha256']);
        $this->assertTrue($exported['hasreport']);
        $this->assertArrayNotHasKey('apikey', $exported);
        $json = json_encode($exported);
        $this->assertStringNotContainsString('x-apikey', $json);
        $this->assertStringNotContainsString($row->contenthash, $json);
        $this->assertSame('<script>alert(1)</script>.pdf', $exported['filename']);
        $this->assertSame('antivirus-verdict-banner', $exported['outcomeclass']);
        $this->assertFalse($exported['showrescanunavailable']);
        $this->assertSame(get_string('copyhash', 'antivirus_verdict'), $exported['copyhashtitle']);
        $this->assertStringContainsString('/lib/antivirus/verdict/history.php', $exported['historyurl']);
        $this->assertStringContainsString('www.virustotal.com/gui/file/', $exported['reporturl']);
        $error = $this->scan_row(scan_status::ERROR, null, null, '');
        $error->errorcode = 'error_network';
        $errorexport = (new scan_detail($error))->export_for_template($this->page_renderer());
        $this->assertSame('antivirus-verdict-banner', $errorexport['outcomeclass']);
        $this->assertSame(get_string('error_network', 'antivirus_verdict'), $errorexport['outcomemessage']);
        $this->assertArrayNotHasKey('phase', $errorexport);
    }

    /**
     * History table escapes filenames and does not print zero for unknown counts.
     */
    public function test_history_table_escapes_filename(): void {
        $this->resetAfterTest();
        $table = new history_table('antivirus_verdict_history_test');
        $row = $this->scan_row(scan_status::PENDING, null, null, '');
        $row->filename = '<script>x</script>.bin';
        $html = $table->col_filename($row);
        $this->assertStringNotContainsString('<script>', $html);
        $this->assertStringContainsString('&lt;script&gt;', $html);
        $this->assertStringContainsString('title="&lt;script&gt;x&lt;/script&gt;.bin"', $html);
        $this->assertTrue($table->is_sortable('timecreated'));
        $this->assertSame(get_string('valueempty', 'antivirus_verdict'), $table->col_result($row));
        $this->assertStringNotContainsString('0 / 0', $table->col_result($row));
    }

    /**
     * Authorised teachers can open scan and history pages. Students cannot.
     */
    public function test_page_setup_capabilities(): void {
        global $PAGE;

        $this->resetAfterTest();
        set_config('teacheraccess', 1, 'antivirus_verdict');
        $course = $this->getDataGenerator()->create_course();
        $teacher = $this->getDataGenerator()->create_and_enrol($course, 'editingteacher');
        $student = $this->getDataGenerator()->create_and_enrol($course, 'student');
        $coursecontext = \context_course::instance($course->id);

        $this->setUser($teacher);
        $this->assertTrue(scan_access::can_scan($coursecontext, (int) $teacher->id));
        $this->assertTrue(scan_access::can_view_history_page($coursecontext, (int) $teacher->id));
        access::require_access($coursecontext, 'antivirus/verdict:scan');

        $PAGE = new \moodle_page();
        $_GET['courseid'] = $course->id;
        $context = page::setup('scan.php', 'manualscan', 'antivirus/verdict:scan');
        $this->assertSame((int) $coursecontext->id, (int) $context->id);

        $this->setUser($student);
        $this->assertFalse(scan_access::can_scan($coursecontext, (int) $student->id));
        $PAGE = new \moodle_page();
        $this->expectException(\required_capability_exception::class);
        page::setup('scan.php', 'manualscan', 'antivirus/verdict:scan');
    }

    /**
     * Scan detail is a standalone Verdict page, including assignment-origin scans.
     */
    public function test_view_php_is_standalone_verdict_page(): void {
        global $CFG;
        $source = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/view.php');
        $this->assertStringContainsString('/lib/antivirus/verdict/view.php', $source);
        $this->assertStringContainsString('pluginbrand', $source);
        $this->assertStringContainsString('apply_site_application_chrome', $source);
        $this->assertStringContainsString('context_system::instance()', $source);
        $this->assertStringNotContainsString('$displaycontext', $source);
        $this->assertStringNotContainsString('require_login(get_course', $source);
        $this->assertStringNotContainsString('mod/assign', $source);
        $this->assertStringNotContainsString('intro', $source);
        $this->assertStringNotContainsString('get_coursemodule_from_id', $source);
        $this->assertStringNotContainsString('$PAGE->set_context($displaycontext)', $source);
        $pagephp = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/classes/local/page.php');
        $this->assertStringContainsString('activityheader', $pagephp);
        $this->assertStringContainsString('disable', $pagephp);
        $this->assertStringContainsString("set_pagelayout('report')", $pagephp);
        $this->assertStringContainsString('$PAGE->set_course($SITE)', $pagephp);
        $this->assertStringContainsString('javascript/ui.js', $pagephp);
        $this->assertStringContainsString("javascript/theme-boot.js'), true)", $pagephp);
        $this->assertStringContainsString("set_primary_active_tab('antivirus_verdict')", $pagephp);
        $hooks = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/classes/local/hook_callbacks.php');
        $this->assertStringContainsString('make_active()', $hooks);
        $this->assertStringContainsString('/lib/antivirus/verdict/', $hooks);
        $this->assertStringNotContainsString("set_pagelayout('standard')", $pagephp);
        $this->assertStringContainsString('product_start', $source);
        $this->assertTrue(get_string_manager()->string_exists('scandetail', 'antivirus_verdict'));
        $historyphp = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/history.php');
        $this->assertStringContainsString("apply_site_application_chrome('scanhistory')", $historyphp);
        $this->assertStringContainsString('can_access_course(', $historyphp);
        $this->assertStringNotContainsString('require_login($course)', $historyphp);
        $this->assertStringNotContainsString("page::prepare('history.php'", $historyphp);
        $this->assertStringNotContainsString("page::setup('history.php'", $historyphp);
        $detailphp = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/classes/output/scan_detail.php');
        $this->assertStringContainsString('/lib/antivirus/verdict/history.php', $detailphp);
        $this->assertStringNotContainsString('/course/view.php', $detailphp);
        $this->assertStringContainsString('reportlabel', file_get_contents(
            $CFG->dirroot . '/lib/antivirus/verdict/templates/scan_detail.mustache'
        ));
        $this->assertStringContainsString('target="_blank"', file_get_contents(
            $CFG->dirroot . '/lib/antivirus/verdict/templates/scan_detail.mustache'
        ));
        $scanphp = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/scan.php');
        $this->assertStringContainsString('/lib/antivirus/verdict/view.php', $scanphp);
        $bulkphp = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/bulk.php');
        $this->assertStringContainsString('antivirus-verdict-subtitle--full', $bulkphp);
        $this->assertStringContainsString('bulkscanwarning', $bulkphp);
        $this->assertStringNotContainsString('bulkscanintro', $bulkphp);
        $bulkform = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/classes/form/bulk_scan_form.php');
        $this->assertStringNotContainsString('bulkscanpurpose', $bulkform);
        $this->assertStringContainsString('antivirus-verdict-field-hint', $bulkform);
        $this->assertStringContainsString('bulkscanonlymissing_desc', $bulkform);
        $detailtpl = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/templates/scan_detail.mustache');
        $this->assertStringContainsString('data-antivirus-verdict="copy-hash"', $detailtpl);
        $this->assertStringContainsString('data-antivirus-verdict="dismiss-banner"', $detailtpl);
        $this->assertStringContainsString('antivirus-verdict-title-text', $detailtpl);
        $this->assertStringContainsString('title="{{filename}}"', $detailtpl);
        $overviewtpl = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/templates/overview.mustache');
        $this->assertStringContainsString('antivirus-verdict-ov', $overviewtpl);
        $this->assertStringContainsString('/lib/antivirus/verdict/configure.php', $overviewtpl);
        $this->assertStringContainsString('antivirus-verdict-status-grid', $overviewtpl);
        $this->assertStringContainsString('dashhealthheading', $overviewtpl);
        $historytable = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/classes/output/history_table.php');
        $this->assertStringContainsString("'title'", $historytable);
    }

    /**
     * History detail links stay on the Verdict view page.
     */
    public function test_history_detail_link_is_verdict_view(): void {
        $this->resetAfterTest();
        $table = new history_table('antivirus_verdict_history_test');
        $row = $this->scan_row(scan_status::CLEAN, 0, 10, str_repeat('a', 64));
        $html = $table->col_view($row);
        $this->assertStringContainsString('/lib/antivirus/verdict/view.php', $html);
        $this->assertStringContainsString('id=1', $html);
        $this->assertStringNotContainsString('/mod/assign/', $html);
        $this->assertStringContainsString('antivirus-verdict-badge', $table->col_status($row));
    }

    /**
     * History context sits in a visible cell class, not Bootstrap muted/hidden helpers.
     */
    public function test_history_context_uses_visible_verdict_class(): void {
        global $CFG;

        $this->resetAfterTest();
        $css = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/styles.css');
        $this->assertStringContainsString('.antivirus-verdict-history-context', $css);
        $this->assertStringNotContainsString('td.antivirus-verdict-filename span {', $css);
        $tablephp = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/classes/output/history_table.php');
        $this->assertStringContainsString('antivirus-verdict-history-context', $tablephp);
        $this->assertStringNotContainsString('text-muted', $tablephp);
        $this->assertStringContainsString('antivirus-verdict-history-filename', $tablephp);
        $this->assertStringContainsString('/lib/antivirus/verdict/view.php', $tablephp);
        $this->assertStringContainsString("column_class('view', 'antivirus-verdict-actions')", $tablephp);
        $this->assertStringContainsString("'data-label' => get_string('colstatus', 'antivirus_verdict')", $tablephp);
    }

    /**
     * Overview radars reverse clockwise rotation, and the bulk select is relatively positioned.
     */
    public function test_overview_radar_and_select_css_contract(): void {
        global $CFG;

        $this->resetAfterTest();
        $css = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/styles.css');
        $this->assertStringContainsString('transform: rotate(-360deg)', $css);
        $this->assertStringNotContainsString("@keyframes antivirus-verdict-ov-spin { to { transform: rotate(360deg); } }", $css);
        $this->assertStringContainsString('.antivirus-verdict-select {', $css);
        $this->assertStringContainsString('.antivirus-verdict-actions', $css);
        $this->assertStringContainsString('.antivirus-verdict-scanform .mform .fitem_actionbuttons.row', $css);
        $this->assertStringContainsString('.antivirus-verdict-scanform .mform .d-flex.flex-wrap > .fitem', $css);
        $this->assertStringContainsString('.antivirus-verdict-btn-row', $css);
        $this->assertStringContainsString('.antivirus-verdict-scanform .fitem_fadvcheckbox .form-check-label', $css);
        $this->assertStringContainsString('@media (max-width: 1024px)', $css);
        $this->assertStringNotContainsString('@media (max-width: 860px)', $css);
        $this->assertStringContainsString('.antivirus-verdict-history-table table.generaltable', $css);
        $this->assertStringContainsString('content: attr(data-label)', $css);
        $this->assertStringContainsString('min-width: 0;', $css);
        $this->assertStringContainsString('.antivirus-verdict-topbar {', $css);
        $this->assertStringContainsString('flex-wrap: wrap;', $css);
        $this->assertStringContainsString('body.antivirus-verdict-app #page-footer', $css);
        $this->assertStringContainsString('min-height: 100dvh', $css);
    }

    /**
     * Shared chrome uses Verdict banners, badges, and timestamps — not Boost helpers.
     */
    public function test_shared_surfaces_use_verdict_chrome(): void {
        global $CFG;

        $this->resetAfterTest();
        $plugindir = $CFG->dirroot . '/lib/antivirus/verdict';
        $coverage = file_get_contents($plugindir . '/templates/coverage.mustache');
        $this->assertStringContainsString('antivirus-verdict-history-context', $coverage);
        $this->assertStringContainsString('antivirus-verdict-badge', $coverage);
        $this->assertStringNotContainsString('text-muted', $coverage);
        $this->assertStringNotContainsString('coverage-state', $coverage);

        $overviewsrc = file_get_contents($plugindir . '/classes/local/overview_service.php');
        $this->assertStringContainsString('count_quarantine_inventory()', $overviewsrc);
        $this->assertStringNotContainsString('count_by_enforcement([', $overviewsrc);

        $renderer = file_get_contents($plugindir . '/classes/output/renderer.php');
        $this->assertStringContainsString("antivirus-verdict-banner", $renderer);
        $this->assertStringNotContainsString('NOTIFY_INFO', $renderer);

        $testconn = file_get_contents($plugindir . '/test_connection.php');
        $this->assertStringContainsString('antivirus-verdict-topline', $testconn);
        $this->assertStringContainsString('antivirus-verdict-banner--ok', $testconn);
        $this->assertStringNotContainsString('OUTPUT->notification', $testconn);

        $inventory = file_get_contents($plugindir . '/classes/local/quarantine_inventory.php');
        $this->assertStringContainsString('scan_presenter::format_time((int) $match->timecreated)', $inventory);
        $this->assertStringNotContainsString('userdate((int) $match->timecreated)', $inventory);
    }

    /**
     * GET scan.php?id= is a detail alias, not a queue action.
     */
    public function test_scan_php_get_id_redirects_to_view(): void {
        global $CFG;

        $scanphp = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/scan.php');
        $this->assertStringContainsString("optional_param('id', 0, PARAM_INT)", $scanphp);
        $this->assertStringContainsString("empty(\$_POST)", $scanphp);
        $this->assertStringContainsString('/lib/antivirus/verdict/view.php', $scanphp);
        $this->assertStringNotContainsString('queue_from_draft', explode('if ($data = $form->get_data())', $scanphp)[0]);
    }

    /**
     * Detail GET does not call scan creation APIs. Rescan is POST + sesskey only.
     */
    public function test_detail_get_does_not_queue_scans(): void {
        global $CFG;

        $view = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/view.php');
        $this->assertStringContainsString('rescan_form', $view);
        $this->assertStringContainsString('get_data()', $view);
        $this->assertStringContainsString('require_sesskey()', $view);
        $this->assertStringNotContainsString('queue_file_scan', $view);
        $this->assertStringNotContainsString('queue_from_draft', $view);
        $this->assertDoesNotMatchRegularExpression('/\$_GET\[.rescan/', $view);
        $scanphp = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/scan.php');
        $this->assertStringContainsString('get_data()', $scanphp);
        $this->assertStringContainsString('require_sesskey()', $scanphp);
    }

    /**
     * Related-gate copy is a Mustache lang string, never a raw [[relatedgatescan]] token.
     */
    public function test_related_scan_block_omitted_or_translated(): void {
        $this->resetAfterTest();
        $row = $this->scan_row(scan_status::CLEAN, 0, 10, str_repeat('a', 64));
        $export = (new scan_detail($row))->export_for_template($this->page_renderer());
        $this->assertFalse($export['hasrelatedscan']);
        $this->assertSame('', $export['relatedscanurl']);
        $html = $this->page_renderer()->render(new scan_detail($row));
        $this->assertStringNotContainsString('[[relatedgatescan]]', $html);
        $this->assertStringNotContainsString('[[relatedassignscan]]', $html);

        $tpl = file_get_contents($GLOBALS['CFG']->dirroot . '/lib/antivirus/verdict/templates/scan_detail.mustache');
        $this->assertStringContainsString('{{#hasrelatedscan}}', $tpl);
        $this->assertStringContainsString('{{#str}}relatedgatescan, antivirus_verdict{{/str}}', $tpl);
        $this->assertStringContainsString('{{#str}}relatedassignscan, antivirus_verdict{{/str}}', $tpl);
        $this->assertStringNotContainsString('[[relatedgatescan]]', $tpl);
        $corr = file_get_contents($GLOBALS['CFG']->dirroot . '/lib/antivirus/verdict/classes/local/scan_correlation.php');
        $this->assertStringContainsString('/lib/antivirus/verdict/view.php', $corr);
        $this->assertStringNotContainsString("scan.php', ['id' => \$relatedid]", $corr);
    }

    public function test_ui_does_not_call_virustotal_client(): void {
        global $CFG;
        $files = [
            $CFG->dirroot . '/lib/antivirus/verdict/scan.php',
            $CFG->dirroot . '/lib/antivirus/verdict/history.php',
            $CFG->dirroot . '/lib/antivirus/verdict/view.php',
            $CFG->dirroot . '/lib/antivirus/verdict/index.php',
            $CFG->dirroot . '/lib/antivirus/verdict/configure.php',
            $CFG->dirroot . '/lib/antivirus/verdict/classes/local/manual_scan.php',
            $CFG->dirroot . '/lib/antivirus/verdict/classes/local/scan_presenter.php',
            $CFG->dirroot . '/lib/antivirus/verdict/classes/output/renderer.php',
            $CFG->dirroot . '/lib/antivirus/verdict/classes/output/history_table.php',
            $CFG->dirroot . '/lib/antivirus/verdict/classes/output/scan_detail.php',
            $CFG->dirroot . '/lib/antivirus/verdict/classes/local/overview_service.php',
            $CFG->dirroot . '/lib/antivirus/verdict/classes/output/overview.php',
            $CFG->dirroot . '/lib/antivirus/verdict/classes/output/settings_page.php',
            $CFG->dirroot . '/lib/antivirus/verdict/classes/local/rescan.php',
            $CFG->dirroot . '/lib/antivirus/verdict/classes/form/rescan_form.php',
            $CFG->dirroot . '/lib/antivirus/verdict/classes/local/plugin_file_lifecycle.php',
            $CFG->dirroot . '/lib/antivirus/verdict/classes/task/recover_stale_scans.php',
        ];
        foreach ($files as $path) {
            $source = file_get_contents($path);
            $this->assertStringNotContainsString('virustotal\\client', $source);
            $this->assertStringNotContainsString('curl_', $source);
            $this->assertStringNotContainsString('$_FILES', $source);
            $this->assertStringNotContainsString('lookup_file_hash', $source);
            $this->assertStringNotContainsString('upload_file', $source);
            $this->assertStringNotContainsString('get_analysis', $source);
            $this->assertStringNotContainsString('setInterval', $source);
            $this->assertDoesNotMatchRegularExpression('/\bfetch\s*\(/', $source);
        }
    }

    /**
     * Build a scan row for presentation tests.
     *
     * @param string $status Status.
     * @param int|null $malicious Malicious count.
     * @param int|null $total Total engines.
     * @param string $sha256 SHA-256.
     * @return \stdClass
     */
    private function scan_row(string $status, ?int $malicious, ?int $total, string $sha256): \stdClass {
        return (object) [
            'id' => 1,
            'contextid' => (int) \context_system::instance()->id,
            'courseid' => 0,
            'userid' => 0,
            'initiatedby' => 0,
            'submissionid' => 0,
            'component' => 'antivirus_verdict',
            'filearea' => 'manual',
            'filename' => 'file.bin',
            'source' => scan_source::MANUAL,
            'status' => $status,
            'malicious' => $malicious,
            'suspicious' => null,
            'undetected' => null,
            'harmless' => null,
            'timeout' => null,
            'totalengines' => $total,
            'sha256' => $sha256,
            'mimetype' => 'application/octet-stream',
            'filesize' => 12,
            'errorcode' => null,
            'timecreated' => time(),
            'timesubmitted' => 0,
            'timecompleted' => 0,
            'contenthash' => str_repeat('d', 40),
        ];
    }

    /**
     * Plugin renderer for templatable export.
     *
     * @return \renderer_base
     */
    private function page_renderer(): \renderer_base {
        global $PAGE;
        $PAGE->set_url(new \moodle_url('/lib/antivirus/verdict/view.php'));
        $PAGE->set_context(\context_system::instance());
        return $PAGE->get_renderer('antivirus_verdict');
    }
}
