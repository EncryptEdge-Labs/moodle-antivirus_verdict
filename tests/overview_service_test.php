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
 * Tests for the administrator overview.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\overview_service;
use antivirus_verdict\local\plugin_config;
use antivirus_verdict\local\provider_health;
use antivirus_verdict\local\scan_access;
use antivirus_verdict\local\teacher_access;
use antivirus_verdict\local\scan_repository;
use antivirus_verdict\output\overview;
use antivirus_verdict\tests\test_credentials;


/**
 * Overview access, configuration state, and scan aggregates.
 *
 * @covers \antivirus_verdict\local\overview_service
 * @covers \antivirus_verdict\output\overview
 * @covers \antivirus_verdict\local\scan_repository
 */
final class overview_service_test extends \advanced_testcase {
    /**
     * Managers always see the overview. Teachers see it only after an administrator enables that page.
     */
    public function test_overview_access(): void {
        $this->resetAfterTest();
        $course = $this->getDataGenerator()->create_course();
        $teacher = $this->getDataGenerator()->create_and_enrol($course, 'editingteacher');
        $student = $this->getDataGenerator()->create_and_enrol($course, 'student');
        $manager = $this->create_manager();

        $this->assertTrue(scan_access::can_view_overview((int) $manager->id));
        $this->assertFalse(scan_access::can_view_overview((int) $teacher->id));
        $this->assertFalse(teacher_access::show_in_navigation((int) $teacher->id));
        $this->assertFalse(scan_access::can_view_overview((int) $student->id));

        set_config('teacheraccess', 1, 'antivirus_verdict');
        set_config('teacherpageoverview', 1, 'antivirus_verdict');
        set_config('teacherpagehistory', 0, 'antivirus_verdict');
        $this->assertTrue(scan_access::can_view_overview((int) $teacher->id));
        $this->assertTrue(teacher_access::show_in_navigation((int) $teacher->id));
        $this->assertFalse(teacher_access::allows('scanhistory', (int) $teacher->id));
        $this->assertFalse(scan_access::can_view_overview((int) $student->id));

        set_config('teacheraccess', 0, 'antivirus_verdict');
        $this->assertFalse(scan_access::can_view_overview((int) $teacher->id));
        $this->assertFalse(teacher_access::show_in_navigation((int) $teacher->id));
        $this->assertTrue(teacher_access::page_enabled('overview'));
    }

    /**
     * Teachers with overview access see the same live gate policy card as site managers.
     */
    public function test_teacher_overview_live_policies_match_admin(): void {
        global $CFG, $PAGE;

        $this->resetAfterTest();
        $CFG->antiviruses = 'verdict';
        set_config('apikey', 'unit-test-key', 'antivirus_verdict');
        set_config('teacheraccess', 1, 'antivirus_verdict');
        set_config('teacherpageoverview', 1, 'antivirus_verdict');
        set_config('scanscope', \antivirus_verdict\local\scan_scope::SELECTED_AREAS, 'antivirus_verdict');
        set_config('asyncenforcement', 'report', 'antivirus_verdict');

        $course = $this->getDataGenerator()->create_course();
        $teacher = $this->getDataGenerator()->create_and_enrol($course, 'editingteacher');

        $PAGE->set_url(new \moodle_url('/lib/antivirus/verdict/index.php'));
        $PAGE->set_context(\context_system::instance());
        $renderer = $PAGE->get_renderer('antivirus_verdict');
        $context = \context_system::instance();

        $this->setAdminUser();
        $adminexported = (new overview(overview_service::from_site_config(), $context))
            ->export_for_template($renderer);

        $this->setUser($teacher);
        $teacherservice = overview_service::from_site_config()->for_viewer((int) $teacher->id);
        $teacherexported = (new overview($teacherservice, $context))
            ->export_for_template($renderer);

        $this->assertCount(5, $adminexported['livepolicies']);
        $this->assertSame($adminexported['livepolicies'], $teacherexported['livepolicies']);
        $this->assertSame(
            get_string('scanscope_selectedareas', 'antivirus_verdict'),
            $teacherexported['livepolicies'][3]['value']
        );
        $this->assertSame(
            get_string('dash_policy_reportonly', 'antivirus_verdict'),
            $teacherexported['livepolicies'][4]['value']
        );
        $this->assertSame('block', $teacherexported['livepolicies'][3]['swatch']);
        $this->assertSame('report', $teacherexported['livepolicies'][4]['swatch']);
    }

    /**
     * A teacher's overview counts include only courses they teach.
     */
    public function test_teacher_overview_counts_stay_in_their_courses(): void {
        $this->resetAfterTest();
        $mine = $this->getDataGenerator()->create_course();
        $other = $this->getDataGenerator()->create_course();
        $teacher = $this->getDataGenerator()->create_and_enrol($mine, 'editingteacher');
        $this->insert_scan($mine, scan_status::CLEAN, 'mine.txt', time(), 0, 10);
        $this->insert_scan($other, scan_status::MALICIOUS, 'other.txt', time(), 1, 10);

        $repo = (new scan_repository())->limited_to_viewer((int) $teacher->id);
        $counts = $repo->get_overview_status_counts();
        $this->assertSame(1, $counts['total']);
        $this->assertSame(1, $counts[scan_status::CLEAN]);
        $this->assertSame(0, $counts[scan_status::MALICIOUS]);

        $menu = scan_access::bulk_course_menu((int) $teacher->id);
        $this->assertArrayHasKey((int) $mine->id, $menu);
        $this->assertArrayNotHasKey((int) $other->id, $menu);
    }

    /**
     * Configuration matrix: disabled, missing key, and assignment combinations.
     */
    public function test_configuration_states(): void {
        $this->resetAfterTest();
        $repo = new scan_repository();

        $a = new overview_service($repo, new plugin_config(false, 1024, false), new test_credentials(''));
        $this->assertSame('disabled', $a->scanner_state());
        $this->assertSame('disabled', $a->assignment_state());
        $this->assertFalse($a->is_operational());
        $this->assertFalse($a->has_api_key());

        $b = new overview_service($repo, new plugin_config(true, 1024, false), new test_credentials(''));
        $this->assertSame('configrequired', $b->scanner_state());
        $this->assertFalse($b->is_operational());

        $c = new overview_service($repo, new plugin_config(false, 1024, true), new test_credentials('unit-test-key'));
        $this->assertSame('disabled', $c->scanner_state());
        $this->assertSame('enabled', $c->assignment_state());
        $this->assertTrue($c->has_api_key());
        $this->assertTrue($c->is_assignscan_effective());

        $d = new overview_service($repo, new plugin_config(true, 1024, false), new test_credentials('unit-test-key'));
        $this->assertSame('enabled', $d->scanner_state());
        $this->assertSame('disabled', $d->assignment_state());
        $this->assertTrue($d->is_operational());

        $e = new overview_service($repo, new plugin_config(true, 1024, true), new test_credentials('unit-test-key'));
        $this->assertSame('enabled', $e->scanner_state());
        $this->assertSame('enabled', $e->assignment_state());
        $this->assertTrue($e->is_assignscan_effective());

        $blockedkey = new overview_service(
            $repo,
            new plugin_config(true, 1024, true),
            new test_credentials('')
        );
        $this->assertSame('blockedcredentials', $blockedkey->assignment_state());
    }

    /**
     * Protection headline reflects credentials, enablement, and provider circuit.
     */
    public function test_protection_state(): void {
        $repo = new scan_repository();
        $missing = new overview_service($repo, new plugin_config(false, 1024, false), new test_credentials(''));
        $this->assertSame('configrequired', $missing->protection_state());

        $disabled = new overview_service(
            $repo,
            new plugin_config(false, 1024, true),
            new test_credentials('unit-test-key')
        );
        $this->assertSame('disabled', $disabled->protection_state());

        $operational = new overview_service(
            $repo,
            new plugin_config(true, 1024, false),
            new test_credentials('unit-test-key')
        );
        $this->assertSame('operational', $operational->protection_state());
    }

    /**
     * Status counts use stored status, including an empty table.
     */
    public function test_status_counts(): void {
        $this->resetAfterTest();
        $course = $this->getDataGenerator()->create_course();
        $service = $this->make_operational_service();

        $empty = $service->get_status_counts();
        $this->assertSame(0, $empty['total']);
        $this->assertSame(0, $empty[scan_status::PENDING]);
        $this->assertSame(0, $empty[scan_status::CLEAN]);

        $this->insert_scan($course, scan_status::PENDING, 'a.pdf', time(), null, null);
        $this->insert_scan($course, scan_status::CLEAN, 'b.pdf', time(), 0, 70);
        $this->insert_scan($course, scan_status::SUSPICIOUS, 'c.pdf', time(), 0, 12);
        $this->insert_scan($course, scan_status::MALICIOUS, 'd.pdf', time(), 4, 40);
        $this->insert_scan($course, scan_status::ERROR, 'e.pdf', time(), null, null);
        $this->insert_scan($course, scan_status::NOTSCANNED, 'f.pdf', time(), null, null);

        $counts = $service->get_status_counts();
        $this->assertSame(6, $counts['total']);
        $this->assertSame(1, $counts[scan_status::PENDING]);
        $this->assertSame(1, $counts[scan_status::CLEAN]);
        $this->assertSame(1, $counts[scan_status::SUSPICIOUS]);
        $this->assertSame(1, $counts[scan_status::MALICIOUS]);
        $this->assertSame(1, $counts[scan_status::ERROR]);
        $this->assertSame(1, $counts[scan_status::NOTSCANNED]);
        $known = $counts[scan_status::PENDING] + $counts[scan_status::CLEAN]
            + $counts[scan_status::SUSPICIOUS] + $counts[scan_status::MALICIOUS]
            + $counts[scan_status::ERROR] + $counts[scan_status::NOTSCANNED];
        $this->assertSame($counts['total'], $known);
    }

    /**
     * Recent activity is newest first and limited.
     */
    public function test_recent_scans_order_and_limit(): void {
        $this->resetAfterTest();
        $course = $this->getDataGenerator()->create_course();
        $service = $this->make_operational_service();
        $base = time();
        for ($i = 1; $i <= 12; $i++) {
            $this->insert_scan($course, scan_status::CLEAN, "file{$i}.pdf", $base + $i, 0, 8);
        }

        $recent = $service->get_recent_scans(overview_service::RECENT_LIMIT);
        $this->assertCount(10, $recent);
        $first = reset($recent);
        $last = end($recent);
        $this->assertSame('file12.pdf', $first->filename);
        $this->assertSame('file3.pdf', $last->filename);
        $this->assertGreaterThanOrEqual((int) $last->timecreated, (int) $first->timecreated);
    }

    /**
     * Last 24 hours uses timecreated, not PHP-side filtering of the full table.
     */
    public function test_recent_window_counts(): void {
        $this->resetAfterTest();
        $course = $this->getDataGenerator()->create_course();
        $service = $this->make_operational_service();
        $this->insert_scan($course, scan_status::CLEAN, 'new.pdf', time(), 0, 8);
        $this->insert_scan($course, scan_status::CLEAN, 'old.pdf', time() - (8 * DAYSECS), 0, 8);

        $this->assertSame(1, $service->count_last_24_hours());
        $this->assertSame(1, $service->count_last_7_days());
        $this->assertSame(2, $service->get_status_counts()['total']);
    }

    /**
     * Dedup metrics use distinct SHA-256 values, not invented money saved.
     */
    public function test_deduplication_snapshot_uses_hashes(): void {
        $this->resetAfterTest();
        $course = $this->getDataGenerator()->create_course();
        $service = $this->make_operational_service();
        $this->insert_hashed_scan($course, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
        $this->insert_hashed_scan($course, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
        $this->insert_hashed_scan($course, 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');
        $snap = $service->deduplication_snapshot();
        $this->assertSame(3, $snap['completed']);
        $this->assertSame(2, $snap['uniquehashes']);
        $this->assertSame(1, $snap['reused']);
    }

    /**
     * Overview export uses labels, stored SHA-256 is omitted, and the API key never appears.
     */
    public function test_overview_export_is_safe(): void {
        global $PAGE;

        $this->resetAfterTest();
        $course = $this->getDataGenerator()->create_course();
        $this->setAdminUser();
        $this->insert_scan(
            $course,
            scan_status::PENDING,
            '<script>x</script>.bin',
            time(),
            null,
            null
        );
        $service = $this->make_operational_service();
        $PAGE->set_url(new \moodle_url('/lib/antivirus/verdict/index.php'));
        $PAGE->set_context(\context_system::instance());
        $exported = (new overview($service, \context_system::instance()))
            ->export_for_template($PAGE->get_renderer('antivirus_verdict'));

        $this->assertSame('enabled', $service->scanner_state());
        $this->assertFalse($exported['needssetup']);
        $this->assertArrayNotHasKey('apikey', $exported);
        $json = json_encode($exported);
        $this->assertStringNotContainsString('x-apikey', $json);
        $this->assertStringNotContainsString('unit-test-key', $json);
        $this->assertStringNotContainsString('/var/', $json);
        $this->assertStringNotContainsString('C:\\', $json);
        $this->assertNotEmpty($exported['recent']);
        $row = $exported['recent'][0];
        $this->assertSame('<script>x</script>.bin', $row['filename']);
        $this->assertSame(get_string('source_manual', 'antivirus_verdict'), $row['source']);
        $this->assertSame(get_string('status_pending', 'antivirus_verdict'), $row['status']);
        $this->assertSame(get_string('valueempty', 'antivirus_verdict'), $row['result']);
        $this->assertStringContainsString('view.php', $row['viewurl']);
        $this->assertArrayNotHasKey('sha256', $row);
        $this->assertArrayNotHasKey('filepath', $row);
        $this->assertArrayNotHasKey('contenthash', $row);

        $template = file_get_contents(__DIR__ . '/../templates/overview.mustache');
        $this->assertStringNotContainsString('{{{filename}}}', $template);
        $this->assertStringContainsString('visually-hidden', $template);
        $this->assertStringContainsString('antivirus-verdict-radar-sweep', $template);
        $this->assertStringNotContainsString('fetch(', $template);
        $this->assertStringNotContainsString('setInterval', $template);

        $css = file_get_contents(__DIR__ . '/../styles.css');
        $this->assertStringNotContainsString('100vw', $css);
        $this->assertStringContainsString('prefers-reduced-motion', $css);
        $this->assertStringContainsString('antivirus-verdict-spin', $css);
        $this->assertStringContainsString('text-decoration: none', $css);
        $this->assertDoesNotMatchRegularExpression(
            '/\.antivirus-verdict a:hover\s*\{[^}]*text-decoration:\s*underline/s',
            $css
        );
        $this->assertStringContainsString('--lv-btn-primary-text: #062522', $css);
        $this->assertStringContainsString('a.antivirus-verdict-btn-primary:hover', $css);
        $this->assertStringContainsString('color: var(--lv-btn-primary-text)', $css);
        $this->assertStringContainsString('antivirus-verdict-status-grid', $css);
        $this->assertSame(get_string('dash_systemhealth', 'antivirus_verdict'), $exported['dashhealthheading']);
        $this->assertCount(4, $exported['nativesites']);
        $this->assertFalse($exported['donutempty']);
        $this->assertFalse($exported['hasenforcementevents']);
        $this->assertSame(get_string('dash_enforcementempty', 'antivirus_verdict'), $exported['enforcementemptytext']);
        $this->assertCount(5, $exported['pendingphases']);
        $this->assertCount(5, $exported['livepolicies']);
        $policylabels = array_column($exported['livepolicies'], 'label');
        $this->assertSame(get_string('unknownpolicy', 'antivirus_verdict'), $policylabels[0]);
        $this->assertSame(get_string('suspiciouspolicy', 'antivirus_verdict'), $policylabels[1]);
        $this->assertSame(get_string('providererrorpolicy', 'antivirus_verdict'), $policylabels[2]);
        $this->assertSame(get_string('scanscope', 'antivirus_verdict'), $policylabels[3]);
        $this->assertSame(get_string('asyncenforcement', 'antivirus_verdict'), $policylabels[4]);
        foreach ($exported['livepolicies'] as $policyrow) {
            $this->assertContains($policyrow['swatch'], ['allow', 'block', 'report']);
        }
        $this->assertSame(
            get_string('policy_quarantine', 'antivirus_verdict'),
            $exported['livepolicies'][4]['value']
        );
        $this->assertSame(1, $exported['pendingphases'][0]['count']);
        $this->assertFalse($exported['haserrorbreakdown']);
        $this->assertSame(0, $exported['archivemalicious']);
        $this->assertTrue($exported['scannerradaractive']);
        $this->assertTrue($exported['providerradaractive']);
        $this->assertSame($exported['scannerradaractive'], $exported['scannerpillon']);
        $this->assertSame($exported['providerradaractive'], $exported['providerpillon']);
        $this->assertSame(get_string('scannerstate_enabled', 'antivirus_verdict'), $exported['scannerstatelabel']);
        $this->assertSame(get_string('providerstate_closed', 'antivirus_verdict'), $exported['providerstate']);
    }

    /**
     * Overview radar motion follows scanner operational state and circuit state.
     */
    public function test_radar_motion_follows_backend_state(): void {
        global $PAGE;

        $this->resetAfterTest();
        $this->setAdminUser();
        $PAGE->set_url(new \moodle_url('/lib/antivirus/verdict/index.php'));
        $PAGE->set_context(\context_system::instance());
        $renderer = $PAGE->get_renderer('antivirus_verdict');
        $repo = new scan_repository();

        $operational = new overview_service(
            $repo,
            new plugin_config(true, 1024, false),
            new test_credentials('unit-test-key')
        );
        $this->assertTrue($operational->is_operational());
        $this->assertTrue($operational->scanner_radar_active());
        $exported = (new overview($operational, \context_system::instance()))->export_for_template($renderer);
        $this->assertTrue($exported['scannerradaractive']);
        $this->assertSame($exported['scannerstatelabel'], get_string('scannerstate_enabled', 'antivirus_verdict'));
        $this->assertSame($exported['scannerradaractive'], $exported['scannerpillon']);

        $disabled = new overview_service(
            $repo,
            new plugin_config(false, 1024, false),
            new test_credentials('unit-test-key')
        );
        $this->assertFalse($disabled->is_operational());
        $this->assertFalse($disabled->scanner_radar_active());
        $exported = (new overview($disabled, \context_system::instance()))->export_for_template($renderer);
        $this->assertFalse($exported['scannerradaractive']);
        $this->assertSame($exported['scannerstatelabel'], get_string('scannerstate_disabled', 'antivirus_verdict'));

        $nkey = new overview_service(
            $repo,
            new plugin_config(true, 1024, false),
            new test_credentials('')
        );
        $this->assertSame('configrequired', $nkey->scanner_state());
        $this->assertFalse($nkey->is_operational());
        $this->assertFalse($nkey->scanner_radar_active());
        $exported = (new overview($nkey, \context_system::instance()))->export_for_template($renderer);
        $this->assertFalse($exported['scannerradaractive']);
        $this->assertSame(
            $exported['scannerstatelabel'],
            get_string('scannerstate_configrequired', 'antivirus_verdict')
        );

        $health = new provider_health();
        $this->assertTrue($operational->provider_radar_active());
        $exported = (new overview($operational, \context_system::instance()))->export_for_template($renderer);
        $this->assertTrue($exported['providerradaractive']);
        $this->assertSame($exported['providerstate'], get_string('providerstate_closed', 'antivirus_verdict'));
        $this->assertSame($exported['providerradaractive'], $exported['providerpillon']);

        for ($i = 0; $i < provider_health::FAILURE_THRESHOLD; $i++) {
            $health->record_failure();
        }
        $this->assertSame(provider_health::STATE_OPEN, $health->dashboard_snapshot()['state']);
        $this->assertFalse($operational->provider_radar_active());
        $exported = (new overview($operational, \context_system::instance()))->export_for_template($renderer);
        $this->assertFalse($exported['providerradaractive']);
        $this->assertSame($exported['providerstate'], get_string('providerstate_open', 'antivirus_verdict'));
        $this->assertSame($exported['providerradaractive'], $exported['providerpillon']);

        $cache = \cache::make('antivirus_verdict', provider_health::CACHE_AREA);
        $cache->set(provider_health::CACHE_KEY, [
            'state' => provider_health::STATE_HALFOPEN,
            'failures' => provider_health::FAILURE_THRESHOLD,
            'openuntil' => time() + 60,
        ]);
        $this->assertFalse($operational->provider_radar_active());
        $exported = (new overview($operational, \context_system::instance()))->export_for_template($renderer);
        $this->assertFalse($exported['providerradaractive']);
        $this->assertSame($exported['providerstate'], get_string('providerstate_halfopen', 'antivirus_verdict'));

        $cache->set(provider_health::CACHE_KEY, [
            'state' => provider_health::STATE_OPEN,
            'failures' => provider_health::FAILURE_THRESHOLD,
            'openuntil' => time() + 60,
        ]);
        $this->assertFalse($operational->provider_radar_active());
        $exported = (new overview($operational, \context_system::instance()))->export_for_template($renderer);
        $this->assertFalse($exported['providerradaractive']);
        $this->assertSame($exported['providerstate'], get_string('providerstate_open', 'antivirus_verdict'));
        $this->assertSame($exported['providerradaractive'], $exported['providerpillon']);

        $health->record_success();
        $this->assertTrue($operational->provider_radar_active());
        $health->record_failure();
        $this->assertSame(provider_health::STATE_CLOSED, $health->dashboard_snapshot()['state']);
        $this->assertTrue($operational->provider_radar_active());
        $exported = (new overview($operational, \context_system::instance()))->export_for_template($renderer);
        $this->assertTrue($exported['providerradaractive']);
        $this->assertSame($exported['providerstate'], get_string('providerstate_closed', 'antivirus_verdict'));

        $template = file_get_contents(__DIR__ . '/../templates/overview.mustache');
        $this->assertStringContainsString('{{^scannerradaractive}} is-paused{{/scannerradaractive}}', $template);
        $this->assertStringContainsString('{{^providerradaractive}} is-paused{{/providerradaractive}}', $template);
        $this->assertStringNotContainsString('{{#scannerenabled}}', $template);
        $css = file_get_contents(__DIR__ . '/../styles.css');
        $this->assertStringContainsString('animation-play-state: paused', $css);
        $this->assertStringContainsString('.antivirus-verdict-ov-radar.is-paused', $css);
        $this->assertStringContainsString('html[data-antivirus-verdict-theme="light"] .antivirus-verdict-ov', $css);
        $this->assertStringContainsString('--ov-donut-track', $css);
        $this->assertStringContainsString('--ov-row-hover', $css);
        $this->assertStringNotContainsString('#161D24', $template);
    }

    /**
     * Overview and shell markup include responsive overflow and accessible names.
     */
    public function test_responsive_accessibility_markup(): void {
        $template = file_get_contents(__DIR__ . '/../templates/overview.mustache');
        $this->assertStringContainsString('antivirus-verdict-ov-banner-body', $template);
        $this->assertStringContainsString('antivirus-verdict-ov-banner-actions', $template);
        $this->assertStringContainsString('antivirus-verdict-ov-tablescroll', $template);
        $this->assertStringContainsString('antivirus-verdict-topline', $template);
        $this->assertStringContainsString('antivirus-verdict-title', $template);
        $this->assertStringContainsString('antivirus-verdict-rule', $template);
        $this->assertStringContainsString('antivirus-verdict-subtitle', $template);
        $this->assertStringNotContainsString('antivirus-verdict-ov-title', $template);
        $this->assertStringContainsString('aria-label="{{periodgroup}}"', $template);
        $this->assertStringContainsString('aria-pressed="true"', $template);
        $this->assertStringContainsString('aria-sort="none"', $template);
        $this->assertStringContainsString('{{status}}', $template);
        $this->assertStringContainsString('table generaltable antivirus-verdict-ov-table', $template);

        $css = file_get_contents(__DIR__ . '/../styles.css');
        $this->assertStringContainsString('border-left: 0 !important', $css);
        $this->assertStringContainsString('font-weight: 700', $css);
        $this->assertStringContainsString('--ov-bg: var(--lv-panel)', $css);
        $this->assertStringContainsString('a.antivirus-verdict-topbar-scan', $css);
        $this->assertStringContainsString('a.antivirus-verdict-ov-qa--primary', $css);
        $this->assertStringContainsString('flex: 0 0 30px', $css);
        $this->assertStringContainsString('height: var(--lv-chrome-height)', $css);
        $this->assertStringContainsString('min-width: 920px', $css);
        $this->assertStringContainsString('@media (max-width: 560px)', $css);
        $this->assertStringContainsString('@media (max-width: 400px)', $css);
        $this->assertStringContainsString('antivirus-verdict-navbackdrop', $css);
        $this->assertStringContainsString('outline: 2px solid var(--lv-accent)', $css);
        $this->assertStringContainsString('.antivirus-verdict-filterbar .mform select:focus', $css);

        $js = file_get_contents(__DIR__ . '/../javascript/ui.js');
        $this->assertStringContainsString("event.key !== 'Escape'", $js);
        $this->assertStringContainsString("setAttribute('aria-pressed'", $js);
        $this->assertStringContainsString("setAttribute('aria-sort'", $js);
        $this->assertStringContainsString('initNavDrawer', $js);
    }

    /**
     * Error breakdown and archive malicious members come from stored scan rows.
     */
    public function test_error_breakdown_and_archive_malicious_members(): void {
        $this->resetAfterTest();
        $course = $this->getDataGenerator()->create_course();
        $service = $this->make_operational_service();
        $first = $this->insert_scan($course, scan_status::ERROR, 'a.bin', time(), null, null);
        $first->errorcode = 'error_network';
        (new scan_repository())->update($first);
        $second = $this->insert_scan($course, scan_status::ERROR, 'b.bin', time(), null, null);
        $second->errorcode = 'error_network';
        (new scan_repository())->update($second);
        $third = $this->insert_scan($course, scan_status::ERROR, 'c.bin', time(), null, null);
        $third->errorcode = 'error_ratelimit';
        (new scan_repository())->update($third);

        $counts = $service->error_code_counts(5);
        $this->assertCount(2, $counts);
        $this->assertSame('error_network', $counts[0]['errorcode']);
        $this->assertSame(2, $counts[0]['count']);
        $this->assertSame('error_ratelimit', $counts[1]['errorcode']);
        $this->assertSame(1, $counts[1]['count']);

        $parent = $this->insert_scan($course, scan_status::CLEAN, 'pack.zip', time(), 0, 8);
        $member = $this->insert_scan($course, scan_status::MALICIOUS, 'eicar.com', time(), 1, 8);
        $member->parentscanid = (int) $parent->id;
        (new scan_repository())->update($member);
        $snap = $service->archive_snapshot();
        $this->assertSame(1, $snap['maliciousmembers']);
        $this->assertSame(1, $snap['members']);
    }

    /**
     * Pending and error counts become history links. Null detections stay an em dash.
     */
    public function test_stat_links_and_null_detections(): void {
        global $PAGE;

        $this->resetAfterTest();
        $course = $this->getDataGenerator()->create_course();
        $this->setAdminUser();
        $this->insert_scan($course, scan_status::PENDING, 'wait.bin', time(), null, null);
        $this->insert_scan($course, scan_status::ERROR, 'fail.bin', time(), null, null);
        $service = $this->make_operational_service();
        $PAGE->set_url(new \moodle_url('/lib/antivirus/verdict/index.php'));
        $PAGE->set_context(\context_system::instance());
        $exported = (new overview($service, \context_system::instance()))
            ->export_for_template($PAGE->get_renderer('antivirus_verdict'));

        $bylabel = [];
        foreach ($exported['stats'] as $card) {
            $bylabel[$card['label']] = $card;
        }
        $this->assertSame(1, $bylabel[get_string('statpending', 'antivirus_verdict')]['count']);
        $this->assertTrue($bylabel[get_string('statpending', 'antivirus_verdict')]['hasurl']);
        $this->assertStringContainsString('status=pending', $bylabel[get_string('statpending', 'antivirus_verdict')]['url']);
        $this->assertTrue($bylabel[get_string('staterror', 'antivirus_verdict')]['hasurl']);
        $this->assertSame(0, $bylabel[get_string('statclean', 'antivirus_verdict')]['count']);
        $this->assertFalse($bylabel[get_string('statclean', 'antivirus_verdict')]['hasurl']);
        $this->assertSame(get_string('valueempty', 'antivirus_verdict'), $exported['recent'][0]['result']);
        $this->assertStringNotContainsString('0 / 0', $exported['recent'][0]['result']);
    }

    /**
     * Settings strings describe assignment dependency and non-blocking behaviour.
     */
    public function test_settings_strings(): void {
        $assign = get_string('assignscan_desc', 'antivirus_verdict');
        $this->assertStringContainsString('asynchronously', $assign);
        $this->assertStringContainsString('never blocked', $assign);
        $this->assertStringContainsString('not prevent submission', $assign);
        $this->assertStringContainsString('backfill', $assign);
        $enabled = get_string('enabled_desc', 'antivirus_verdict');
        $this->assertStringContainsString('$CFG->antiviruses', $enabled);
        $manage = get_string('antivirusenabled_page', 'antivirus_verdict');
        $this->assertStringContainsString('Plugins → Antivirus plugins', $manage);
        $this->assertStringContainsString('Manage antivirus plugins', $manage);
    }

    /**
     * Overview PHP files do not call the VirusTotal client.
     */
    public function test_overview_does_not_call_provider(): void {
        global $CFG;
        $files = [
            $CFG->dirroot . '/lib/antivirus/verdict/index.php',
            $CFG->dirroot . '/lib/antivirus/verdict/classes/local/overview_service.php',
            $CFG->dirroot . '/lib/antivirus/verdict/classes/output/overview.php',
            $CFG->dirroot . '/lib/antivirus/verdict/templates/overview.mustache',
        ];
        foreach ($files as $path) {
            $source = file_get_contents($path);
            $this->assertStringNotContainsString('virustotal\\client', $source);
            $this->assertStringNotContainsString('lookup_file_hash', $source);
            $this->assertStringNotContainsString('upload_file', $source);
            $this->assertStringNotContainsString('get_analysis', $source);
            $this->assertStringNotContainsString('curl_', $source);
        }
    }

    /**
     * Build an operational overview service.
     *
     * @return overview_service
     */
    private function make_operational_service(): overview_service {
        return new overview_service(
            new scan_repository(),
            new plugin_config(true, 1048576, false),
            new test_credentials('unit-test-key')
        );
    }

    /**
     * Assign the manager role at system context.
     *
     * @return \stdClass
     */
    private function create_manager(): \stdClass {
        global $DB;
        $user = $this->getDataGenerator()->create_user();
        $roleid = $DB->get_field('role', 'id', ['shortname' => 'manager'], \MUST_EXIST);
        role_assign($roleid, $user->id, \context_system::instance()->id);
        return $user;
    }

    /**
     * Insert a scan row.
     *
     * @param \stdClass $course Course.
     * @param string $status Status.
     * @param string $filename File name.
     * @param int $timecreated Created time.
     * @param int|null $malicious Malicious count.
     * @param int|null $totalengines Total engines.
     * @return \stdClass
     */
    private function insert_scan(
        \stdClass $course,
        string $status,
        string $filename,
        int $timecreated,
        ?int $malicious,
        ?int $totalengines
    ): \stdClass {
        $repo = new scan_repository();
        $context = \context_course::instance($course->id);
        $record = (object) [
            'fileid' => 0,
            'contenthash' => sha1($filename . $timecreated),
            'pathnamehash' => sha1($filename . $course->id . $timecreated),
            'contextid' => $context->id,
            'courseid' => $course->id,
            'component' => 'antivirus_verdict',
            'filearea' => 'unittest',
            'itemid' => random_int(1, 1000000),
            'filepath' => '/',
            'filename' => $filename,
            'userid' => 2,
            'source' => scan_source::MANUAL,
            'sha256' => '',
            'filesize' => 10,
            'mimetype' => 'application/octet-stream',
            'status' => $status,
            'phase' => $status === scan_status::PENDING ? scan_phase::QUEUED : scan_phase::COMPLETED,
            'vtanalysisid' => null,
            'vtfileid' => null,
            'malicious' => $malicious,
            'suspicious' => null,
            'undetected' => null,
            'harmless' => null,
            'timeout' => null,
            'totalengines' => $totalengines,
            'errorcode' => null,
            'pollattempts' => 0,
            'timelastpoll' => 0,
            'timesubmitted' => 0,
            'timecreated' => $timecreated,
            'timemodified' => $timecreated,
            'timecompleted' => $status === scan_status::PENDING ? 0 : $timecreated,
        ];
        $record->id = $repo->insert($record);
        return $record;
    }

    /**
     * Completed hashed scan for dedup tests.
     *
     * @param \stdClass $course Course.
     * @param string $sha256 SHA-256.
     */
    private function insert_hashed_scan(\stdClass $course, string $sha256): void {
        $record = $this->insert_scan($course, scan_status::CLEAN, $sha256 . '.bin', time(), 0, 8);
        $record->sha256 = $sha256;
        (new scan_repository())->update($record);
    }
}
