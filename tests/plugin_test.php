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
 * Foundation tests for the antivirus_verdict plugin.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;


/**
 * Verifies plugin installation metadata, capabilities, and schema.
 *
 * @covers \antivirus_verdict\scan_status
 * @covers \antivirus_verdict\scan_phase
 * @covers \antivirus_verdict\scan_source
 */
final class plugin_test extends \advanced_testcase {
    /**
     * Plugin config version is stored after installation.
     */
    public function test_plugin_is_installed(): void {
        $this->resetAfterTest();
        $version = get_config('antivirus_verdict', 'version');
        $this->assertNotEmpty($version);
    }

    /**
     * Required capabilities exist.
     */
    public function test_capabilities_are_defined(): void {
        global $DB;

        $this->resetAfterTest();
        $expected = [
            'antivirus/verdict:manage',
            'antivirus/verdict:scan',
            'antivirus/verdict:viewreports',
            'antivirus/verdict:viewhistory',
            'antivirus/verdict:rescan',
        ];
        foreach ($expected as $capability) {
            $this->assertTrue(
                $DB->record_exists('capabilities', ['name' => $capability]),
                'Missing capability: ' . $capability
            );
        }
    }

    /**
     * Scan table is created from install.xml.
     */
    public function test_scans_table_exists(): void {
        global $DB;

        $this->resetAfterTest();
        $this->assertTrue($DB->get_manager()->table_exists('antivirus_verdict_scans'));
        $columns = $DB->get_columns('antivirus_verdict_scans');
        $this->assertArrayHasKey('fileid', $columns);
        $this->assertArrayHasKey('vtfileid', $columns);
        $this->assertArrayHasKey('timesubmitted', $columns);
        $this->assertArrayHasKey('sha256', $columns);
        $hastimecreated = false;
        foreach ($DB->get_indexes('antivirus_verdict_scans') as $index) {
            if (!empty($index['columns']) && in_array('timecreated', $index['columns'], true)) {
                $hastimecreated = true;
                break;
            }
        }
        $this->assertTrue($hastimecreated, 'Expected a timecreated index on antivirus_verdict_scans');
    }

    /**
     * Release metadata matches version.php.
     */
    public function test_release_metadata(): void {
        global $CFG;
        $plugin = new \stdClass();
        include($CFG->dirroot . '/lib/antivirus/verdict/version.php');
        $this->assertSame(2026092801, $plugin->version);
        $this->assertSame('1.0.0', $plugin->release);
        $this->assertSame('antivirus_verdict', $plugin->component);
        $this->assertSame(\MATURITY_STABLE, $plugin->maturity);
        $this->assertSame(2024100700, $plugin->requires);
        $this->assertSame([405, 502], $plugin->supported);
    }

    /**
     * Moodle plugin overview uses pix/icon.png. The shell keeps dark and light marks.
     */
    public function test_plugin_icon_exists(): void {
        global $CFG;

        $icon = $CFG->dirroot . '/lib/antivirus/verdict/pix/icon-dark-mode.png';
        $this->assertFileExists($icon);
        $info = getimagesize($icon);
        $this->assertNotFalse($info);
        $this->assertSame('image/png', $info['mime']);
        $light = $CFG->dirroot . '/lib/antivirus/verdict/pix/icon-light-mode.png';
        $this->assertFileExists($light);
        $lightinfo = getimagesize($light);
        $this->assertNotFalse($lightinfo);
        $this->assertSame('image/png', $lightinfo['mime']);
        $pluginicon = $CFG->dirroot . '/lib/antivirus/verdict/pix/icon.png';
        $this->assertFileExists($pluginicon);
        $pluginiconinfo = getimagesize($pluginicon);
        $this->assertNotFalse($pluginiconinfo);
        $this->assertSame('image/png', $pluginiconinfo['mime']);
        $this->assertFileDoesNotExist($CFG->dirroot . '/lib/antivirus/verdict/pix/icon1.png');
        $template = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/templates/product_start.mustache');
        $this->assertStringContainsString('{{brandiconurl}}', $template);
        $this->assertStringContainsString('{{brandiconlighturl}}', $template);
        $this->assertStringContainsString('antivirus-verdict-brand-mark', $template);
        $this->assertStringContainsString('data-antivirus-verdict="theme-toggle"', $template);
        $this->assertStringContainsString('aria-current="page"', $template);
        $this->assertStringContainsString('antivirus-verdict-navbackdrop', $template);
        $this->assertStringContainsString('aria-label="{{crumbnav}}"', $template);
        $this->assertStringContainsString('{{poweredby}}', $template);
        $this->assertStringContainsString('antivirus-verdict-pulse{{^scannerlive}} is-paused{{/scannerlive}}', $template);
        $this->assertStringNotContainsString('{{versionlabel}}', $template);
        $renderer = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/classes/output/renderer.php');
        $this->assertStringContainsString("image_url('icon-dark-mode', 'antivirus_verdict')", $renderer);
        $this->assertStringContainsString("image_url('icon-light-mode', 'antivirus_verdict')", $renderer);
        $this->assertStringNotContainsString("image_url('icon', 'antivirus_verdict')", $renderer);
        $this->assertStringContainsString('scannerlive', $renderer);
        $this->assertStringNotContainsString("image_url('icon1', 'antivirus_verdict')", $renderer);
        $hooks = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/classes/local/hook_callbacks.php');
        $this->assertStringContainsString("pix_icon('icon-dark-mode'", $hooks);
        $form = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/classes/form/history_filter_form.php');
        $this->assertStringContainsString('filterfilenameplaceholder', $form);
        $this->assertStringContainsString("'placeholder'", $form);
    }

    /**
     * Important user-facing language strings exist.
     */
    public function test_required_language_strings_exist(): void {
        $keys = [
            'pluginname',
            'pluginbrand',
            'privacy:metadata',
            'status_pending',
            'status_clean',
            'status_suspicious',
            'status_malicious',
            'status_error',
            'status_notscanned',
            'error_disabled',
            'error_nokey',
            'error_generic',
            'error_ratelimit_queued',
            'error_providerunavailable_queued',
            'connection_success',
            'rescanintro',
            'scanfile_help',
            'operationheading',
            'scandetail',
            'navoverview',
            'themetoggle',
            'themetolight',
            'themetodark',
            'settingscrumb',
            'privacy:path:copies',
            'privacy:metadata:scans:pollattempts',
            'nativestatusheading',
            'antivirusmanage',
            'scannerstate_configured',
            'crumbnav',
            'ov_periodgroup',
            'filterfilenameplaceholder',
        ];
        foreach ($keys as $key) {
            $this->assertTrue(
                get_string_manager()->string_exists($key, 'antivirus_verdict'),
                'Missing language string: ' . $key
            );
            $this->assertNotEmpty(get_string($key, 'antivirus_verdict'));
        }
        $this->assertSame('Verdict', get_string('pluginbrand', 'antivirus_verdict'));
        $this->assertSame('Verdict for Moodle', get_string('brandproduct', 'antivirus_verdict'));
        $this->assertSame('Setting', get_string('settingscrumb', 'antivirus_verdict'));
        $this->assertSame('Verdict for Moodle', get_string('pluginname', 'antivirus_verdict'));
        $this->assertSame('Search file name', get_string('filterfilenameplaceholder', 'antivirus_verdict'));
        $this->assertNotEquals(
            get_string('status_clean', 'antivirus_verdict'),
            get_string('status_notscanned', 'antivirus_verdict')
        );
        $this->assertNotEquals(
            get_string('status_clean', 'antivirus_verdict'),
            get_string('status_pending', 'antivirus_verdict')
        );
    }

    /**
     * Domain constants are stable values used by the schema.
     */
    public function test_domain_constants(): void {
        $this->assertSame('pending', scan_status::PENDING);
        $this->assertContains(scan_status::NOTSCANNED, scan_status::all());
        $this->assertContains(scan_phase::HASHLOOKUP, scan_phase::all());
        $this->assertContains(scan_source::MANUAL, scan_source::all());
        $this->assertContains(scan_source::ASSIGN, scan_source::all());
        $this->assertContains(scan_source::ANTIVIRUS, scan_source::all());
        $this->assertTrue(scan_status::is_valid(scan_status::CLEAN));
        $this->assertFalse(scan_status::is_valid('hashlookup'));
        $this->assertTrue(scan_status::is_terminal(scan_status::CLEAN));
        $this->assertTrue(scan_status::is_terminal(scan_status::ERROR));
        $this->assertFalse(scan_status::is_terminal(scan_status::PENDING));
    }

    /**
     * Moodle plugin manager allows a normal standalone uninstall.
     *
     * core_plugin_manager::can_uninstall_plugin() returns false when the
     * plugin is unknown, not yet installed (status new), required by another
     * plugin, or the plugininfo type forbids uninstall. Antivirus plugins
     * other than clamav use core\plugininfo\antivirus, which allows uninstall.
     */
    public function test_plugin_manager_allows_uninstall(): void {
        $pluginman = \core_plugin_manager::instance();
        $info = $pluginman->get_plugin_info('antivirus_verdict');
        $this->assertNotNull($info);
        $this->assertSame('antivirus', $info->type);
        $this->assertInstanceOf(\core\plugininfo\antivirus::class, $info);
        $this->assertTrue($info->is_uninstall_allowed());
        $this->assertNotSame(\core_plugin_manager::PLUGIN_STATUS_NEW, $info->get_status());
        $this->assertSame([], $info->get_other_required_plugins());
        $this->assertSame([], $pluginman->other_plugins_that_require('antivirus_verdict'));
        $this->assertTrue($pluginman->can_uninstall_plugin('antivirus_verdict'));
        $url = $pluginman->get_uninstall_url('antivirus_verdict', 'overview');
        $this->assertInstanceOf(\moodle_url::class, $url);
        $this->assertSame('antivirus_verdict', $url->param('uninstall'));
        $this->assertStringContainsString('admin/plugins.php', $url->out(false));
    }

    /**
     * version.php must not declare a plugin dependency that would veto uninstall.
     */
    public function test_version_php_has_no_plugin_dependencies(): void {
        global $CFG;

        $plugin = new \stdClass();
        include($CFG->dirroot . '/lib/antivirus/verdict/version.php');
        $this->assertSame('antivirus_verdict', $plugin->component);
        $this->assertTrue(empty($plugin->dependencies));
    }

    /**
     * The plugin does not replace Moodle's antivirus plugininfo uninstall rules.
     */
    public function test_plugin_does_not_override_uninstall_plugininfo(): void {
        global $CFG;

        $root = $CFG->dirroot . '/lib/antivirus/verdict';
        $this->assertFileDoesNotExist($root . '/classes/plugininfo.php');
        $this->assertDirectoryDoesNotExist($root . '/classes/plugininfo');
        $this->assertFileExists($root . '/db/uninstall.php');
        $source = file_get_contents($root . '/db/uninstall.php');
        $this->assertStringContainsString('function xmldb_antivirus_verdict_uninstall()', $source);
        $this->assertStringNotContainsString('drop_table', $source);
        $this->assertStringNotContainsString('antivirus_verdict_scans', $source);
    }

    /**
     * Assignment auto-scan is off by default; Moodle $CFG->antiviruses is the master switch.
     */
    public function test_scanning_disabled_by_default(): void {
        $this->resetAfterTest();
        $assignscan = get_config('antivirus_verdict', 'assignscan');
        $this->assertTrue($assignscan === false || $assignscan === '' || (int) $assignscan === 0);
    }

    /**
     * Stale-scan recovery is registered as a scheduled task.
     */
    public function test_recovery_task_is_defined(): void {
        global $CFG, $DB;

        $this->resetAfterTest();
        $tasks = [];
        include($CFG->dirroot . '/lib/antivirus/verdict/db/tasks.php');
        $this->assertNotEmpty($tasks);
        $this->assertSame('\antivirus_verdict\task\recover_stale_scans', $tasks[0]['classname']);
        $this->assertTrue(
            $DB->record_exists_select(
                'task_scheduled',
                $DB->sql_like('classname', ':cname'),
                ['cname' => '%recover_stale_scans%']
            )
        );
        $task = new \antivirus_verdict\task\recover_stale_scans();
        $this->assertNotEmpty($task->get_name());
    }

    /**
     * Plugin get_string() identifiers used in PHP/Mustache exist in English.
     */
    public function test_used_language_identifiers_exist(): void {
        global $CFG;

        $string = [];
        include($CFG->dirroot . '/lib/antivirus/verdict/lang/en/antivirus_verdict.php');
        $this->assertArrayHasKey('scandetail', $string);
        $this->assertArrayNotHasKey('scandetetail', $string);

        $root = $CFG->dirroot . '/lib/antivirus/verdict';
        $files = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS)
        );
        $missing = [];
        foreach ($files as $file) {
            if (!$file->isFile()) {
                continue;
            }
            $ext = strtolower($file->getExtension());
            if (!in_array($ext, ['php', 'mustache'], true)) {
                continue;
            }
            $path = $file->getPathname();
            if (str_contains($path, DIRECTORY_SEPARATOR . 'lang' . DIRECTORY_SEPARATOR)) {
                continue;
            }
            $source = file_get_contents($path);
            if (preg_match_all("/get_string\(\s*'([^']+)'\s*,\s*'antivirus_verdict'/", $source, $matches)) {
                foreach ($matches[1] as $key) {
                    if (!array_key_exists($key, $string)) {
                        $missing[] = $key . ' in ' . substr($path, strlen($root) + 1);
                    }
                }
            }
            if (preg_match_all("/apply_chrome\(\s*'([^']+)'/", $source, $matches)) {
                foreach ($matches[1] as $key) {
                    if (!array_key_exists($key, $string)) {
                        $missing[] = 'apply_chrome ' . $key . ' in ' . substr($path, strlen($root) + 1);
                    }
                }
            }
            if (preg_match_all("/page::(?:setup|prepare)\(\s*'[^']+'\s*,\s*'([^']+)'/", $source, $matches)) {
                foreach ($matches[1] as $key) {
                    if (!array_key_exists($key, $string)) {
                        $missing[] = 'page title ' . $key . ' in ' . substr($path, strlen($root) + 1);
                    }
                }
            }
            if (preg_match_all('/\{\{#str\}\}([^,]+),\s*antivirus_verdict/', $source, $matches)) {
                foreach ($matches[1] as $key) {
                    $key = trim($key);
                    if (!array_key_exists($key, $string)) {
                        $missing[] = 'mustache ' . $key . ' in ' . substr($path, strlen($root) + 1);
                    }
                }
            }
        }
        $this->assertSame([], $missing, 'Missing antivirus_verdict language strings: ' . implode(', ', $missing));
        $this->assertStringNotContainsString('scandetetail', file_get_contents($root . '/view.php'));
    }
}
