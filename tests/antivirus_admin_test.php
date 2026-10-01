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
 * Native Moodle Antivirus discovery and enablement.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\plugin_config;


defined('MOODLE_INTERNAL') || die();

global $CFG;
require_once($CFG->libdir . '/adminlib.php');

/**
 * Verdict is discovered and enabled through Moodle's Antivirus manager.
 *
 * @covers \antivirus_verdict\scanner
 * @covers \antivirus_verdict\local\plugin_config
 */
final class antivirus_admin_test extends \advanced_testcase {
    /**
     * Moodle lists Verdict among available antivirus plugins.
     */
    public function test_manager_discovers_verdict(): void {
        $available = \core\antivirus\manager::get_available();
        $this->assertArrayHasKey('verdict', $available);
        $this->assertSame(get_string('pluginname', 'antivirus_verdict'), $available['verdict']);
    }

    /**
     * Configured (API key) is independent of enabled ($CFG->antiviruses).
     */
    public function test_configured_is_not_enabled(): void {
        global $CFG;

        $this->resetAfterTest();
        unset($CFG->antiviruses);
        $CFG->antiviruses = '';
        set_config('apikey', 'phpunit-admin-key', 'antivirus_verdict');

        $scanner = \core\antivirus\manager::get_antivirus('verdict');
        $this->assertInstanceOf(scanner::class, $scanner);
        $this->assertTrue($scanner->is_configured());
        $this->assertFalse(plugin_config::is_antivirus_enabled());
    }

    /**
     * Enabled without an API key is not configured.
     */
    public function test_enabled_without_key_is_not_configured(): void {
        global $CFG;

        $this->resetAfterTest();
        unset_config('apikey', 'antivirus_verdict');
        $CFG->antiviruses = 'verdict';

        $scanner = \core\antivirus\manager::get_antivirus('verdict');
        $this->assertFalse($scanner->is_configured());
        $this->assertTrue(plugin_config::is_antivirus_enabled());
    }

    /**
     * Moodle's native enable_plugin updates $CFG->antiviruses.
     */
    public function test_native_enable_and_disable_persist(): void {
        global $CFG;

        $this->resetAfterTest();
        $CFG->antiviruses = '';
        \core\plugininfo\antivirus::enable_plugin('verdict', 1);
        $this->assertTrue(plugin_config::is_antivirus_enabled());
        $this->assertStringContainsString('verdict', (string) $CFG->antiviruses);

        \core\plugininfo\antivirus::enable_plugin('verdict', 0);
        $this->assertFalse(plugin_config::is_antivirus_enabled());
        $this->assertStringNotContainsString('verdict', (string) ($CFG->antiviruses ?? ''));
    }

    /**
     * Verdict settings stay visible while the scanner is disabled.
     */
    public function test_settings_page_visible_when_disabled(): void {
        global $CFG;

        $this->resetAfterTest();
        $this->setAdminUser();
        $CFG->antiviruses = '';
        \core_plugin_manager::reset_caches();

        $adminroot = \admin_get_root(true);
        $this->assertNotNull($adminroot->locate('manageantiviruses'));
        $this->assertNull($adminroot->locate('antivirus_verdict_testconnection'));

        $node = $adminroot->locate('antivirussettingsverdict');
        $this->assertNotNull($node);
        $this->assertFalse($node->hidden);
        $this->assertEquals(get_string('pluginname', 'antivirus_verdict'), (string) $node->visiblename);
    }

    /**
     * Manage antivirus plugins table includes Verdict and its settings link.
     */
    public function test_manage_table_lists_verdict(): void {
        global $CFG;

        $this->resetAfterTest();
        $this->setAdminUser();
        $CFG->antiviruses = $CFG->antiviruses ?? '';

        $setting = new \admin_setting_manageantiviruses();
        $html = $setting->output_html('', '');
        $this->assertStringContainsString(get_string('pluginname', 'antivirus_verdict'), $html);
        $this->assertStringContainsString('antivirus=verdict', $html);
        $this->assertStringContainsString('section=antivirussettingsverdict', $html);
        $this->assertStringContainsString('admin/antiviruses.php', $html);
    }

    /**
     * settings.php does not add a second enable switch or sibling admin page.
     */
    public function test_settings_php_uses_native_enablement(): void {
        global $CFG;

        $source = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/settings.php');
        $this->assertStringNotContainsString('admin_externalpage', $source);
        $this->assertStringNotContainsString("antivirus_verdict/enabled", $source);
        $this->assertStringContainsString('manageantiviruses', $source);
        $this->assertStringContainsString('new admin_settingpage', $source);
        $this->assertStringContainsString('nativestatusheading', $source);
        $this->assertMatchesRegularExpression('/admin_settingpage\s*\([\s\S]*false\s*\)/', $source);
    }
}
