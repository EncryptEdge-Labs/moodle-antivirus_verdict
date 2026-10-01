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
 * Tests for the dark-shell settings page.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\page;
use antivirus_verdict\local\plugin_config;
use antivirus_verdict\output\settings_page;


/**
 * Settings UI stays in the Verdict shell and does not leak the API key.
 *
 * @covers \antivirus_verdict\output\settings_page
 * @covers \antivirus_verdict\local\page
 * @covers \antivirus_verdict\local\plugin_config
 */
final class settings_ui_test extends \advanced_testcase {
    /** Placeholder key used only in these tests. */
    private const FAKE_KEY = 'phpunit-settings-secret-key';

    /**
     * Unrevealed export never includes the stored API key.
     */
    public function test_settings_export_hides_key_until_reveal(): void {
        global $CFG;

        $this->resetAfterTest();
        $this->setAdminUser();
        $CFG->antiviruses = 'verdict';
        set_config('apikey', self::FAKE_KEY, 'antivirus_verdict');
        set_config('assignscan', 0, 'antivirus_verdict');
        set_config('maxfilesize', 100, 'antivirus_verdict');

        $hidden = (new settings_page(false))->export_for_template($this->page_renderer());
        $this->assertTrue($hidden['haskey']);
        $this->assertFalse($hidden['keyrevealed']);
        $this->assertSame('', $hidden['apikey']);
        $this->assertStringNotContainsString(self::FAKE_KEY, json_encode($hidden));
        $this->assertStringContainsString('verdict', $CFG->antiviruses);
        $this->assertFalse($hidden['assignscan']);
        $this->assertSame(100, $hidden['maxfilesize']);
        $this->assertSame(plugin_config::DEFAULT_MAX_MB, $hidden['maxfilesizecap']);
        $this->assertArrayHasKey('privatescan', $hidden);
        $this->assertFalse($hidden['privatescan']);
        $this->assertStringContainsString('/lib/antivirus/verdict/configure.php', $hidden['actionurl']);
        $this->assertStringContainsString('section=manageantiviruses', $hidden['antivirusmanageurl']);
        $this->assertTrue($hidden['antivirusenabled']);
        $this->assertTrue($hidden['haskey']);
        $this->assertSame(get_string('scannerstate_configured', 'antivirus_verdict'), $hidden['configuredyes']);

        $shown = (new settings_page(true))->export_for_template($this->page_renderer());
        $this->assertTrue($shown['keyrevealed']);
        $this->assertSame(self::FAKE_KEY, $shown['apikey']);
    }

    /**
     * Size limits are clamped to the plugin default and upload cap.
     */
    public function test_normalise_max_mb(): void {
        $this->assertSame(plugin_config::DEFAULT_MAX_MB, plugin_config::normalise_max_mb(0));
        $this->assertSame(plugin_config::DEFAULT_MAX_MB, plugin_config::normalise_max_mb(-4));
        $this->assertSame(8, plugin_config::normalise_max_mb(8));
        $this->assertSame(plugin_config::DEFAULT_MAX_MB, plugin_config::normalise_max_mb(plugin_config::DEFAULT_MAX_MB));
        $this->assertSame(plugin_config::DEFAULT_MAX_MB, plugin_config::normalise_max_mb(99999));
    }

    /**
     * Upgrade from 2026092500 migrates the legacy 32 MB default to 100 MB.
     */
    public function test_upgrade_migrates_legacy_maxfilesize_default(): void {
        global $CFG;

        $this->resetAfterTest();
        require_once($CFG->libdir . '/upgradelib.php');
        require_once($CFG->dirroot . '/lib/antivirus/verdict/db/upgrade.php');

        set_config('version', 2026092500, 'antivirus_verdict');
        set_config('maxfilesize', 32, 'antivirus_verdict');
        $this->assertTrue(xmldb_antivirus_verdict_upgrade(2026092500));
        $this->assertSame(
            (string) plugin_config::DEFAULT_MAX_MB,
            (string) get_config('antivirus_verdict', 'maxfilesize')
        );

        set_config('version', 2026092500, 'antivirus_verdict');
        set_config('maxfilesize', 8, 'antivirus_verdict');
        $this->assertTrue(xmldb_antivirus_verdict_upgrade(2026092500));
        $this->assertSame('8', (string) get_config('antivirus_verdict', 'maxfilesize'));
    }

    /**
     * Settings controller stays on the dark shell and requires site config.
     */
    public function test_configure_php_is_gated_and_uses_product_shell(): void {
        global $CFG;

        $source = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/configure.php');
        $this->assertStringContainsString("page::prepare('configure.php', 'settingsheading')", $source);
        $this->assertStringContainsString('locatemoodle.php', $source);
        $this->assertStringContainsString("require_capability('moodle/site:config'", $source);
        $this->assertStringContainsString('require_sesskey()', $source);
        $this->assertStringContainsString("set_config('assignscan'", $source);
        $this->assertStringContainsString("set_config('maxfilesize'", $source);
        $this->assertStringContainsString("set_config('privatescan'", $source);
        $this->assertStringContainsString("set_config('datascan'", $source);
        $this->assertStringContainsString("set_config('unknownpolicy'", $source);
        $this->assertStringNotContainsString('get_config(\'antivirus_verdict\', \'apikey\')', $source);
        $this->assertStringNotContainsString('admin_externalpage_setup', $source);
        $this->assertStringNotContainsString('admin/settings.php', $source);
        $this->assertStringNotContainsString('page::setup', $source);
        $this->assertStringContainsString('plugin_tabs(\'settings\'', $source);
    }

    /**
     * Sidebar, overview, and connection-test cancel use configure.php.
     */
    public function test_settings_links_use_configure_php(): void {
        global $CFG;

        $renderer = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/classes/output/renderer.php');
        $this->assertStringContainsString('page::settings_url()', $renderer);
        $this->assertStringNotContainsString('admin/settings.php', $renderer);

        $overview = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/classes/output/overview.php');
        $this->assertStringContainsString('page::settings_url()', $overview);
        $this->assertStringContainsString('page::antivirus_manage_url()', $overview);

        $testconnection = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/test_connection.php');
        $this->assertStringContainsString('page::settings_url()', $testconnection);
        $this->assertStringContainsString("page::prepare('test_connection.php'", $testconnection);
        $this->assertStringNotContainsString('admin_externalpage_setup', $testconnection);
        $this->assertStringNotContainsString('admin/settings.php', $testconnection);

        $this->assertStringContainsString(
            '/lib/antivirus/verdict/configure.php',
            page::settings_url()->out(false)
        );
    }

    /**
     * Settings template matches the dark-shell mockup structure.
     */
    public function test_settings_template_has_jump_nav_and_toggles(): void {
        global $CFG;

        $template = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/templates/settings.mustache');
        $this->assertStringContainsString('antivirus-verdict-jump-chip', $template);
        $this->assertStringContainsString('#antivirus-verdict-panel-privacy', $template);
        $this->assertStringContainsString('#antivirus-verdict-panel-credentials', $template);
        $this->assertStringContainsString('#antivirus-verdict-panel-how', $template);
        $this->assertStringContainsString('#antivirus-verdict-panel-scanning', $template);
        $this->assertStringContainsString('#antivirus-verdict-panel-archive', $template);
        $this->assertStringContainsString('#antivirus-verdict-panel-policies', $template);
        $this->assertStringContainsString('#antivirus-verdict-panel-notifications', $template);
        $this->assertStringContainsString('#antivirus-verdict-panel-storage', $template);
        $this->assertStringNotContainsString('class="form-control"', $template);
        $this->assertStringContainsString('antivirus-verdict-toggle', $template);
        $this->assertStringContainsString('name="assignscan"', $template);
        $this->assertStringContainsString('name="maxfilesize"', $template);
        $this->assertStringContainsString('name="asyncenforcement"', $template);
        $this->assertStringContainsString('name="privatescan"', $template);
        $this->assertStringContainsString('name="datascan"', $template);
        $this->assertStringContainsString('name="wikiscan"', $template);
        $this->assertStringContainsString('name="scormscan"', $template);
        $this->assertStringContainsString('name="questionscan"', $template);
        $this->assertStringContainsString('name="notifysuspicious"', $template);
        $this->assertStringContainsString('name="notifyerror"', $template);
        $scanpos = strpos($template, 'id="antivirus-verdict-panel-scanning"');
        $datapos = strpos($template, 'name="datascan"');
        $formend = strrpos($template, '</form>');
        $this->assertNotFalse($scanpos);
        $this->assertNotFalse($datapos);
        $this->assertNotFalse($formend);
        $this->assertGreaterThan($scanpos, $datapos);
        $this->assertLessThan($formend, $datapos);
        $this->assertStringContainsString('name="sesskey"', $template);
        $this->assertStringContainsString('antivirus-verdict-btn-primary', $template);
        $this->assertStringContainsString('antivirus-verdict-btn-row', $template);
        $this->assertStringContainsString('antivirus-verdict-key-actions', $template);
        $this->assertStringContainsString('{{antivirusmanageurl}}', $template);
        $this->assertStringContainsString('{{configuredlabel}}', $template);
        $this->assertStringContainsString('{{apikey}}', $template);
        $this->assertStringNotContainsString('{{{apikey}}}', $template);
        $this->assertStringNotContainsString('data-apikey', $template);
    }

    /**
     * Private-files and policy settings load from the same config runtime uses.
     */
    public function test_settings_export_matches_runtime_config(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('privatescan', 1, 'antivirus_verdict');
        set_config('unknownpolicy', 'block', 'antivirus_verdict');
        set_config('providererrorpolicy', 'block', 'antivirus_verdict');

        $exported = (new settings_page(false))->export_for_template($this->page_renderer());
        $runtime = plugin_config::from_site_config();
        $this->assertTrue($exported['privatescan']);
        $this->assertTrue($runtime->privatescan);
        $this->assertTrue($exported['unknownpolicyblock']);
        $this->assertSame('block', $runtime->unknownpolicy);
        $this->assertTrue($exported['providererrorpolicyblock']);
        $this->assertSame('block', $runtime->providererrorpolicy);
    }

    /**
     * Saving privatescan updates the key plugin_config reads.
     */
    public function test_privatescan_config_is_authoritative(): void {
        $this->resetAfterTest();
        set_config('privatescan', 0, 'antivirus_verdict');
        $this->assertFalse(plugin_config::from_site_config()->privatescan);
        set_config('privatescan', 1, 'antivirus_verdict');
        $this->assertTrue(plugin_config::from_site_config()->privatescan);
    }

    /**
     * Copy and dismiss behaviour is client-side and does not embed secrets.
     */
    public function test_ui_javascript_has_no_secrets(): void {
        global $CFG;

        $js = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/javascript/ui.js');
        $this->assertStringContainsString('navigator.clipboard.writeText', $js);
        $this->assertStringContainsString('copy-hash', $js);
        $this->assertStringContainsString('dismiss-banner', $js);
        $this->assertStringContainsString('edit-key', $js);
        $this->assertStringContainsString('theme-toggle', $js);
        $this->assertStringContainsString('antivirus_verdict_theme', $js);
        $this->assertStringContainsString('core_filepicker', $js);
        $this->assertStringNotContainsString('data-apikey', $js);
        $this->assertStringNotContainsString(self::FAKE_KEY, $js);
        $this->assertStringContainsString('1400', $js);
    }

    /**
     * Plugin renderer for templatable export.
     *
     * @return \renderer_base
     */
    private function page_renderer(): \renderer_base {
        global $PAGE;
        $PAGE->set_url(new \moodle_url('/lib/antivirus/verdict/configure.php'));
        $PAGE->set_context(\context_system::instance());
        return $PAGE->get_renderer('antivirus_verdict');
    }
}
