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
 * Prompt 8 hardening tests for secrets, errors, and forms.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\form\manual_scan_form;
use antivirus_verdict\form\test_connection_form;
use antivirus_verdict\local\file_hasher;
use antivirus_verdict\local\plugin_config;
use antivirus_verdict\local\scan_presenter;
use antivirus_verdict\local\scan_repository;
use antivirus_verdict\local\scan_service;
use antivirus_verdict\provider\provider_exception;
use antivirus_verdict\task\process_scan;
use antivirus_verdict\tests\fake_provider;
use antivirus_verdict\tests\recording_scheduler;


/**
 * API-key secrecy, safe errors, and form protection.
 *
 * @covers \antivirus_verdict\local\scan_presenter
 * @covers \antivirus_verdict\form\test_connection_form
 * @covers \antivirus_verdict\form\manual_scan_form
 * @covers \antivirus_verdict\task\process_scan
 */
final class hardening_test extends \advanced_testcase {
    /** Placeholder key used only in these tests. */
    private const FAKE_KEY = 'phpunit-hardening-secret-key';

    /**
     * The API key is not stored on scan rows or in the adhoc task payload.
     */
    public function test_api_key_absent_from_scan_and_task(): void {
        global $DB;

        $this->resetAfterTest();
        set_config('apikey', self::FAKE_KEY, 'antivirus_verdict');
        $scheduler = new recording_scheduler();
        $service = new scan_service(
            new fake_provider(),
            new scan_repository(),
            new file_hasher(),
            new plugin_config(true, 1048576, false),
            $scheduler
        );
        $file = get_file_storage()->create_file_from_string([
            'contextid' => \context_system::instance()->id,
            'component' => 'antivirus_verdict',
            'filearea' => 'unittest',
            'itemid' => 1,
            'filepath' => '/',
            'filename' => 'sample.bin',
        ], 'sample-bytes');
        $scan = $service->enqueue_file_scan($file, scan_source::MANUAL, 2);

        $row = $DB->get_record('antivirus_verdict_scans', ['id' => $scan->id], '*', \MUST_EXIST);
        $this->assertStringNotContainsString(self::FAKE_KEY, json_encode($row));

        $task = new process_scan();
        $task->set_custom_data(['scanid' => (int) $scan->id]);
        $payload = json_encode($task->get_custom_data());
        $this->assertStringContainsString('scanid', $payload);
        $this->assertStringNotContainsString(self::FAKE_KEY, $payload);
        $this->assertStringNotContainsString('x-apikey', $payload);
        $this->assertSame(['scanid' => (int) $scan->id], (array) $task->get_custom_data());
    }

    /**
     * Provider exceptions and presenter output never include the API key.
     */
    public function test_errors_do_not_leak_secrets_or_unknown_codes(): void {
        $this->resetAfterTest();
        $redacted = provider_exception::redact(
            'x-apikey: ' . self::FAKE_KEY . ' Authorization: Bearer ' . self::FAKE_KEY,
            self::FAKE_KEY
        );
        $this->assertStringNotContainsString(self::FAKE_KEY, $redacted);
        $exception = new provider_exception('error_generic', $redacted);
        $this->assertSame(
            get_string('error_generic', 'antivirus_verdict'),
            scan_presenter::exception_message($exception)
        );
        $this->assertStringNotContainsString(self::FAKE_KEY, $exception->debuginfo);
        $this->assertSame(
            get_string('error_auth', 'antivirus_verdict'),
            scan_presenter::exception_message(new provider_exception('error_auth'))
        );
        $queued = get_string('error_ratelimit_queued', 'antivirus_verdict');
        $this->assertStringNotContainsString(self::FAKE_KEY, $queued);
        $this->assertStringNotContainsString('x-apikey', $queued);
        $this->assertSame(
            get_string('error_invalidfile', 'antivirus_verdict'),
            scan_presenter::exception_message(new \invalid_parameter_exception('error_invalidfile'))
        );
        $this->assertSame(
            get_string('error_generic', 'antivirus_verdict'),
            scan_presenter::lang_message('not-a-real-code')
        );
    }

    /**
     * Connection test and manual scan forms are POST with sesskey.
     */
    public function test_forms_require_sesskey_and_validate(): void {
        global $CFG;

        $this->resetAfterTest();
        $user = $this->getDataGenerator()->create_user();
        $this->setUser($user);

        $connection = new test_connection_form();
        $connectionhtml = $connection->render();
        $this->assertMatchesRegularExpression('/<form[^>]*method="post"/i', $connectionhtml);
        $this->assertStringContainsString('sesskey', $connectionhtml);
        $this->assertStringNotContainsString(self::FAKE_KEY, $connectionhtml);
        $this->assertNull($connection->get_data());

        $manual = new manual_scan_form();
        $manualhtml = $manual->render();
        $this->assertMatchesRegularExpression('/<form[^>]*method="post"/i', $manualhtml);
        $this->assertStringContainsString('sesskey', $manualhtml);
        $this->assertStringContainsString(get_string('manualscan_intro', 'antivirus_verdict'), $manualhtml);
        $this->assertStringContainsString('antivirus-verdict-dropzone', $manualhtml);
        $this->assertStringContainsString(get_string('scanfilerequired', 'antivirus_verdict'), $manualhtml);
        $this->assertStringNotContainsString("addRule('scanfile'", file_get_contents(
            $CFG->dirroot . '/lib/antivirus/verdict/classes/form/manual_scan_form.php'
        ));
        $errors = $manual->validation(['scanfile' => 0], []);
        $this->assertArrayHasKey('scanfile', $errors);
    }

    /**
     * Manual scan filepicker uses the global FILE_INTERNAL constant.
     *
     * FILE_INTERNAL is defined in repository/lib.php, not filelib.php.
     * Unqualified FILE_INTERNAL inside namespace antivirus_verdict\form is
     * resolved as local\virustotal\form\FILE_INTERNAL.
     */
    public function test_manual_scan_form_uses_global_file_internal(): void {
        global $CFG;

        $this->resetAfterTest();
        $user = $this->getDataGenerator()->create_user();
        $this->setUser($user);

        $source = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/classes/form/manual_scan_form.php');
        $this->assertStringContainsString("'return_types' => \\FILE_INTERNAL", $source);
        $this->assertStringNotContainsString("'return_types' => FILE_INTERNAL", $source);
        $this->assertStringContainsString("repository/lib.php", $source);
        require_once($CFG->dirroot . '/repository/lib.php');
        $this->assertTrue(defined('FILE_INTERNAL'));

        $form = new manual_scan_form(null, ['maxbytes' => 1024]);
        $html = $form->render();
        $this->assertStringContainsString('scanfile', $html);

        $formproperty = new \ReflectionProperty($form, '_form');
        $formproperty->setAccessible(true);
        $mform = $formproperty->getValue($form);
        $element = $mform->getElement('scanfile');
        $this->assertSame('filepicker', $element->getType());
        $optionsproperty = new \ReflectionProperty($element, '_options');
        $optionsproperty->setAccessible(true);
        $options = $optionsproperty->getValue($element);
        $this->assertSame(\FILE_INTERNAL, $options['return_types']);
    }

    /**
     * Page scripts never print the configured API key.
     */
    public function test_pages_do_not_print_api_key(): void {
        global $CFG;

        $this->resetAfterTest();
        set_config('apikey', self::FAKE_KEY, 'antivirus_verdict');
        $files = [
            $CFG->dirroot . '/lib/antivirus/verdict/test_connection.php',
            $CFG->dirroot . '/lib/antivirus/verdict/settings.php',
            $CFG->dirroot . '/lib/antivirus/verdict/configure.php',
            $CFG->dirroot . '/lib/antivirus/verdict/view.php',
            $CFG->dirroot . '/lib/antivirus/verdict/scan.php',
            $CFG->dirroot . '/lib/antivirus/verdict/history.php',
            $CFG->dirroot . '/lib/antivirus/verdict/index.php',
        ];
        foreach ($files as $path) {
            $source = file_get_contents($path);
            $this->assertStringNotContainsString('get_config(\'antivirus_verdict\', \'apikey\')', $source);
            $this->assertStringNotContainsString('echo $key', $source);
            $this->assertDoesNotMatchRegularExpression('/var_dump\s*\(/', $source);
            $this->assertDoesNotMatchRegularExpression('/print_r\s*\(/', $source);
        }
    }
}
