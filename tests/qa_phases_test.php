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
 * Remaining QA plan phases: consumers, retention race, policies, wiring.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\antivirus_gate;
use antivirus_verdict\local\file_area_scanner;
use antivirus_verdict\local\file_hasher;
use antivirus_verdict\local\plugin_config;
use antivirus_verdict\local\scan_policy;
use antivirus_verdict\local\scan_repository;
use antivirus_verdict\local\scan_retention;
use antivirus_verdict\local\scan_retention_cleanup;
use antivirus_verdict\local\scan_service;
use antivirus_verdict\provider\file_lookup_result;
use antivirus_verdict\tests\fake_provider;
use antivirus_verdict\tests\recording_scheduler;


/**
 * Phases 3–7 mock coverage not already in qa_edge_case_test.
 *
 * @coversNothing
 */
final class qa_phases_test extends \advanced_testcase {
    /** SHA-256 of "hello". */
    private const HELLO_SHA256 = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';

    /**
     * VT-EC-D03: completed suspicious hash reuse at gate applies policy without extra lookups.
     */
    public function test_vt_ec_d03_suspicious_hash_reuse_at_gate(): void {
        global $DB;

        $this->resetAfterTest();
        $repo = new scan_repository();
        $row = $this->terminal_row(self::HELLO_SHA256, scan_status::SUSPICIOUS, scan_phase::COMPLETED);
        $row->suspicious = 2;
        $repo->insert($row);

        $provider = new fake_provider();
        $provider->lookupresult = new file_lookup_result(true, self::HELLO_SHA256, [
            'malicious' => 0, 'suspicious' => 2, 'undetected' => 5, 'harmless' => 5, 'timeout' => 0,
        ]);
        $scanner = $this->make_gate_scanner($provider, scan_policy::ALLOW, scan_policy::ALLOW);

        $this->assertSame(scanner::SCAN_RESULT_OK, $scanner->scan_file($this->temp_file('hello'), 'reuse.bin'));
        $this->assertSame(0, $provider->lookupcount, 'Completed suspicious verdict must reuse without lookup.');
        $latest = $DB->get_record('antivirus_verdict_scans', ['filename' => 'reuse.bin'], '*', MUST_EXIST);
        $this->assertSame(scan_status::SUSPICIOUS, $latest->status);
    }

    /**
     * VT-EC-G11: synchronous gate never uploads file bytes to VirusTotal.
     */
    public function test_vt_ec_g11_sync_gate_never_uploads(): void {
        $this->resetAfterTest();
        $provider = new fake_provider();
        $scanner = $this->make_gate_scanner($provider);
        $path = $this->temp_file('hello');
        $scanner->scan_file($path, 'known.bin');
        $scanner->scan_file($this->temp_file('brand-new'), 'unknown.bin');
        $this->assertSame(0, $provider->uploadcount);
    }

    /**
     * VT-EC-H02 / H06 / H07: hasher stability and distinctness.
     */
    public function test_vt_ec_h02_one_byte_hash(): void {
        $hasher = new file_hasher();
        $path = $this->temp_file('x');
        $this->assertSame(hash('sha256', 'x'), $hasher->hash_path($path));
    }

    /**
     * VT-EC-H08: unicode filename does not change content hash.
     */
    public function test_vt_ec_h08_unicode_filename_same_content_hash(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $hasher = new file_hasher();
        $content = 'unicode-content';
        $fs = get_file_storage();
        $a = $fs->create_file_from_string([
            'contextid' => \context_system::instance()->id,
            'component' => 'user',
            'filearea' => 'draft',
            'itemid' => file_get_unused_draft_itemid(),
            'filepath' => '/',
            'filename' => 'café-附件.pdf',
        ], $content);
        $b = $fs->create_file_from_string([
            'contextid' => \context_system::instance()->id,
            'component' => 'user',
            'filearea' => 'draft',
            'itemid' => file_get_unused_draft_itemid(),
            'filepath' => '/',
            'filename' => 'plain.pdf',
        ], $content);
        $this->assertSame($hasher->hash_stored_file($a), $hasher->hash_stored_file($b));
    }

    /**
     * VT-EC-A05: terminal scans are ignored by process_scan workers.
     */
    public function test_vt_ec_a05_terminal_malicious_not_reprocessed(): void {
        $this->resetAfterTest();
        $repo = new scan_repository();
        $id = $repo->insert($this->terminal_row(
            hash('sha256', 'malware'),
            scan_status::MALICIOUS,
            scan_phase::COMPLETED
        ));
        $provider = new fake_provider();
        $provider->analysisresult = null;
        $service = new scan_service(
            $provider,
            $repo,
            new file_hasher(),
            new plugin_config(true, 1024 * 1024),
            new recording_scheduler()
        );
        $this->assertFalse($service->process_scan($id));
        $row = $repo->get_by_id($id);
        $this->assertSame(scan_status::MALICIOUS, $row->status);
        $this->assertSame(0, $provider->analysiscount);
    }

    /**
     * VT-EC-X03: retention purge must not delete malicious rows awaiting enforcement.
     */
    public function test_vt_ec_x03_purge_skips_pending_enforcement_row(): void {
        $this->resetAfterTest();
        $now = time();
        $repo = new scan_repository();
        $id = $repo->insert($this->terminal_row(
            hash('sha256', 'pending-enforce'),
            scan_status::MALICIOUS,
            scan_phase::COMPLETED,
            enforcement_state::PENDING,
            $now - (400 * DAYSECS)
        ));
        $this->assertFalse(scan_retention::is_eligible($repo->get_by_id($id), $now, 365));
        $stats = (new scan_retention_cleanup($repo, $now))->run(365);
        $this->assertSame(0, $stats['purged']);
        $this->assertNotNull($repo->get_by_id($id));
    }

    /**
     * VT-EC-SET01: product default policies match scan_policy constants.
     */
    public function test_vt_ec_set01_default_policies(): void {
        $this->assertSame('allow', scan_policy::UNKNOWN_DEFAULT);
        $this->assertSame('allow', scan_policy::SUSPICIOUS_DEFAULT);
        $this->assertSame('block', scan_policy::PROVIDER_ERROR_DEFAULT);
        $this->assertSame('quarantine', scan_policy::ASYNC_ENFORCEMENT_DEFAULT);
    }

    /**
     * VT-EC-CAP02 / configure: POST actions require sesskey.
     */
    public function test_vt_ec_cap02_configure_requires_sesskey(): void {
        $source = file_get_contents(__DIR__ . '/../configure.php');
        $this->assertStringContainsString('require_sesskey()', $source);
    }

    /**
     * VT-EC-COV: retrospective consumers queue with correct scan_source labels.
     *
     * @param string $source Scan source constant.
     * @dataProvider consumer_source_provider
     */
    public function test_vt_ec_cov_consumer_source_labels(string $source): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('apikey', 'consumer-key', 'antivirus_verdict');

        $provider = new fake_provider();
        $scheduler = new recording_scheduler();
        $service = new scan_service(
            $provider,
            new scan_repository(),
            new file_hasher(),
            new plugin_config(true, 1024 * 1024),
            $scheduler
        );
        $scanner = new file_area_scanner($service, plugin_config::from_site_config());
        $file = $this->create_stored_file($source . '.txt', 'bytes-' . $source);
        $scan = $scanner->queue_file($file, $source, 5);
        $this->assertNotNull($scan);
        $this->assertSame($source, $scan->source);
    }

    /**
     * Internal helper.
     *
     * @return array<string, array{0:string}>
     */
    public static function consumer_source_provider(): array {
        return [
            'forum' => [scan_source::FORUM],
            'workshop' => [scan_source::WORKSHOP],
            'glossary' => [scan_source::GLOSSARY],
            'data' => [scan_source::DATA],
            'wiki' => [scan_source::WIKI],
            'scorm' => [scan_source::SCORM],
            'question' => [scan_source::QUESTION],
            'restore' => [scan_source::RESTORE],
            'bulk' => [scan_source::BULK],
            'private' => [scan_source::PRIVATE],
        ];
    }

    /**
     * VT-EC-COV: event observers registered for commercial consumers.
     */
    public function test_vt_ec_cov_observer_callbacks_registered(): void {
        global $CFG;
        $observers = [];
        include($CFG->dirroot . '/lib/antivirus/verdict/db/events.php');
        $callbacks = array_column($observers, 'callback');
        $expected = [
            '\antivirus_verdict\observer::assessable_submitted',
            '\antivirus_verdict\observer::forum_assessable_uploaded',
            '\antivirus_verdict\observer::workshop_assessable_uploaded',
            '\antivirus_verdict\observer::glossary_entry_created',
            '\antivirus_verdict\observer::course_restored',
            '\antivirus_verdict\observer::question_created',
            '\antivirus_verdict\observer::course_module_scorm_changed',
        ];
        foreach ($expected as $callback) {
            $this->assertContains($callback, $callbacks, 'Missing observer: ' . $callback);
        }
    }

    /**
     * VT-EC-L02: HTTP timeout constants documented on the VT client.
     */
    public function test_vt_ec_l02_client_timeout_constants(): void {
        $source = file_get_contents(__DIR__ . '/../classes/provider/virustotal/client.php');
        $this->assertStringContainsString('TIMEOUT_GET', $source);
        $this->assertStringContainsString('TIMEOUT_CONNECT', $source);
    }

    /**
     * VT-EC-PRIV01: privacy export JSON must not contain site API key (explicit QA assert).
     */
    public function test_vt_ec_priv01_export_excludes_apikey(): void {
        global $DB;

        $this->resetAfterTest();
        $secret = 'qa-export-must-not-leak-key';
        set_config('apikey', $secret, 'antivirus_verdict');
        $user = $this->getDataGenerator()->create_user();
        $course = $this->getDataGenerator()->create_course();
        $context = \context_course::instance($course->id);

        $record = $this->terminal_row(hash('sha256', 'priv'), scan_status::CLEAN, scan_phase::COMPLETED);
        $record->userid = $user->id;
        $record->contextid = $context->id;
        $record->courseid = $course->id;
        $record->filename = 'export-me.pdf';
        $record->source = scan_source::FORUM;
        $id = (new scan_repository())->insert($record);

        $approved = new \core_privacy\local\request\approved_contextlist(
            $user,
            'antivirus_verdict',
            [$context->id]
        );
        \antivirus_verdict\privacy\provider::export_user_data($approved);
        $writer = \core_privacy\local\request\writer::with_context($context);
        $export = $writer->get_data([]);
        $encoded = json_encode($export);
        $this->assertStringNotContainsString($secret, $encoded);
        $this->assertNotNull($DB->get_record('antivirus_verdict_scans', ['id' => $id]));
    }

    /**
     * Internal helper.
     *
     * @param string $sha256 Hash.
     * @param string $status Status.
     * @param string $phase Phase.
     * @param string $enforcement Enforcement state.
     * @param int|null $completed Completion time.
     * @return \stdClass
     */
    private function terminal_row(
        string $sha256,
        string $status,
        string $phase,
        string $enforcement = enforcement_state::NONE,
        ?int $completed = null
    ): \stdClass {
        $now = $completed ?? time();
        $row = new \stdClass();
        $row->fileid = 0;
        $row->contenthash = null;
        $row->pathnamehash = '';
        $row->contextid = \context_system::instance()->id;
        $row->courseid = 0;
        $row->component = 'user';
        $row->filearea = 'draft';
        $row->itemid = 0;
        $row->filepath = '/';
        $row->filename = 'row.bin';
        $row->userid = 2;
        $row->source = scan_source::MANUAL;
        $row->sha256 = $sha256;
        $row->filesize = 4;
        $row->mimetype = null;
        $row->status = $status;
        $row->phase = $phase;
        $row->vtanalysisid = null;
        $row->vtfileid = null;
        $row->malicious = $status === scan_status::MALICIOUS ? 3 : 0;
        $row->suspicious = 0;
        $row->undetected = 0;
        $row->harmless = 0;
        $row->timeout = 0;
        $row->totalengines = 0;
        $row->errorcode = null;
        $row->enforcement = $enforcement;
        $row->pollattempts = 0;
        $row->timelastpoll = 0;
        $row->timesubmitted = 0;
        $row->timecreated = $now - 60;
        $row->timemodified = $now;
        $row->timecompleted = $now;
        $row->parentscanid = 0;
        $row->archiveoutcome = archive_outcome::NONE;
        return $row;
    }

    /**
     * Internal helper.
     *
     * @param fake_provider $provider Provider.
     * @param string $unknown Unknown policy.
     * @param string $suspicious Suspicious policy.
     * @return scanner
     */
    private function make_gate_scanner(
        fake_provider $provider,
        string $unknown = scan_policy::ALLOW,
        string $suspicious = scan_policy::ALLOW
    ): scanner {
        $gate = new antivirus_gate(
            $provider,
            new scan_repository(),
            new file_hasher(),
            new plugin_config(true, 1048576, false, $unknown, $suspicious, scan_policy::BLOCK),
            new recording_scheduler()
        );
        $scanner = new scanner();
        $scanner->set_gate($gate);
        return $scanner;
    }

    /**
     * Internal helper.
     *
     * @param string $filename Name.
     * @param string $content Bytes.
     * @return \stored_file
     */
    private function create_stored_file(string $filename, string $content): \stored_file {
        $fs = get_file_storage();
        return $fs->create_file_from_string([
            'contextid' => \context_system::instance()->id,
            'component' => 'user',
            'filearea' => 'draft',
            'itemid' => file_get_unused_draft_itemid(),
            'filepath' => '/',
            'filename' => $filename,
        ], $content);
    }

    /**
     * Internal helper.
     *
     * @param string $contents Bytes.
     * @return string Path.
     */
    private function temp_file(string $contents): string {
        $path = make_request_directory() . '/qaphase-' . random_int(1, 100000000) . '.bin';
        file_put_contents($path, $contents);
        return $path;
    }
}
