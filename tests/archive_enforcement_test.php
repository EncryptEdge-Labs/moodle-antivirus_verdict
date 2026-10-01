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

namespace antivirus_verdict;

use antivirus_verdict\local\file_hasher;
use antivirus_verdict\local\plugin_config;
use antivirus_verdict\local\scan_repository;
use antivirus_verdict\local\scan_service;
use antivirus_verdict\tests\fake_provider;
use antivirus_verdict\tests\recording_enforcer;
use antivirus_verdict\tests\recording_scheduler;

/**
 * Archive-related enforcement boundaries on scan_service.
 *
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @covers \antivirus_verdict\local\scan_service
 */
final class archive_enforcement_test extends \advanced_testcase {
    /**
     * Malicious archive member scans must not invoke permanent-file enforcement.
     */
    public function test_malicious_member_skips_direct_enforcement(): void {
        $enforcer = new recording_enforcer(new scan_repository(), new plugin_config(true, 1024), new file_hasher());
        $service = new scan_service(
            new fake_provider(),
            new scan_repository(),
            new file_hasher(),
            new plugin_config(true, 1024),
            new recording_scheduler(),
            null,
            $enforcer
        );

        $member = (object) [
            'id' => 99,
            'status' => scan_status::MALICIOUS,
            'parentscanid' => 42,
            'filename' => 'member.bin',
        ];

        $method = new \ReflectionMethod(scan_service::class, 'enforce_if_malicious');
        $method->setAccessible(true);
        $method->invoke($service, $member);

        $this->assertSame([], $enforcer->quarantined);
        $this->assertSame([], $enforcer->deleted);
    }
}
