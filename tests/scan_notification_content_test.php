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
 * Tests for Verdict scan alert message copy.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\scan_notification_content;
use antivirus_verdict\scan_source;
use antivirus_verdict\scan_status;


/**
 * Notification copy for malicious, suspicious, and error scan alerts.
 *
 * @covers \antivirus_verdict\local\scan_notification_content
 */
final class scan_notification_content_test extends \advanced_testcase {
    /**
     * Malicious alerts include branded subject, HTML, and escaped file names.
     */
    public function test_malicious_compose_is_branded_and_escaped(): void {
        $this->resetAfterTest();
        $course = $this->getDataGenerator()->create_course(['fullname' => 'Security 101']);
        $record = (object) [
            'id' => 42,
            'filename' => '<img onerror=alert(1)>evil.exe',
            'status' => scan_status::MALICIOUS,
            'source' => scan_source::MANUAL,
            'courseid' => $course->id,
            'malicious' => 5,
            'suspicious' => 0,
            'totalengines' => 70,
            'enforcement' => 'quarantined',
        ];

        $content = scan_notification_content::compose($record);

        $this->assertStringContainsString('Verdict security alert', $content['subject']);
        $this->assertStringContainsString('Malicious file detected', $content['bodyplain']);
        $this->assertStringContainsString('Security 101', $content['bodyplain']);
        $this->assertStringContainsString('Open scan in Verdict', $content['contextlabel']);
        $this->assertStringNotContainsString('<img', $content['bodyhtml']);
        $this->assertStringContainsString('evil.exe', $content['bodyhtml']);
        $this->assertStringContainsString('Open scan in Verdict', $content['bodyhtml']);
    }
}
