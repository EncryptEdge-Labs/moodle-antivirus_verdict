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
 * Tests for site configuration credentials.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\config_credentials;
use antivirus_verdict\provider\provider_exception;


/**
 * Unit tests for site configuration credentials.
 *
 * @covers \antivirus_verdict\local\config_credentials
 */
final class config_credentials_test extends \advanced_testcase {
    /**
     * Placeholder key used only in tests.
     */
    private const FAKE_KEY = 'phpunit-fake-key';

    /**
     * Configured key is returned and is not empty.
     */
    public function test_reads_configured_key(): void {
        $this->resetAfterTest();
        set_config('apikey', self::FAKE_KEY, 'antivirus_verdict');
        $credentials = new config_credentials();
        $this->assertTrue($credentials->has_api_key());
        $this->assertSame(self::FAKE_KEY, $credentials->get_api_key());
    }

    /**
     * Missing key raises a normalised error.
     */
    public function test_missing_key_throws(): void {
        $this->resetAfterTest();
        set_config('apikey', '', 'antivirus_verdict');
        $credentials = new config_credentials();
        $this->assertFalse($credentials->has_api_key());
        $this->expectException(provider_exception::class);
        $credentials->get_api_key();
    }

    /**
     * Debug output does not include the secret.
     */
    public function test_debug_info_hides_key(): void {
        $this->resetAfterTest();
        set_config('apikey', self::FAKE_KEY, 'antivirus_verdict');
        $credentials = new config_credentials();
        $reflection = new \ReflectionClass($credentials);
        foreach ($reflection->getProperties() as $property) {
            if (!$property->isInitialized($credentials)) {
                continue;
            }
            $value = $property->getValue($credentials);
            if (is_string($value)) {
                $this->assertStringNotContainsString(self::FAKE_KEY, $value);
            }
        }
        $this->assertSame(self::FAKE_KEY, $credentials->get_api_key());
    }
}
