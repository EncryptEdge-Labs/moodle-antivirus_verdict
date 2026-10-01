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
 * Helpers for PHPUnit runs against Moodle trees with broken optional plugins on disk.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\tests;

/**
 * Tolerates optional broken-plugin debugging noise in notification tests.
 */
trait environment_debugging_trait {
    /**
     * Assert the notification-hook debugging line, tolerating broken third-party plugins on disk.
     *
     * @param string $verdictmessage Expected Verdict debugging message.
     */
    protected function assert_verdict_debugging_with_optional_environment_noise(string $verdictmessage): void {
        $debugging = $this->getDebuggingMessages();
        $broken = null;
        $verdict = null;
        foreach ($debugging as $debug) {
            if (str_contains($debug->message, 'does not declare valid $plugin->component')) {
                $broken = $debug->message;
            }
            if ($debug->message === $verdictmessage) {
                $verdict = $debug->message;
            }
        }
        if ($broken !== null && $verdict !== null) {
            $this->assertDebuggingCalledCount(
                2,
                [$broken, $verdict],
                [DEBUG_DEVELOPER, DEBUG_DEVELOPER]
            );
            return;
        }
        $this->assertDebuggingCalled($verdictmessage, DEBUG_DEVELOPER);
    }
}
