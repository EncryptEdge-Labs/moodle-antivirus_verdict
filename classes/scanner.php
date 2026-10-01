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
 * Native Moodle Antivirus scanner for Verdict.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\antivirus_gate;


/**
 * Synchronous upload-gate adapter. Does not wait for VirusTotal analysis.
 *
 * Capability checks must not appear here. Moodle calls this as a system service.
 */
class scanner extends \core\antivirus\scanner {
    /** @var antivirus_gate|null Injected gate for tests. */
    private ?antivirus_gate $gate = null;

    /**
     * Whether a VirusTotal API key is configured.
     *
     * Moodle also requires this plugin to be listed in $CFG->antiviruses.
     *
     * @return bool
     */
    public function is_configured() {
        $key = get_config('antivirus_verdict', 'apikey');
        return is_string($key) && trim($key) !== '';
    }

    /**
     * Scan a filesystem path supplied by core\antivirus\manager.
     *
     * @param string $file Full path to the file.
     * @param string $filename Original filename.
     * @return int SCAN_RESULT_OK, SCAN_RESULT_FOUND, or SCAN_RESULT_ERROR.
     */
    public function scan_file($file, $filename) {
        return $this->gate()->scan_file((string) $file, (string) $filename, $this);
    }

    /**
     * Inject a gate. Used by PHPUnit only.
     *
     * @param antivirus_gate $gate Gate.
     */
    public function set_gate(antivirus_gate $gate): void {
        $this->gate = $gate;
    }

    /**
     * Publish a scanning notice for the antivirus manager.
     *
     * @param string $notice Safe, non-secret notice.
     */
    public function publish_notice(string $notice): void {
        $this->set_scanning_notice($notice);
    }

    /**
     * User-facing malware message used by core\antivirus\manager.
     *
     * Manager merges {$a->item} with the original filename. This does not
     * change SCAN_RESULT_FOUND or allow the upload.
     *
     * @return array{string:string,component:string,placeholders:array}
     */
    public function get_virus_found_message() {
        return [
            'string' => 'error_malwareblocked',
            'component' => 'antivirus_verdict',
            'placeholders' => [],
        ];
    }

    /**
     * Production or injected gate.
     *
     * @return antivirus_gate
     */
    private function gate(): antivirus_gate {
        return $this->gate ?? antivirus_gate::from_site_config();
    }
}
