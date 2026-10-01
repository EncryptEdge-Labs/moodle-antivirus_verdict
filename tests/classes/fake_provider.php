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
 * Configurable malware provider for PHPUnit.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\tests;

use antivirus_verdict\provider\analysis_result;
use antivirus_verdict\provider\connection_result;
use antivirus_verdict\provider\file_lookup_result;
use antivirus_verdict\provider\file_payload;
use antivirus_verdict\provider\malware_provider;
use antivirus_verdict\provider\provider_exception;
use antivirus_verdict\provider\submission_result;


/**
 * Records provider calls. Never contacts VirusTotal.
 */
class fake_provider implements malware_provider {
    /** @var int Hash lookup calls. */
    public int $lookupcount = 0;
    /** @var int Upload calls. */
    public int $uploadcount = 0;
    /** @var int Analysis retrieval calls. */
    public int $analysiscount = 0;
    /** @var string[] Uploaded filenames. */
    public array $uploadednames = [];
    /** @var int[] Uploaded sizes. */
    public array $uploadedsizes = [];
    /** @var file_lookup_result|null Forced lookup result. */
    public ?file_lookup_result $lookupresult = null;
    /** @var array<string, file_lookup_result> Lookup results keyed by SHA-256. */
    public array $lookupsbyhash = [];
    /** @var provider_exception|null Forced lookup error. */
    public ?provider_exception $lookupexception = null;
    /** @var submission_result|null Forced upload result. */
    public ?submission_result $uploadresult = null;
    /** @var provider_exception|null Forced upload error. */
    public ?provider_exception $uploadexception = null;
    /** @var analysis_result|null Forced analysis result. */
    public ?analysis_result $analysisresult = null;
    /** @var provider_exception|null Forced analysis error. */
    public ?provider_exception $analysisexception = null;

    /**
     * Connection test is unused in scan-engine tests.
     *
     * @return connection_result
     */
    public function test_connection(): connection_result {
        return new connection_result(true, 'connection_success');
    }

    /**
     * Hash lookup.
     *
     * @param string $sha256 Hex SHA-256.
     * @return file_lookup_result
     */
    public function lookup_file_hash(string $sha256): file_lookup_result {
        $this->lookupcount++;
        if ($this->lookupexception) {
            throw $this->lookupexception;
        }
        if (isset($this->lookupsbyhash[$sha256])) {
            return $this->lookupsbyhash[$sha256];
        }
        if ($this->lookupresult) {
            return $this->lookupresult;
        }
        return file_lookup_result::not_found($sha256);
    }

    /**
     * File upload.
     *
     * @param file_payload $file File payload.
     * @return submission_result
     */
    public function upload_file(file_payload $file): submission_result {
        $this->uploadcount++;
        $this->uploadednames[] = $file->filename;
        $this->uploadedsizes[] = $file->size;
        if ($this->uploadexception) {
            throw $this->uploadexception;
        }
        if ($this->uploadresult) {
            return $this->uploadresult;
        }
        return new submission_result('analysis-fake-1');
    }

    /**
     * Analysis retrieval.
     *
     * @param string $analysisid Analysis id.
     * @return analysis_result
     */
    public function get_analysis(string $analysisid): analysis_result {
        $this->analysiscount++;
        if ($this->analysisexception) {
            throw $this->analysisexception;
        }
        if ($this->analysisresult) {
            return $this->analysisresult;
        }
        return new analysis_result($analysisid, 'completed', [
            'malicious' => 0,
            'suspicious' => 0,
            'undetected' => 10,
            'harmless' => 5,
            'timeout' => 0,
        ]);
    }
}
