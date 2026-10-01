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
 * Site configuration credential provider.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

use antivirus_verdict\provider\provider_exception;


/**
 * Reads the VirusTotal API key from Moodle plugin settings.
 *
 * Other plugin classes must use this service instead of calling get_config()
 * for the API key.
 */
class config_credentials implements credential_provider {
    /**
     * Setting name inside the antivirus_verdict plugin config.
     */
    public const SETTING_APIKEY = 'apikey';

    /**
     * Return the configured API key.
     *
     * @return string
     */
    public function get_api_key(): string {
        $key = trim((string) get_config('antivirus_verdict', self::SETTING_APIKEY));
        if ($key === '') {
            throw new provider_exception('error_nokey');
        }
        return $key;
    }

    /**
     * Whether a non-empty API key is configured.
     *
     * @return bool
     */
    public function has_api_key(): bool {
        return trim((string) get_config('antivirus_verdict', self::SETTING_APIKEY)) !== '';
    }
}
