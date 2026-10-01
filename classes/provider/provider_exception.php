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
 * Normalised provider exception.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\provider;


/**
 * Transport/provider failure with a stable error code and redacted debug text.
 *
 * User-facing text comes from language strings. Debug info is for developers
 * and must never contain API keys or authorisation headers.
 */
class provider_exception extends \moodle_exception {
    /** @var int|null HTTP status when the failure came from HTTP. */
    public readonly ?int $httpstatus;

    /** @var int|null Seconds from Retry-After, when present. */
    public readonly ?int $retryafter;

    /**
     * Create a provider exception.
     *
     * @param string $errorcode Language string id in antivirus_verdict.
     * @param string $debuginfo Optional developer detail, already redacted.
     * @param int|null $httpstatus HTTP status when the failure came from HTTP.
     * @param int|null $retryafter Seconds from Retry-After, when present.
     */
    public function __construct(
        string $errorcode,
        string $debuginfo = '',
        ?int $httpstatus = null,
        ?int $retryafter = null
    ) {
        $this->httpstatus = $httpstatus;
        $this->retryafter = $retryafter;
        parent::__construct($errorcode, 'antivirus_verdict', '', null, $debuginfo);
    }

    /**
     * Remove secrets and authorisation headers from text that might be stored.
     *
     * @param string $text Raw message.
     * @param string $secret Optional API key to strip.
     * @return string
     */
    public static function redact(string $text, string $secret = ''): string {
        $redacted = preg_replace('/x-apikey\s*[:=]\s*\S+/i', 'x-apikey: [redacted]', $text);
        if (!is_string($redacted)) {
            $redacted = $text;
        }
        $redacted = preg_replace(
            '/(authorization|proxy-authorization)\s*[:=]\s*\S+/i',
            '$1: [redacted]',
            $redacted
        );
        if (!is_string($redacted)) {
            $redacted = $text;
        }
        if ($secret !== '') {
            $redacted = str_replace($secret, '[redacted]', $redacted);
        }
        return $redacted;
    }
}
