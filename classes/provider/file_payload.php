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
 * Provider-layer file payload. No Moodle course, user, or assignment fields.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\provider;


/**
 * File bytes or a readable stream for provider upload.
 */
final class file_payload {
    /**
     * Raw file bytes or an open readable stream.
     *
     * @var string|resource
     */
    public readonly mixed $contents;
    /** @var string Display name for the multipart upload only. */
    public readonly string $filename;
    /** @var int Size in bytes. */
    public readonly int $size;

    /**
     * Create a file payload.
     *
     * @param string|resource $contents Raw bytes or a readable stream.
     * @param string $filename Display name for the multipart upload only.
     * @param int|null $size Required when $contents is a stream.
     */
    public function __construct($contents, string $filename = 'file', ?int $size = null) {
        if ($filename === '') {
            throw new provider_exception('error_invalidrequest');
        }
        $this->filename = $filename;
        if (is_string($contents)) {
            $this->contents = $contents;
            $this->size = $size ?? strlen($contents);
            return;
        }
        if (is_resource($contents)) {
            if ($size === null || $size < 0) {
                throw new provider_exception('error_invalidrequest');
            }
            $this->contents = $contents;
            $this->size = $size;
            return;
        }
        throw new provider_exception('error_invalidrequest');
    }

    /**
     * Close a stream resource. No-op for string payloads.
     */
    public function close(): void {
        if (is_resource($this->contents)) {
            fclose($this->contents);
        }
    }
}
