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
 * Streaming SHA-256 of Moodle stored files.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;


/**
 * Calculates SHA-256 from Moodle File API content, not from contenthash.
 */
class file_hasher {
    /** Read size for streaming hash updates. */
    public const CHUNK_BYTES = 1048576;

    /**
     * SHA-256 of a Moodle stored file's content.
     *
     * @param \stored_file $file Moodle file.
     * @return string Lowercase 64-character hex digest.
     */
    public function hash_stored_file(\stored_file $file): string {
        if ($file->is_directory()) {
            throw new \invalid_parameter_exception('error_invalidfile');
        }
        $handle = $file->get_content_file_handle();
        if ($handle === false) {
            throw new \invalid_parameter_exception('error_invalidfile');
        }
        try {
            return $this->hash_handle($handle);
        } finally {
            fclose($handle);
        }
    }

    /**
     * SHA-256 of a filesystem path. Streams the file; does not load it into memory.
     *
     * @param string $path Absolute filesystem path.
     * @return string Lowercase 64-character hex digest.
     */
    public function hash_path(string $path): string {
        if ($path === '' || !is_file($path) || !is_readable($path)) {
            throw new \invalid_parameter_exception('error_invalidfile');
        }
        $handle = fopen($path, 'rb');
        if ($handle === false) {
            throw new \invalid_parameter_exception('error_invalidfile');
        }
        try {
            return $this->hash_handle($handle);
        } finally {
            fclose($handle);
        }
    }

    /**
     * SHA-256 of an already-open readable stream. Does not close the handle.
     *
     * @param resource $handle Readable stream.
     * @return string Lowercase 64-character hex digest.
     */
    public function hash_handle($handle): string {
        if (!is_resource($handle)) {
            throw new \invalid_parameter_exception('error_invalidfile');
        }
        $context = hash_init('sha256');
        while (!feof($handle)) {
            $chunk = fread($handle, self::CHUNK_BYTES);
            if ($chunk === false) {
                throw new \invalid_parameter_exception('error_invalidfile');
            }
            if ($chunk === '') {
                break;
            }
            hash_update($context, $chunk);
        }
        $hash = strtolower(hash_final($context));
        if (!preg_match('/^[a-f0-9]{64}$/', $hash)) {
            throw new \invalid_parameter_exception('error_invalidfile');
        }
        return $hash;
    }
}
