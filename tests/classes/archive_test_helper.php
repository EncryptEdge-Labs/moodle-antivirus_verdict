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

namespace antivirus_verdict\tests;


/**
 * Builds small synthetic ZIP fixtures for archive unit tests.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
final class archive_test_helper {
    /**
     * Write a zip file containing the given entries.
     *
     * @param string $path Output path.
     * @param array<string,string> $entries Map of entry path to file contents.
     * @return bool
     */
    public static function write_zip(string $path, array $entries): bool {
        if (!class_exists('ZipArchive')) {
            return false;
        }
        $zip = new \ZipArchive();
        if ($zip->open($path, \ZipArchive::CREATE | \ZipArchive::OVERWRITE) !== true) {
            return false;
        }
        foreach ($entries as $name => $content) {
            $zip->addFromString($name, $content);
        }
        $closed = $zip->close();
        return $closed && is_file($path);
    }

    /**
     * Create a password-protected ZIP when the PHP build supports ZipArchive encryption.
     *
     * @param string $path Output path.
     * @return bool False when encryption cannot be applied on this runtime.
     */
    public static function write_encrypted_zip(string $path): bool {
        if (!class_exists('ZipArchive')) {
            return false;
        }
        if (!defined('ZipArchive::EM_AES_256')) {
            return false;
        }
        $zip = new \ZipArchive();
        if ($zip->open($path, \ZipArchive::CREATE | \ZipArchive::OVERWRITE) !== true) {
            return false;
        }
        $entry = 'secret.txt';
        if (!$zip->addFromString($entry, 'encrypted-payload')) {
            $zip->close();
            return false;
        }
        $zip->setPassword('phpunit-archive-password');
        if (!$zip->setEncryptionName($entry, \ZipArchive::EM_AES_256)) {
            $zip->close();
            return false;
        }
        $closed = $zip->close();
        return $closed && is_file($path);
    }

    /**
     * Write a zip that contains only directory entries (no scannable files).
     *
     * @param string $path Output path.
     * @return bool
     */
    public static function write_dir_only_zip(string $path): bool {
        if (!class_exists('ZipArchive')) {
            return false;
        }
        $zip = new \ZipArchive();
        if ($zip->open($path, \ZipArchive::CREATE | \ZipArchive::OVERWRITE) !== true) {
            return false;
        }
        $zip->addEmptyDir('emptydir');
        $closed = $zip->close();
        return $closed && is_file($path);
    }

    /**
     * Write a stored-method ZIP that preserves entry names exactly.
     *
     * ZipArchive::addFromString() may normalise unsafe names. Tests that need
     * a real member such as ../evil.txt use this writer instead.
     *
     * @param string $path Output path.
     * @param array<string,string> $entries Entry name to payload.
     */
    public static function write_stored_entries(string $path, array $entries): void {
        $locals = '';
        $centrals = '';
        $count = 0;
        foreach ($entries as $name => $payload) {
            $name = (string) $name;
            $payload = (string) $payload;
            $size = strlen($payload);
            $namelen = strlen($name);
            $crc = crc32($payload);
            $offset = strlen($locals);
            $locals .= pack(
                'VvvvvvVVVvv',
                0x04034b50,
                20,
                0,
                0,
                0,
                0,
                $crc,
                $size,
                $size,
                $namelen,
                0
            ) . $name . $payload;
            $centrals .= pack(
                'VvvvvvvVVVvvvvvVV',
                0x02014b50,
                20,
                20,
                0,
                0,
                0,
                0,
                $crc,
                $size,
                $size,
                $namelen,
                0,
                0,
                0,
                0,
                0,
                $offset
            ) . $name;
            $count++;
        }
        $eocd = pack(
            'VvvvvVVv',
            0x06054b50,
            0,
            0,
            $count,
            $count,
            strlen($centrals),
            strlen($locals),
            0
        );
        file_put_contents($path, $locals . $centrals . $eocd);
    }

    /**
     * Fixture directory under tests/fixtures/archives (created on demand).
     *
     * @return string Absolute directory path.
     */
    public static function fixtures_dir(): string {
        $dir = dirname(__DIR__) . '/fixtures/archives';
        if (!is_dir($dir)) {
            mkdir($dir, 0777, true);
        }
        return $dir;
    }
}
