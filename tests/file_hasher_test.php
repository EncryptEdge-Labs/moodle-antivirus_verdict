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
 * Tests for streaming SHA-256 of Moodle stored files.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\file_hasher;


/**
 * SHA-256 hashing via the File API.
 *
 * @covers \antivirus_verdict\local\file_hasher
 */
final class file_hasher_test extends \advanced_testcase {
    /** Empty-file SHA-256. */
    private const EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

    /** SHA-256 of "hello". */
    private const HELLO_SHA256 = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';

    /**
     * Known ASCII content matches the published SHA-256.
     */
    public function test_known_file_hash(): void {
        $this->resetAfterTest();
        $file = $this->create_file('hello.txt', 'hello');
        $hash = (new file_hasher())->hash_stored_file($file);
        $this->assertSame(self::HELLO_SHA256, $hash);
        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $hash);
        $this->assertNotEquals($file->get_contenthash(), $hash);
    }

    /**
     * Empty file has the documented SHA-256.
     */
    public function test_empty_file_hash(): void {
        $this->resetAfterTest();
        $file = $this->create_file('empty.bin', '');
        $this->assertSame(self::EMPTY_SHA256, (new file_hasher())->hash_stored_file($file));
    }

    /**
     * Binary content is hashed from bytes, not the filename.
     */
    public function test_binary_file_hash(): void {
        $this->resetAfterTest();
        $content = "\x00\x01\x02\xff";
        $file = $this->create_file('binary.dat', $content);
        $expected = hash('sha256', $content);
        $this->assertSame($expected, (new file_hasher())->hash_stored_file($file));
    }

    /**
     * Larger content is streamed rather than treated as a filename hash.
     */
    public function test_larger_file_hash(): void {
        $this->resetAfterTest();
        $content = str_repeat("A\x00B", 20000);
        $file = $this->create_file('large.bin', $content);
        $this->assertSame(hash('sha256', $content), (new file_hasher())->hash_stored_file($file));
    }

    /**
     * The hasher streams chunks and does not load the whole file via file_get_contents.
     */
    public function test_hasher_does_not_use_file_get_contents(): void {
        $source = file_get_contents(__DIR__ . '/../classes/local/file_hasher.php');
        $this->assertStringNotContainsString('file_get_contents', $source);
        $this->assertStringContainsString('fread', $source);
        $service = file_get_contents(__DIR__ . '/../classes/local/scan_service.php');
        $this->assertStringContainsString('get_content_file_handle', $service);
        $this->assertDoesNotMatchRegularExpression('/file_get_contents\s*\(\s*\$file/', $service);
    }

    /**
     * Filesystem paths are hashed by streaming, independently of contenthash.
     */
    public function test_hash_path_matches_known_digest(): void {
        $this->resetAfterTest();
        $path = make_request_directory() . '/hello.bin';
        file_put_contents($path, 'hello');
        $this->assertSame(self::HELLO_SHA256, (new file_hasher())->hash_path($path));
    }

    /**
     * Unreadable paths fail closed.
     */
    public function test_hash_path_rejects_missing_file(): void {
        $this->expectException(\invalid_parameter_exception::class);
        (new file_hasher())->hash_path(make_request_directory() . '/missing.bin');
    }

    /**
     * Directory placeholders cannot be hashed.
     */
    public function test_directory_is_rejected(): void {
        $this->resetAfterTest();
        $fs = get_file_storage();
        $context = \context_system::instance();
        $dir = $fs->create_directory($context->id, 'antivirus_verdict', 'unittest', 1, '/');
        $this->assertTrue($dir->is_directory());
        $this->expectException(\invalid_parameter_exception::class);
        (new file_hasher())->hash_stored_file($dir);
    }

    /**
     * Create a stored file in the system context.
     *
     * @param string $filename File name.
     * @param string $content File bytes.
     * @return \stored_file
     */
    private function create_file(string $filename, string $content): \stored_file {
        $fs = get_file_storage();
        $context = \context_system::instance();
        return $fs->create_file_from_string([
            'contextid' => $context->id,
            'component' => 'antivirus_verdict',
            'filearea' => 'unittest',
            'itemid' => random_int(1, 100000000),
            'filepath' => '/',
            'filename' => $filename,
        ], $content);
    }
}
