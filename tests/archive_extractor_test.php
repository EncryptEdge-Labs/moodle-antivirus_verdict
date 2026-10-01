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

namespace antivirus_verdict;

use antivirus_verdict\local\archive_extractor;
use antivirus_verdict\local\archive_limits;
use antivirus_verdict\local\plugin_config;
use antivirus_verdict\tests\archive_test_helper;

/**
 * Tests for archive extraction.
 *
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @covers \antivirus_verdict\local\archive_extractor
 */
final class archive_extractor_test extends \advanced_testcase {
    /**
     * Clean multi-member zip extracts all regular files.
     */
    public function test_extracts_clean_zip_members(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $this->resetAfterTest();
        $zip = archive_test_helper::fixtures_dir() . '/clean.zip';
        archive_test_helper::write_zip($zip, [
            'a.txt' => 'alpha',
            'dir/b.txt' => 'beta',
        ]);
        $limits = new archive_limits(50, 1, 1024 * 1024, 1024 * 1024);
        $extractor = new archive_extractor($limits);
        $work = make_temp_directory('avvarchtest');
        $result = $extractor->extract_zip_path($zip, $work);
        $this->assertTrue($result->hasscanmembers);
        $this->assertCount(2, $result->members);
    }

    /**
     * Path traversal entries are rejected.
     */
    public function test_rejects_path_traversal_entries(): void {
        $extractor = new archive_extractor(new archive_limits(50, 1, 1024 * 1024, 1024));
        $this->assertFalse($extractor->is_safe_entry_name('../etc/passwd'));
        $this->assertFalse($extractor->is_safe_entry_name('/absolute.txt'));
        $this->assertFalse($extractor->is_safe_entry_name('C:\\Windows\\win.ini'));
    }

    /**
     * Member count limit stops extraction without treating archive as clean-only success.
     */
    public function test_member_limit_sets_limit_flag(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $entries = [];
        for ($i = 0; $i < 5; $i++) {
            $entries['f' . $i . '.txt'] = 'x';
        }
        $zip = archive_test_helper::fixtures_dir() . '/many.zip';
        archive_test_helper::write_zip($zip, $entries);
        $limits = new archive_limits(2, 0, 1024 * 1024, 1024);
        $extractor = new archive_extractor($limits);
        $work = make_temp_directory('avvarchlimit');
        $result = $extractor->extract_zip_path($zip, $work);
        $this->assertTrue($result->limitsexceeded);
        $this->assertLessThanOrEqual(2, count($result->members));
    }

    /**
     * Nested zip expands when depth allows.
     */
    /**
     * Nested zip beyond max depth is not expanded; outer member may still be scanned as a file.
     */
    public function test_nested_depth_zero_skips_inner(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $inner = archive_test_helper::fixtures_dir() . '/inneronly.zip';
        archive_test_helper::write_zip($inner, ['secret.txt' => 'hidden']);
        $outer = archive_test_helper::fixtures_dir() . '/outerdepth0.zip';
        $zip = new \ZipArchive();
        $zip->open($outer, \ZipArchive::CREATE | \ZipArchive::OVERWRITE);
        $zip->addFile($inner, 'nested.zip');
        $zip->close();

        $limits = new archive_limits(10, 0, 1024 * 1024, 1024 * 1024);
        $extractor = new archive_extractor($limits);
        $work = make_temp_directory('avvdepth0');
        $result = $extractor->extract_zip_path($outer, $work);
        $this->assertCount(1, $result->members);
        $this->assertStringContainsString('nested.zip', $result->members[0]['relpath']);
    }

    public function test_nested_zip_respects_depth(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $inner = archive_test_helper::fixtures_dir() . '/inner.zip';
        archive_test_helper::write_zip($inner, ['inner.txt' => 'nested-content']);
        $outer = archive_test_helper::fixtures_dir() . '/outer.zip';
        $zip = new \ZipArchive();
        $zip->open($outer, \ZipArchive::CREATE | \ZipArchive::OVERWRITE);
        $zip->addFile($inner, 'nested.zip');
        $zip->close();

        $limits = new archive_limits(10, 1, 1024 * 1024, 1024 * 1024);
        $extractor = new archive_extractor($limits);
        $work = make_temp_directory('avvnested');
        $result = $extractor->extract_zip_path($outer, $work);
        $this->assertTrue($result->hasscanmembers);
        $this->assertGreaterThanOrEqual(1, count($result->members));
    }

    /**
     * 7z extension is reported as unsupported.
     */
    /**
     * Corrupt or non-zip bytes are uninspectable.
     */
    public function test_corrupt_zip_is_uninspectable(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $path = archive_test_helper::fixtures_dir() . '/corrupt.zip';
        file_put_contents($path, 'not-a-valid-zip-header');
        $extractor = new archive_extractor(new archive_limits(50, 1, 1024 * 1024, 1024));
        $work = make_temp_directory('avvcorrupt');
        $result = $extractor->extract_zip_path($path, $work);
        $this->assertTrue($result->uninspectable);
        $this->assertSame('error_archive_corrupt', $result->reason);
    }

    /**
     * Empty zip yields no scan members (not treated as a successful deep scan).
     */
    public function test_empty_zip_has_no_members(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $path = archive_test_helper::fixtures_dir() . '/dironly.zip';
        @unlink($path);
        $this->assertTrue(archive_test_helper::write_dir_only_zip($path));
        $extractor = new archive_extractor(new archive_limits(50, 1, 1024 * 1024, 1024));
        $work = make_temp_directory('avvempty');
        $result = $extractor->extract_zip_path($path, $work);
        $this->assertSame([], $result->members);
        $this->assertFalse($result->limitsexceeded);
        $this->assertFalse($result->uninspectable);
    }

    /**
     * Aggregate extracted byte cap is enforced across members.
     */
    public function test_aggregate_extracted_limit(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $zip = archive_test_helper::fixtures_dir() . '/bigmembers.zip';
        archive_test_helper::write_zip($zip, [
            'a.bin' => str_repeat('a', 500),
            'b.bin' => str_repeat('b', 500),
        ]);
        $limits = new archive_limits(50, 0, 600, 1024);
        $extractor = new archive_extractor($limits);
        $work = make_temp_directory('avvagg');
        $result = $extractor->extract_zip_path($zip, $work);
        $this->assertTrue($result->limitsexceeded);
    }

    /**
     * Individual member size cap triggers limit flag.
     */
    public function test_oversized_member_limit(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $zip = archive_test_helper::fixtures_dir() . '/onembig.zip';
        archive_test_helper::write_zip($zip, ['large.bin' => str_repeat('z', 200)]);
        $limits = new archive_limits(50, 0, 1024 * 1024, 100);
        $extractor = new archive_extractor($limits);
        $work = make_temp_directory('avvbigone');
        $result = $extractor->extract_zip_path($zip, $work);
        $this->assertTrue($result->limitsexceeded);
    }

    /**
     * UNC-style entry names are rejected.
     */
    public function test_rejects_unc_paths(): void {
        $extractor = new archive_extractor(new archive_limits(50, 1, 1024, 1024));
        $this->assertFalse($extractor->is_safe_entry_name('\\\\server\\share\\evil.txt'));
    }

    /**
     * MBZ extension is detected as mbz format.
     */
    public function test_detects_mbz_format(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $fs = get_file_storage();
        $file = $fs->create_file_from_string([
            'contextid' => \context_system::instance()->id,
            'component' => 'user',
            'filearea' => 'draft',
            'itemid' => file_get_unused_draft_itemid(),
            'filepath' => '/',
            'filename' => 'course.mbz',
        ], 'PK');
        $extractor = new archive_extractor(archive_limits::from_site_config(new plugin_config(true, 1024)));
        $this->assertSame('mbz', $extractor->detect_format($file));
    }

    /**
     * RAR extension is unsupported on portable hosting.
     */
    public function test_detects_unsupported_rar(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $fs = get_file_storage();
        $file = $fs->create_file_from_string([
            'contextid' => \context_system::instance()->id,
            'component' => 'user',
            'filearea' => 'draft',
            'itemid' => file_get_unused_draft_itemid(),
            'filepath' => '/',
            'filename' => 'data.rar',
        ], 'rar');
        $extractor = new archive_extractor(archive_limits::from_site_config(new plugin_config(true, 1024)));
        $this->assertSame('unsupported_rar', $extractor->detect_format($file));
    }

    /**
     * Ordinary HTML is not treated as any archive format.
     */
    public function test_html_is_not_archive(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $fs = get_file_storage();
        $file = $fs->create_file_from_string([
            'contextid' => \context_system::instance()->id,
            'component' => 'user',
            'filearea' => 'draft',
            'itemid' => file_get_unused_draft_itemid(),
            'filepath' => '/',
            'filename' => 'portfolio-track-notice.html',
        ], '<!DOCTYPE html><html><body>notice</body></html>');
        $extractor = new archive_extractor(archive_limits::from_site_config(new plugin_config(true, 1024)));
        $this->assertSame('not_archive', $extractor->detect_format($file));
        $this->assertSame('text/html', $file->get_mimetype());
    }

    /**
     * A declared size far above the compressed size is rejected before inflate.
     */
    public function test_compression_ratio_is_rejected_before_inflate(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $this->resetAfterTest();
        $zip = archive_test_helper::fixtures_dir() . '/ratio.zip';
        $this->write_lying_size_zip($zip, 'bomb.txt', 20, 2000000);
        $limits = new archive_limits(50, 1, 1024 * 1024 * 1024, 1024 * 1024 * 1024);
        $extractor = new archive_extractor($limits);
        $work = make_temp_directory('avvarchratio');
        $result = $extractor->extract_zip_path($zip, $work);
        $this->assertTrue($result->limitsexceeded);
        $this->assertSame([], $result->members);
        $this->assertSame('error_archive_limits', $result->reason);
        $this->assertNotEmpty($result->skipped);
        $this->assertFileDoesNotExist($work . DIRECTORY_SEPARATOR . 'bomb.txt');
    }

    /**
     * An archive whose only file cannot be extracted is not reported as empty.
     */
    public function test_unsafe_only_archive_is_not_empty(): void {
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('ZipArchive not available');
        }
        $this->resetAfterTest();
        $zip = archive_test_helper::fixtures_dir() . '/unsafe.zip';
        $archive = new \ZipArchive();
        $this->assertTrue($archive->open($zip, \ZipArchive::CREATE | \ZipArchive::OVERWRITE));
        $archive->addFromString('../evil.txt', 'secret');
        $archive->close();
        $limits = new archive_limits(50, 1, 1024 * 1024, 1024 * 1024);
        $extractor = new archive_extractor($limits);
        $work = make_temp_directory('avvarchunsafe');
        $result = $extractor->extract_zip_path($zip, $work);
        if ($result->hasscanmembers) {
            $this->markTestSkipped('ZipArchive normalised the unsafe entry name');
        }
        $this->assertTrue($result->uninspectable);
        $this->assertSame('error_archive_member', $result->reason);
        $this->assertNotSame('', $result->reason);
    }

    public function test_detects_unsupported_7z(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $fs = get_file_storage();
        $file = $fs->create_file_from_string([
            'contextid' => \context_system::instance()->id,
            'component' => 'user',
            'filearea' => 'draft',
            'itemid' => file_get_unused_draft_itemid(),
            'filepath' => '/',
            'filename' => 'bundle.7z',
        ], '7z');
        $extractor = new archive_extractor(archive_limits::from_site_config(new plugin_config(true, 1024)));
        $this->assertSame('unsupported_7z', $extractor->detect_format($file));
    }

    /**
     * Write a stored ZIP whose declared uncompressed size is far above the payload.
     *
     * @param string $path Output path.
     * @param string $name Entry name.
     * @param int $compressed Compressed size and payload length.
     * @param int $uncompressed Declared uncompressed size.
     */
    private function write_lying_size_zip(string $path, string $name, int $compressed, int $uncompressed): void {
        $payload = str_repeat("\0", $compressed);
        $namelen = strlen($name);
        $local = pack(
            'VvvvvvVVVvv',
            0x04034b50,
            20,
            0,
            0,
            0,
            0,
            0,
            $compressed,
            $uncompressed,
            $namelen,
            0
        ) . $name . $payload;
        $central = pack(
            'VvvvvvvVVVvvvvvVV',
            0x02014b50,
            20,
            20,
            0,
            0,
            0,
            0,
            0,
            $compressed,
            $uncompressed,
            $namelen,
            0,
            0,
            0,
            0,
            0,
            0
        ) . $name;
        $eocd = pack(
            'VvvvvVVv',
            0x06054b50,
            0,
            0,
            1,
            1,
            strlen($central),
            strlen($local),
            0
        );
        file_put_contents($path, $local . $central . $eocd);
    }
}
