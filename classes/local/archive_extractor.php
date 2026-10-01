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
 * Portable ZIP/MBZ extraction for archive member scanning.
 *
 * 7z and RAR are not supported here: they require external binaries or PECL
 * extensions that are unavailable on typical Moodle shared hosting.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;


/**
 * Extracts regular files into a caller-owned temp directory using ZipArchive only.
 */
class archive_extractor {
    /** @var archive_limits Extraction limits. */
    private archive_limits $limits;

    /**
     * Create an archive extractor.
     *
     * @param archive_limits $limits Active limits.
     */
    public function __construct(archive_limits $limits) {
        $this->limits = $limits;
    }

    /**
     * Detect whether a stored file is a supported ZIP-style container.
     *
     * @param \stored_file $file Moodle file.
     * @return string One of zip, mbz, unsupported_7z, unsupported_rar, not_archive.
     */
    public function detect_format(\stored_file $file): string {
        $name = strtolower($file->get_filename());
        if (str_ends_with($name, '.7z')) {
            return 'unsupported_7z';
        }
        if (preg_match('/\.(rar|r\d{2})$/', $name)) {
            return 'unsupported_rar';
        }
        $mimetype = (string) $file->get_mimetype();
        if (in_array($mimetype, ['application/zip', 'application/vnd.moodle.backup'], true)) {
            return str_ends_with($name, '.mbz') ? 'mbz' : 'zip';
        }
        if (str_ends_with($name, '.zip')) {
            return 'zip';
        }
        if (str_ends_with($name, '.mbz')) {
            return 'mbz';
        }
        return 'not_archive';
    }

    /**
     * Extract members from a local zip path into a dedicated temp directory.
     *
     * @param string $zippath Readable local zip path.
     * @param string $workdir Empty directory that will receive extracted files.
     * @param int|null $deadline Unix timestamp after which extraction stops.
     * @return archive_extract_result
     */
    public function extract_zip_path(
        string $zippath,
        string $workdir,
        ?int $deadline = null
    ): archive_extract_result {
        if (!class_exists('ZipArchive')) {
            return new archive_extract_result(false, false, true, 'error_archive_unavailable');
        }
        if ($zippath === '' || !is_readable($zippath) || !is_dir($workdir)) {
            return new archive_extract_result(false, false, true, 'error_archive_corrupt');
        }

        $deadline = $deadline ?? (time() + archive_limits::MAX_WORK_SECONDS);
        $members = [];
        $skipped = [];
        $queued = 0;
        $extractedbytes = 0;
        $limitsexceeded = false;

        $this->walk_zip(
            $zippath,
            $workdir,
            '',
            0,
            $deadline,
            $members,
            $skipped,
            $queued,
            $extractedbytes,
            $limitsexceeded
        );

        if ($members === [] && !$limitsexceeded) {
            $zip = new \ZipArchive();
            $open = $zip->open($zippath);
            if ($open !== true) {
                return new archive_extract_result(false, false, true, 'error_archive_corrupt', [], $skipped);
            }
            if ($zip->numFiles === 0) {
                $zip->close();
                return new archive_extract_result(false, false, false, '', [], $skipped);
            }
            if ($this->zip_is_encrypted($zip)) {
                $zip->close();
                return new archive_extract_result(false, false, true, 'error_archive_encrypted', [], $skipped);
            }
            $zip->close();
            if ($this->skipped_real_members($skipped)) {
                return new archive_extract_result(false, false, true, 'error_archive_member', [], $skipped);
            }
            return new archive_extract_result(false, false, false, '', [], $skipped);
        }

        // A real member that could not be extracted stays visible even when
        // other members were queued. The scanner marks that parent incomplete.
        $reason = '';
        if ($limitsexceeded) {
            $reason = 'error_archive_limits';
        } else if ($this->skipped_real_members($skipped)) {
            $reason = 'error_archive_member';
        }
        return new archive_extract_result(
            $members !== [],
            $limitsexceeded,
            false,
            $reason,
            $members,
            $skipped
        );
    }

    /**
     * Real file names from the central directory.
     *
     * Uses statIndex only. Member contents are not inflated.
     *
     * @param string $zippath Zip path.
     * @return string[]|null Null when the archive cannot be opened.
     */
    public function list_real_entry_names(string $zippath): ?array {
        $zip = new \ZipArchive();
        $open = $zip->open($zippath);
        if ($open !== true) {
            return null;
        }
        $names = [];
        for ($index = 0; $index < $zip->numFiles; $index++) {
            $stat = $zip->statIndex($index);
            if (!is_array($stat) || empty($stat['name'])) {
                continue;
            }
            $entryname = (string) $stat['name'];
            if (str_ends_with($entryname, '/')) {
                continue;
            }
            if ((int) ($stat['size'] ?? 0) <= 0) {
                continue;
            }
            $names[] = $entryname;
        }
        $zip->close();
        return $names;
    }

    /**
     * Walk one zip file, optionally recursing into nested zip/mbz members.
     *
     * @param string $zippath Zip path.
     * @param string $workroot Extraction root for canonical checks.
     * @param string $prefix Relative prefix inside workroot.
     * @param int $depth Current nesting depth.
     * @param int $deadline Stop work after this time.
     * @param array $members Out: collected members.
     * @param array $skipped Out: members that were not queued.
     * @param int $queued In/out: member count.
     * @param int $extractedbytes In/out: aggregate bytes.
     * @param bool $limitsexceeded In/out: limit flag.
     */
    private function walk_zip(
        string $zippath,
        string $workroot,
        string $prefix,
        int $depth,
        int $deadline,
        array &$members,
        array &$skipped,
        int &$queued,
        int &$extractedbytes,
        bool &$limitsexceeded
    ): void {
        if (time() >= $deadline) {
            $limitsexceeded = true;
            return;
        }

        $zip = new \ZipArchive();
        if ($zip->open($zippath) !== true) {
            return;
        }
        if ($this->zip_is_encrypted($zip)) {
            $zip->close();
            return;
        }

        $workrootreal = realpath($workroot);
        if ($workrootreal === false) {
            $zip->close();
            return;
        }

        for ($index = 0; $index < $zip->numFiles; $index++) {
            if (time() >= $deadline || $queued >= $this->limits->maxmembers) {
                $limitsexceeded = true;
                break;
            }
            $stat = $zip->statIndex($index);
            if (!is_array($stat) || empty($stat['name'])) {
                continue;
            }
            $entryname = (string) $stat['name'];
            if (str_ends_with($entryname, '/')) {
                continue;
            }
            if (!$this->is_safe_entry_name($entryname)) {
                $skipped[] = ['relpath' => $entryname, 'reason' => 'error_archive_member'];
                continue;
            }
            if (($stat['size'] ?? 0) === 0 && ($stat['comp_size'] ?? 0) === 0) {
                continue;
            }
            $uncompressed = (int) ($stat['size'] ?? 0);
            if ($uncompressed <= 0) {
                continue;
            }
            if ($uncompressed > $this->limits->maxmemberbytes) {
                $limitsexceeded = true;
                $skipped[] = ['relpath' => $entryname, 'reason' => 'error_archive_limits'];
                continue;
            }
            if ($extractedbytes + $uncompressed > $this->limits->maxextractedbytes) {
                $limitsexceeded = true;
                break;
            }
            $compressed = (int) ($stat['comp_size'] ?? 0);
            if ($compressed <= 0 || intdiv($uncompressed, $compressed) > archive_limits::MAX_COMPRESSION_RATIO) {
                $limitsexceeded = true;
                $skipped[] = ['relpath' => $entryname, 'reason' => 'error_archive_limits'];
                continue;
            }

            $relpath = $this->normalise_member_relpath($prefix, $entryname);
            if ($relpath === '') {
                $skipped[] = ['relpath' => $entryname, 'reason' => 'error_archive_member'];
                continue;
            }
            $targetdir = $workroot . DIRECTORY_SEPARATOR . dirname(str_replace('/', DIRECTORY_SEPARATOR, $relpath));
            if (!is_dir($targetdir) && !@mkdir($targetdir, 0700, true) && !is_dir($targetdir)) {
                $skipped[] = ['relpath' => $entryname, 'reason' => 'error_archive_member'];
                continue;
            }
            $target = $workroot . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relpath);
            $contents = $zip->getFromIndex($index);
            if ($contents === false) {
                $skipped[] = ['relpath' => $relpath, 'reason' => 'error_archive_member'];
                continue;
            }
            if (strlen($contents) !== $uncompressed) {
                $skipped[] = ['relpath' => $relpath, 'reason' => 'error_archive_member'];
                continue;
            }
            if (@file_put_contents($target, $contents) === false) {
                $skipped[] = ['relpath' => $relpath, 'reason' => 'error_archive_member'];
                continue;
            }
            @chmod($target, 0600);
            if (!$this->path_within_root($workrootreal, $target)) {
                @unlink($target);
                $skipped[] = ['relpath' => $relpath, 'reason' => 'error_archive_member'];
                continue;
            }

            $lower = strtolower(basename($relpath));
            $isnested = str_ends_with($lower, '.zip') || str_ends_with($lower, '.mbz');
            if ($isnested && $depth < $this->limits->maxdepth) {
                $nesteddir = $target . '_nested';
                if (@mkdir($nesteddir, 0700, true) || is_dir($nesteddir)) {
                    $this->walk_zip(
                        $target,
                        $nesteddir,
                        $relpath . '/',
                        $depth + 1,
                        $deadline,
                        $members,
                        $skipped,
                        $queued,
                        $extractedbytes,
                        $limitsexceeded
                    );
                }
                @unlink($target);
                continue;
            }

            $members[] = [
                'abspath' => $target,
                'relpath' => $relpath,
                'size' => $uncompressed,
                'depth' => $depth,
            ];
            $queued++;
            $extractedbytes += $uncompressed;
        }

        $zip->close();
    }

    /**
     * Whether any skipped entry was a real file rather than a limit.
     *
     * @param array $skipped Skip records from walk_zip.
     * @return bool
     */
    public function skipped_real_members(array $skipped): bool {
        foreach ($skipped as $skip) {
            if ((string) ($skip['reason'] ?? '') === 'error_archive_member') {
                return true;
            }
        }
        return false;
    }

    /**
     * Whether a zip entry name is safe to process.
     *
     * @param string $name Raw zip entry path.
     * @return bool
     */
    public function is_safe_entry_name(string $name): bool {
        if ($name === '' || strlen($name) > archive_limits::MAX_ENTRY_PATH_LENGTH) {
            return false;
        }
        if (str_contains($name, "\0")) {
            return false;
        }
        if (str_starts_with($name, '/') || str_starts_with($name, '\\')) {
            return false;
        }
        if (preg_match('/^[a-zA-Z]:[\\\\\\/]/', $name)) {
            return false;
        }
        if (str_starts_with($name, '\\\\') || str_starts_with($name, '//')) {
            return false;
        }
        $parts = preg_split('#/+#', str_replace('\\', '/', $name));
        foreach ($parts as $part) {
            if ($part === '..' || $part === '') {
                return false;
            }
        }
        return true;
    }

    /**
     * Build a safe relative path for an extracted member.
     *
     * @param string $prefix Path prefix for nested archives.
     * @param string $entryname Zip entry name.
     * @return string Normalised relative path or empty when invalid.
     */
    private function normalise_member_relpath(string $prefix, string $entryname): string {
        $entryname = str_replace('\\', '/', $entryname);
        $combined = $prefix . $entryname;
        $parts = [];
        foreach (explode('/', $combined) as $part) {
            if ($part === '' || $part === '.') {
                continue;
            }
            if ($part === '..') {
                return '';
            }
            $parts[] = $part;
        }
        if ($parts === []) {
            return '';
        }
        $relpath = implode('/', $parts);
        if (strlen($relpath) > archive_limits::MAX_ENTRY_PATH_LENGTH) {
            return '';
        }
        return $relpath;
    }

    /**
     * Canonical path containment check.
     *
     * @param string $rootreal Realpath of extraction root.
     * @param string $candidate Candidate file path.
     * @return bool
     */
    public function path_within_root(string $rootreal, string $candidate): bool {
        $real = realpath($candidate);
        if ($real === false) {
            return false;
        }
        $root = rtrim(str_replace('\\', '/', $rootreal), '/');
        $path = str_replace('\\', '/', $real);
        return $path === $root || str_starts_with($path, $root . '/');
    }

    /**
     * Detect encryption on sample zip entries.
     *
     * @param \ZipArchive $zip Open archive.
     * @return bool
     */
    private function zip_is_encrypted(\ZipArchive $zip): bool {
        for ($i = 0; $i < min($zip->numFiles, 20); $i++) {
            $stat = $zip->statIndex($i);
            if (is_array($stat) && !empty($stat['encryption_method'])) {
                return true;
            }
        }
        return false;
    }
}
