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
 * Queue extracted archive members through scan_service.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

use antivirus_verdict\archive_outcome;
use antivirus_verdict\enforcement_state;
use antivirus_verdict\scan_phase;
use antivirus_verdict\scan_source;
use antivirus_verdict\scan_status;


/**
 * Materialises temp members as short-lived gate copies and enqueues scans.
 */
class archive_member_scanner {
    /** @var scan_service Scan engine. */
    private scan_service $scanservice;

    /**
     * Create a member scanner.
     *
     * @param scan_service $scanservice Scan engine.
     */
    public function __construct(scan_service $scanservice) {
        $this->scanservice = $scanservice;
    }

    /**
     * Queue scans for extracted members.
     *
     * @param \stdClass $parent Container scan row.
     * @param archive_extract_result $extraction Extraction result.
     * @return int Number of member scans queued.
     */
    public function queue_members(\stdClass $parent, archive_extract_result $extraction): int {
        if ($extraction->members === []) {
            return 0;
        }
        $context = \context_system::instance();
        $userid = (int) ($parent->userid ?? 0);
        $parentid = (int) $parent->id;
        $queued = 0;
        $existing = [];
        foreach ((new scan_repository())->find_children_by_parent($parentid) as $child) {
            $existing[(string) $child->filepath . "\0" . (string) $child->filename] = true;
        }

        foreach ($extraction->members as $member) {
            $abspath = (string) ($member['abspath'] ?? '');
            $relpath = (string) ($member['relpath'] ?? '');
            if ($abspath === '' || !is_readable($abspath)) {
                $this->note_unscanned_member($parent, $extraction, $relpath, $existing);
                if ($abspath !== '' && is_file($abspath)) {
                    @unlink($abspath);
                }
                continue;
            }
            $filename = self::member_filename($relpath);
            if ($filename === '') {
                $this->note_unscanned_member($parent, $extraction, $relpath, $existing);
                @unlink($abspath);
                continue;
            }
            $filepath = self::member_filepath($relpath);
            if (isset($existing[$filepath . "\0" . $filename])) {
                @unlink($abspath);
                continue;
            }
            $copy = null;
            try {
                $copy = plugin_file_lifecycle::store_path_copy($abspath, $filename, $context, $userid);
                $scan = $this->scanservice->enqueue_file_scan(
                    $copy,
                    scan_source::ARCHIVE,
                    $userid,
                    false,
                    $parentid,
                    $filepath,
                    (int) ($parent->submissionid ?? 0),
                    (int) ($parent->initiatedby ?? 0)
                );
                $this->reuse_parent_context($scan, $parent);
                $existing[$filepath . "\0" . $filename] = true;
                $queued++;
                $copy = null;
            } catch (\Throwable $e) {
                debugging('antivirus_verdict archive member queue failed: ' . $relpath, \DEBUG_DEVELOPER);
                if ($copy) {
                    try {
                        $copy->delete();
                    } catch (\Throwable $cleanup) {
                        debugging(
                            'antivirus_verdict archive member copy cleanup failed: ' . $cleanup->getMessage(),
                            \DEBUG_DEVELOPER
                        );
                    }
                }
                $this->note_unscanned_member($parent, $extraction, $relpath, $existing);
            } finally {
                if ($abspath !== '' && is_file($abspath)) {
                    @unlink($abspath);
                }
            }
        }

        return $queued;
    }

    /**
     * Copy the parent's Moodle context onto a member row.
     *
     * The member bytes live in a plugin copy. Course, module context, and the
     * parent's initiator are the context that already belongs to the container.
     * Component and file area stay on the copy.
     *
     * @param \stdClass $scan Member scan row.
     * @param \stdClass $parent Container scan row.
     */
    private function reuse_parent_context(\stdClass $scan, \stdClass $parent): void {
        $contextid = (int) ($parent->contextid ?? 0);
        $courseid = (int) ($parent->courseid ?? 0);
        if ($contextid <= 0 && $courseid <= 0) {
            return;
        }
        if ((int) $scan->contextid === $contextid && (int) $scan->courseid === $courseid) {
            return;
        }
        if ($contextid > 0) {
            $scan->contextid = $contextid;
        }
        $scan->courseid = $courseid;
        (new scan_repository())->update($scan);
    }

    /**
     * Record a real member that was extracted or named but could not be scanned.
     *
     * The row is terminal and auditable. It does not notify on its own; parent
     * aggregation sees the error and cannot publish clean.
     *
     * @param \stdClass $parent Container scan row.
     * @param string $relpath Archive-internal member path.
     * @param string $errorcode Stable error code.
     */
    public function record_member_error(\stdClass $parent, string $relpath, string $errorcode): void {
        $filename = self::member_filename($relpath);
        if ($filename === '') {
            $filename = 'member';
        }
        $filepath = self::member_filepath($relpath);
        $key = $filepath . "\0" . $filename;
        $parentid = (int) $parent->id;
        $repo = new scan_repository();
        foreach ($repo->find_children_by_parent($parentid) as $child) {
            if ((string) $child->filepath . "\0" . (string) $child->filename === $key) {
                return;
            }
        }
        $now = time();
        $row = new \stdClass();
        $row->fileid = 0;
        $row->contenthash = null;
        $row->pathnamehash = null;
        $row->contextid = (int) ($parent->contextid ?? 0);
        $row->courseid = (int) ($parent->courseid ?? 0);
        $row->component = (string) ($parent->component ?? '');
        $row->filearea = (string) ($parent->filearea ?? '');
        $row->itemid = (int) ($parent->itemid ?? 0);
        $row->filepath = $filepath;
        $row->filename = $filename;
        $row->userid = (int) ($parent->userid ?? 0);
        $row->initiatedby = (int) ($parent->initiatedby ?? 0);
        $row->submissionid = (int) ($parent->submissionid ?? 0);
        $row->source = scan_source::ARCHIVE;
        $row->parentscanid = $parentid;
        $row->archiveoutcome = archive_outcome::NONE;
        $row->sha256 = '';
        $row->filesize = 0;
        $row->mimetype = null;
        $row->status = scan_status::ERROR;
        $row->phase = scan_phase::FAILED;
        $row->vtanalysisid = null;
        $row->vtfileid = null;
        $row->malicious = null;
        $row->suspicious = null;
        $row->undetected = null;
        $row->harmless = null;
        $row->timeout = null;
        $row->totalengines = null;
        $row->errorcode = $errorcode;
        $row->enforcement = enforcement_state::NONE;
        $row->pollattempts = 0;
        $row->timelastpoll = 0;
        $row->timesubmitted = 0;
        $row->timecreated = $now;
        $row->timemodified = $now;
        $row->timecompleted = $now;
        $repo->insert($row);
    }

    /**
     * Whether the central directory names a real member with no child row.
     *
     * Reads entry metadata only. Returns null when the copy is not a readable
     * zip, so aggregation of non-archive rows is left unchanged. A nested
     * zip/mbz counts as covered when a child was queued for that member or for
     * a file extracted from it.
     *
     * @param \stored_file $file Container copy.
     * @param \stdClass[] $children Existing member rows.
     * @return bool|null True when a real entry is uncovered, false when covered, null when unknown.
     */
    public static function archive_has_uncovered_entries(\stored_file $file, array $children): ?bool {
        $path = tempnam(sys_get_temp_dir(), 'avvidx');
        if ($path === false) {
            return null;
        }
        if (!$file->copy_content_to($path)) {
            @unlink($path);
            return null;
        }
        try {
            $names = (new archive_extractor(archive_limits::from_site_config()))->list_real_entry_names($path);
            if ($names === null) {
                return null;
            }
            $keys = [];
            $paths = [];
            foreach ($children as $child) {
                $keys[(string) $child->filepath . "\0" . (string) $child->filename] = true;
                $paths[] = (string) $child->filepath;
            }
            foreach ($names as $name) {
                if (!self::entry_is_covered((string) $name, $keys, $paths)) {
                    return true;
                }
            }
            return false;
        } finally {
            @unlink($path);
        }
    }

    /**
     * Remember a member that will not be scanned, without losing its path.
     *
     * @param \stdClass $parent Container scan row.
     * @param archive_extract_result $extraction Extraction result being updated.
     * @param string $relpath Archive-internal path.
     * @param array $existing Child identity keys already recorded.
     */
    private function note_unscanned_member(
        \stdClass $parent,
        archive_extract_result $extraction,
        string $relpath,
        array &$existing
    ): void {
        if ($relpath === '') {
            return;
        }
        $extraction->skipped[] = [
            'relpath' => $relpath,
            'reason' => 'error_archive_member',
        ];
        $this->record_member_error($parent, $relpath, 'error_archive_member');
        $existing[self::member_key($relpath)] = true;
    }

    /**
     * Whether one central-directory entry already has a child row.
     *
     * @param string $entryname Raw zip entry name.
     * @param array $keys filepath + filename keys.
     * @param string[] $paths Child filepath values.
     * @return bool
     */
    private static function entry_is_covered(string $entryname, array $keys, array $paths): bool {
        if (isset($keys[self::member_key($entryname)])) {
            return true;
        }
        $base = self::member_filename($entryname);
        $lower = strtolower($base);
        if ($base === '' || (!str_ends_with($lower, '.zip') && !str_ends_with($lower, '.mbz'))) {
            return false;
        }
        $prefix = self::member_filepath($entryname . '/member');
        foreach ($paths as $path) {
            if ($path === $prefix || str_starts_with($path, $prefix)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Identity key for an archive-internal path.
     *
     * @param string $relpath Member path inside the archive.
     * @return string
     */
    public static function member_key(string $relpath): string {
        return self::member_filepath($relpath) . "\0" . self::member_filename($relpath);
    }

    /**
     * Derive a storage-safe filename for a member path.
     *
     * @param string $relpath Member path inside archive.
     * @return string PARAM_FILE-safe filename.
     */
    public static function member_filename(string $relpath): string {
        $relpath = str_replace('\\', '/', $relpath);
        $base = basename($relpath);
        $base = clean_param($base, PARAM_FILE);
        return is_string($base) ? $base : '';
    }

    /**
     * Derive a Moodle filepath prefix for audit history.
     *
     * @param string $relpath Member path inside archive.
     * @return string Moodle filepath prefix for audit.
     */
    public static function member_filepath(string $relpath): string {
        $relpath = str_replace('\\', '/', $relpath);
        $dir = dirname($relpath);
        if ($dir === '.' || $dir === '') {
            return '/archive/';
        }
        $dir = clean_param('/archive/' . trim($dir, '/') . '/', PARAM_PATH);
        return is_string($dir) ? $dir : '/archive/';
    }
}
