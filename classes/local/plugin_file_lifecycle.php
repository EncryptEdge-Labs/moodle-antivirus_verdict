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
 * Lifecycle for plugin-owned manual scan file copies.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;


/**
 * Deletes only plugin-owned File API copies. Never Assignment or other files.
 */
class plugin_file_lifecycle {
    /** File area for copies created at the antivirus gate. */
    public const GATE_FILEAREA = 'gate';

    /** File API component that owns every plugin copy. */
    public const COMPONENT = 'antivirus_verdict';

    /**
     * Plugin-owned file areas that may hold copies of user file content.
     *
     * Both areas store real uploaded bytes and record the owning user, so
     * privacy discovery, export, deletion, and uninstall must all cover them.
     *
     * @return string[]
     */
    public static function copy_fileareas(): array {
        return [manual_scan::FILEAREA, self::GATE_FILEAREA];
    }

    /**
     * Whether the stored file belongs to this plugin's copy areas.
     *
     * @param \stored_file $file Moodle file.
     * @return bool
     */
    public static function is_plugin_copy(\stored_file $file): bool {
        if ($file->get_component() !== self::COMPONENT) {
            return false;
        }
        return in_array($file->get_filearea(), self::copy_fileareas(), true);
    }

    /**
     * Delete the plugin-owned copy referenced by a scan, if one exists.
     *
     * Missing files and files owned by other components are ignored.
     *
     * @param \stdClass $record Scan row.
     */
    public static function delete_copy_for_scan(\stdClass $record): void {
        self::delete_copy_for_scan_if_unreferenced($record);
    }

    /**
     * Delete a plugin-owned copy when no other scan row still references it.
     *
     * @param \stdClass $record Scan row being purged.
     * @param scan_repository|null $repository Optional repository for tests.
     * @return bool True when a plugin copy was deleted.
     */
    public static function delete_copy_for_scan_if_unreferenced(
        \stdClass $record,
        ?scan_repository $repository = null
    ): bool {
        $file = self::resolve_plugin_copy($record);
        if (!$file) {
            return false;
        }
        $repository = $repository ?? new scan_repository();
        $references = $repository->count_references_to_file(
            (int) ($record->fileid ?? 0),
            (string) ($record->pathnamehash ?? ''),
            (int) ($record->id ?? 0)
        );
        if ($references > 0) {
            return false;
        }
        $file->delete();
        return true;
    }

    /**
     * Resolve a plugin-owned copy for the scan, or null.
     *
     * @param \stdClass $record Scan row.
     * @return \stored_file|null
     */
    public static function resolve_plugin_copy(\stdClass $record): ?\stored_file {
        $fs = get_file_storage();
        $file = null;
        if (!empty($record->fileid)) {
            $file = $fs->get_file_by_id((int) $record->fileid);
        }
        if (!$file && !empty($record->pathnamehash)) {
            $file = $fs->get_file_by_hash((string) $record->pathnamehash);
        }
        if (!$file || !self::is_plugin_copy($file)) {
            return null;
        }
        return $file;
    }

    /**
     * Store a filesystem path as a plugin-owned gate copy.
     *
     * @param string $path Readable filesystem path.
     * @param string $filename Destination filename.
     * @param \context $context Destination context.
     * @param int $userid Owner recorded on the copy.
     * @return \stored_file
     */
    public static function store_path_copy(
        string $path,
        string $filename,
        \context $context,
        int $userid
    ): \stored_file {
        if ($path === '' || !is_file($path) || !is_readable($path)) {
            throw new \invalid_parameter_exception('error_invalidfile');
        }
        $filename = basename(str_replace(["\0", '\\'], '', $filename));
        if ($filename === '' || $filename === '.' || $filename === '..') {
            $filename = 'file';
        }
        $fs = get_file_storage();
        $itemid = (int) (microtime(true) * 1000);
        while ($fs->file_exists($context->id, 'antivirus_verdict', self::GATE_FILEAREA, $itemid, '/', $filename)) {
            $itemid++;
        }
        return $fs->create_file_from_pathname([
            'contextid' => $context->id,
            'component' => 'antivirus_verdict',
            'filearea' => self::GATE_FILEAREA,
            'itemid' => $itemid,
            'filepath' => '/',
            'filename' => $filename,
            'userid' => max(0, $userid),
        ], $path);
    }
}
