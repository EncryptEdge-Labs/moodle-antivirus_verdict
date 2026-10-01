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
 * Generic File API consumer for asynchronous Verdict scans.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

use antivirus_verdict\scan_source;


/**
 * Queues stored files by pathname hash or component/file area without blocking Moodle.
 */
class file_area_scanner {
    /** @var scan_service Scan engine. */
    private scan_service $scanservice;

    /** @var plugin_config Operational settings. */
    private plugin_config $config;

    /**
     * Create a file-area scanner.
     *
     * @param scan_service $scanservice Scan engine.
     * @param plugin_config $config Operational settings.
     */
    public function __construct(scan_service $scanservice, plugin_config $config) {
        $this->scanservice = $scanservice;
        $this->config = $config;
    }

    /**
     * Production scanner using site configuration.
     *
     * @return self
     */
    public static function from_site_config(): self {
        return new self(scan_service::from_site_config(), plugin_config::from_site_config());
    }

    /**
     * Queue files referenced by assessable_uploaded pathname hashes.
     *
     * @param string[] $pathnamehashes Moodle file pathname hashes.
     * @param string $source Scan source constant.
     * @param int $userid Associated user id.
     * @return \stdClass[] Scan records.
     */
    public function scan_pathname_hashes(array $pathnamehashes, string $source, int $userid): array {
        $fs = get_file_storage();
        $scans = [];
        foreach ($pathnamehashes as $hash) {
            if (!is_string($hash) || $hash === '') {
                continue;
            }
            $file = $fs->get_file_by_hash($hash);
            if (!$file || $file->is_directory()) {
                continue;
            }
            $scans[] = $this->queue_file($file, $source, $userid);
        }
        return array_values(array_filter($scans));
    }

    /**
     * Queue all files in a component/file area for one item id.
     *
     * @param \context $context File context.
     * @param string $component File API component.
     * @param string $filearea File area.
     * @param int $itemid Item id.
     * @param string $source Scan source.
     * @param int $userid Associated user.
     * @return \stdClass[] Scan records.
     */
    public function scan_area_files(
        \context $context,
        string $component,
        string $filearea,
        int $itemid,
        string $source,
        int $userid
    ): array {
        $fs = get_file_storage();
        $files = $fs->get_area_files($context->id, $component, $filearea, $itemid, 'id', false);
        $scans = [];
        foreach ($files as $file) {
            $scans[] = $this->queue_file($file, $source, $userid);
        }
        return array_values(array_filter($scans));
    }

    /**
     * Queue one stored file, swallowing errors so callers never block Moodle.
     *
     * @param \stored_file $file Moodle file.
     * @param string $source Scan source.
     * @param int $userid File-associated Moodle user when known.
     * @param int $initiatedby Operator who started bulk/restore, when distinct.
     * @return \stdClass|null Scan record when queued.
     */
    public function queue_file(
        \stored_file $file,
        string $source,
        int $userid,
        int $initiatedby = 0
    ): ?\stdClass {
        try {
            if ($file->get_filesize() > $this->config->maxbytes) {
                return null;
            }
            return $this->scanservice->enqueue_file_scan(
                $file,
                $source,
                max(0, $userid),
                false,
                0,
                null,
                0,
                max(0, $initiatedby)
            );
        } catch (\Throwable $e) {
            debugging('antivirus_verdict file area scan failed: ' . $e->getMessage(), \DEBUG_DEVELOPER);
            return null;
        }
    }
}
