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
 * Queue a manual scan from a Moodle stored file.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

use antivirus_verdict\scan_source;


/**
 * Manual scan adapter. Copies the selected File API object into a plugin
 * file area, then queues work through the existing scan engine.
 */
class manual_scan {
    /** Plugin file area for copies of files chosen in the manual scan form. */
    public const FILEAREA = 'manual';

    /** @var scan_service Scan engine. */
    private scan_service $scanservice;

    /** @var plugin_config Operational settings. */
    private plugin_config $config;

    /** @var credential_provider Credential presence check. */
    private credential_provider $credentials;

    /**
     * Create a manual scan adapter.
     *
     * @param scan_service $scanservice Scan engine.
     * @param plugin_config $config Operational settings.
     * @param credential_provider|null $credentials Credential presence check.
     */
    public function __construct(
        scan_service $scanservice,
        plugin_config $config,
        ?credential_provider $credentials = null
    ) {
        $this->scanservice = $scanservice;
        $this->config = $config;
        $this->credentials = $credentials ?? new config_credentials();
    }

    /**
     * Production adapter using site configuration.
     *
     * @return self
     */
    public static function from_site_config(): self {
        return new self(scan_service::from_site_config(), plugin_config::from_site_config());
    }

    /**
     * Whether manual scanning is currently allowed to queue work.
     *
     * @return bool
     */
    public function can_queue(): bool {
        return $this->credentials->has_api_key();
    }

    /**
     * Language string id explaining why queueing is unavailable.
     *
     * @return string
     */
    public function unavailable_reason(): string {
        if (!$this->credentials->has_api_key()) {
            return 'scanningincomplete';
        }
        return '';
    }

    /**
     * Queue a scan from a user draft file picker item.
     *
     * @param int $draftitemid User draft item id.
     * @param \context $context Page context used to store the plugin copy.
     * @param int $userid Requesting user.
     * @return \stdClass Scan record.
     */
    public function queue_from_draft(int $draftitemid, \context $context, int $userid): \stdClass {
        $file = $this->file_from_draft($draftitemid, $userid);
        return $this->queue_stored_file($file, $context, $userid);
    }

    /**
     * Queue a scan from an existing Moodle stored file.
     *
     * @param \stored_file $file Selected Moodle file.
     * @param \context $context Page context used to store the plugin copy.
     * @param int $userid Requesting user.
     * @return \stdClass Scan record.
     */
    public function queue_stored_file(\stored_file $file, \context $context, int $userid): \stdClass {
        $this->scanservice->assert_scanable_file($file);
        if (!$this->credentials->has_api_key()) {
            throw new \moodle_exception('scanningincomplete', 'antivirus_verdict');
        }
        $stored = $this->persist_for_context($file, $context, $userid);
        // The copy is owned by the person who asked for the scan. The scan row
        // keeps that person as the initiator and the original file user, when
        // Moodle recorded one, as the content owner.
        return $this->scanservice->enqueue_file_scan(
            $stored,
            scan_source::MANUAL,
            self::real_userid((int) $file->get_userid()),
            false,
            0,
            null,
            0,
            self::real_userid($userid)
        );
    }

    /**
     * Resolve the single file in a user draft area.
     *
     * @param int $draftitemid Draft item id.
     * @param int $userid Draft owner.
     * @return \stored_file
     */
    public function file_from_draft(int $draftitemid, int $userid): \stored_file {
        if ($draftitemid <= 0 || $userid <= 0) {
            throw new \moodle_exception('error_invalidfile', 'antivirus_verdict');
        }
        $fs = get_file_storage();
        $usercontext = \context_user::instance($userid);
        $files = $fs->get_area_files($usercontext->id, 'user', 'draft', $draftitemid, 'id', false);
        if (count($files) !== 1) {
            throw new \moodle_exception('error_invalidfile', 'antivirus_verdict');
        }
        $file = reset($files);
        if (!$file || $file->is_directory()) {
            throw new \moodle_exception('error_invalidfile', 'antivirus_verdict');
        }
        return $file;
    }

    /**
     * Copy the selected file into the plugin file area in the page context.
     *
     * @param \stored_file $file Source Moodle file.
     * @param \context $context Destination context.
     * @param int $userid Owner recorded on the copy.
     * @return \stored_file
     */
    private function persist_for_context(\stored_file $file, \context $context, int $userid): \stored_file {
        $fs = get_file_storage();
        $filename = $file->get_filename();
        $itemid = (int) (microtime(true) * 1000);
        while ($fs->file_exists($context->id, 'antivirus_verdict', self::FILEAREA, $itemid, '/', $filename)) {
            $itemid++;
        }
        $record = [
            'contextid' => $context->id,
            'component' => 'antivirus_verdict',
            'filearea' => self::FILEAREA,
            'itemid' => $itemid,
            'filepath' => '/',
            'filename' => $filename,
            'userid' => $userid,
        ];
        return $fs->create_file_from_storedfile($record, $file);
    }

    /**
     * Moodle user id, or 0 when the id is missing or not a real user.
     *
     * @param int $userid Candidate user id.
     * @return int
     */
    private static function real_userid(int $userid): int {
        if ($userid <= 0 || !\core_user::is_real_user($userid, true)) {
            return 0;
        }
        return $userid;
    }
}
