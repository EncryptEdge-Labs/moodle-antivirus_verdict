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
 * Formal file coverage registry for Verdict for Moodle.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;


/**
 * Describes how Moodle file areas relate to Verdict scanning.
 *
 * Does not scan files. Runtime "effective" status reflects site configuration.
 */
class file_coverage_registry {
    /** Upload-time native antivirus gate when Verdict is enabled in $CFG->antiviruses. */
    public const MECHANISM_NATIVE = 'native_gate';

    /** Event-driven backfill through {@see file_area_scanner}. */
    public const MECHANISM_EVENT = 'event_consumer';

    /** Post-restore course file sweep. */
    public const MECHANISM_RESTORE = 'restore_consumer';

    /** Administrator bulk / retrospective tool. */
    public const MECHANISM_BULK = 'bulk_tool';

    /** Archive member extraction after container analysis. */
    public const MECHANISM_ARCHIVE = 'archive_nested';

    /** Covered indirectly when another mechanism applies (for example repository upload). */
    public const MECHANISM_INDIRECT = 'indirect';

    /** Known gap — no automated scan path yet. */
    public const MECHANISM_NONE = 'not_covered';

    /** Registry row is active for this site. */
    public const STATE_ACTIVE = 'active';

    /** Supported but disabled in plugin settings. */
    public const STATE_DISABLED = 'disabled';

    /** Requires credentials or native enablement before it can run. */
    public const STATE_BLOCKED = 'blocked';

    /** Not implemented or not applicable. */
    public const STATE_PENDING = 'pending';

    /**
     * Static registry rows (component, file area, mechanism, config key).
     *
     * @return array<int,array<string,mixed>>
     */
    public static function definitions(): array {
        return [
            [
                'id' => 'assignsubmission_file',
                'component' => 'assignsubmission_file',
                'filearea' => 'submission_files',
                'mechanism' => self::MECHANISM_EVENT,
                'configkey' => 'assignscan',
                'source' => \antivirus_verdict\scan_source::ASSIGN,
            ],
            [
                'id' => 'mod_forum_attachment',
                'component' => 'mod_forum',
                'filearea' => 'attachment',
                'mechanism' => self::MECHANISM_EVENT,
                'configkey' => 'forumscan',
                'source' => \antivirus_verdict\scan_source::FORUM,
            ],
            [
                'id' => 'mod_workshop_submission',
                'component' => 'mod_workshop',
                'filearea' => 'submission_attachment',
                'mechanism' => self::MECHANISM_EVENT,
                'configkey' => 'workshopscan',
                'source' => \antivirus_verdict\scan_source::WORKSHOP,
            ],
            [
                'id' => 'mod_glossary_attachment',
                'component' => 'mod_glossary',
                'filearea' => 'attachment',
                'mechanism' => self::MECHANISM_EVENT,
                'configkey' => 'glossaryscan',
                'source' => \antivirus_verdict\scan_source::GLOSSARY,
            ],
            [
                'id' => 'mod_resource_content',
                'component' => 'mod_resource',
                'filearea' => 'content',
                'mechanism' => self::MECHANISM_INDIRECT,
                'configkey' => '',
                'source' => \antivirus_verdict\scan_source::ANTIVIRUS,
            ],
            [
                'id' => 'user_private',
                'component' => 'user',
                'filearea' => 'private',
                'mechanism' => self::MECHANISM_EVENT,
                'configkey' => 'privatescan',
                'source' => \antivirus_verdict\scan_source::PRIVATE,
            ],
            [
                'id' => 'question_bank',
                'component' => 'question',
                'filearea' => 'questiontext',
                'mechanism' => self::MECHANISM_EVENT,
                'configkey' => 'questionscan',
                'source' => \antivirus_verdict\scan_source::QUESTION,
            ],
            [
                'id' => 'backup_restore',
                'component' => 'backup',
                'filearea' => 'course',
                'mechanism' => self::MECHANISM_RESTORE,
                'configkey' => 'restorescan',
                'source' => \antivirus_verdict\scan_source::RESTORE,
            ],
            [
                'id' => 'repository_upload',
                'component' => 'repository',
                'filearea' => 'upload',
                'mechanism' => self::MECHANISM_INDIRECT,
                'configkey' => '',
                'source' => \antivirus_verdict\scan_source::ANTIVIRUS,
            ],
            [
                'id' => 'h5p_package',
                'component' => 'core_h5p',
                'filearea' => 'package',
                'mechanism' => self::MECHANISM_INDIRECT,
                'configkey' => '',
                'source' => \antivirus_verdict\scan_source::ANTIVIRUS,
            ],
            [
                'id' => 'archive_nested',
                'component' => 'antivirus_verdict',
                'filearea' => 'gate',
                'mechanism' => self::MECHANISM_ARCHIVE,
                'configkey' => 'archivescan',
                'source' => \antivirus_verdict\scan_source::ARCHIVE,
            ],
            [
                'id' => 'mod_data_content',
                'component' => 'mod_data',
                'filearea' => 'content',
                'mechanism' => self::MECHANISM_EVENT,
                'configkey' => 'datascan',
                'source' => \antivirus_verdict\scan_source::DATA,
            ],
            [
                'id' => 'mod_wiki_attachments',
                'component' => 'mod_wiki',
                'filearea' => 'attachments',
                'mechanism' => self::MECHANISM_EVENT,
                'configkey' => 'wikiscan',
                'source' => \antivirus_verdict\scan_source::WIKI,
            ],
            [
                'id' => 'mod_scorm_package',
                'component' => 'mod_scorm',
                'filearea' => 'package',
                'mechanism' => self::MECHANISM_EVENT,
                'configkey' => 'scormscan',
                'source' => \antivirus_verdict\scan_source::SCORM,
            ],
        ];
    }

    /**
     * Registry rows with computed effective state for the current site.
     *
     * @param plugin_config|null $config Operational settings.
     * @param credential_provider|null $credentials Credential presence.
     * @return array<int,array<string,mixed>>
     */
    public static function rows(
        ?plugin_config $config = null,
        ?credential_provider $credentials = null
    ): array {
        $config = $config ?? plugin_config::from_site_config();
        $credentials = $credentials ?? new config_credentials();
        $haskey = $credentials->has_api_key();
        $native = $config->enabled;

        $rows = [];
        foreach (self::definitions() as $def) {
            $state = self::STATE_PENDING;
            $mechanism = (string) $def['mechanism'];

            if ($mechanism === self::MECHANISM_NATIVE || $mechanism === self::MECHANISM_INDIRECT) {
                if ($native && $haskey) {
                    $state = self::STATE_ACTIVE;
                } else if (!$haskey) {
                    $state = self::STATE_BLOCKED;
                } else {
                    $state = self::STATE_DISABLED;
                }
            } else if ($mechanism === self::MECHANISM_NONE) {
                $state = self::STATE_PENDING;
            } else if ($mechanism === self::MECHANISM_BULK) {
                $state = $haskey ? self::STATE_ACTIVE : self::STATE_BLOCKED;
            } else {
                $configkey = (string) ($def['configkey'] ?? '');
                $enabled = $configkey !== '' && $config->consumer_enabled($configkey);
                if (!$haskey) {
                    $state = self::STATE_BLOCKED;
                } else if ($enabled) {
                    $state = self::STATE_ACTIVE;
                } else {
                    $state = self::STATE_DISABLED;
                }
            }

            $rows[] = array_merge($def, [
                'state' => $state,
                'statelabel' => get_string('coveragestate_' . $state, 'antivirus_verdict'),
                'mechanismlabel' => get_string('coveragemechanism_' . $mechanism, 'antivirus_verdict'),
                'title' => get_string('coveragerow_' . $def['id'], 'antivirus_verdict'),
            ]);
        }
        usort($rows, static function (array $a, array $b): int {
            $priority = static function (array $row): int {
                return ($row['mechanism'] ?? '') === self::MECHANISM_INDIRECT ? 0 : 1;
            };
            $pa = $priority($a);
            $pb = $priority($b);
            if ($pa !== $pb) {
                return $pa <=> $pb;
            }
            return strcmp((string) $a['id'], (string) $b['id']);
        });
        return $rows;
    }

    /**
     * Count registry rows by effective state.
     *
     * @return array<string,int>
     */
    public static function state_counts(): array {
        $counts = [
            self::STATE_ACTIVE => 0,
            self::STATE_DISABLED => 0,
            self::STATE_BLOCKED => 0,
            self::STATE_PENDING => 0,
        ];
        foreach (self::rows() as $row) {
            $state = (string) $row['state'];
            if (isset($counts[$state])) {
                $counts[$state]++;
            }
        }
        return $counts;
    }
}
