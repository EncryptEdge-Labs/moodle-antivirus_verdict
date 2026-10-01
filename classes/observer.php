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
 * Event observers for the antivirus_verdict plugin.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\assignment_scanner;
use antivirus_verdict\local\assignment_submission_linker;
use antivirus_verdict\local\file_area_scanner;
use antivirus_verdict\local\plugin_config;
use antivirus_verdict\local\question_bank_scanner;
use antivirus_verdict\local\restore_course_scanner;
use antivirus_verdict\scan_source;


/**
 * Thin Moodle event callbacks. Business logic lives in dedicated services.
 */
class observer {
    /**
     * Queue assignment submission files after a learner submits for grading.
     *
     * Must not throw. Assignment submission must continue if scanning fails.
     *
     * @param \core\event\base $event Moodle event.
     */
    public static function assessable_submitted(\core\event\base $event): void {
        if (!$event instanceof \mod_assign\event\assessable_submitted) {
            return;
        }
        try {
            assignment_scanner::from_site_config()->scan_from_event($event);
        } catch (\Throwable $e) {
            debugging('antivirus_verdict assignment scanner failed: ' . $e->getMessage(), \DEBUG_DEVELOPER);
        }
        try {
            assignment_submission_linker::from_site_config()->link_from_event($event);
        } catch (\Throwable $e) {
            debugging('antivirus_verdict assignment linker failed: ' . $e->getMessage(), \DEBUG_DEVELOPER);
        }
    }

    /**
     * Queue forum attachments after content is uploaded.
     *
     * @param \core\event\base $event Moodle event.
     */
    public static function forum_assessable_uploaded(\core\event\base $event): void {
        self::assessable_uploaded_consumer($event, scan_source::FORUM, 'forum_auto_scan_enabled');
    }

    /**
     * Queue workshop submission attachments after upload.
     *
     * @param \core\event\base $event Moodle event.
     */
    public static function workshop_assessable_uploaded(\core\event\base $event): void {
        self::assessable_uploaded_consumer($event, scan_source::WORKSHOP, 'workshop_auto_scan_enabled');
    }

    /**
     * Queue glossary entry attachments when an entry is created.
     *
     * @param \core\event\base $event Moodle event.
     */
    public static function glossary_entry_created(\core\event\base $event): void {
        try {
            if (!$event instanceof \mod_glossary\event\entry_created) {
                return;
            }
            $config = plugin_config::from_site_config();
            if (!$config->glossary_auto_scan_enabled()) {
                return;
            }
            $context = $event->get_context();
            if (!$context instanceof \context_module) {
                return;
            }
            file_area_scanner::from_site_config()->scan_area_files(
                $context,
                'mod_glossary',
                'attachment',
                (int) $event->objectid,
                scan_source::GLOSSARY,
                (int) $event->userid
            );
        } catch (\Throwable $e) {
            debugging('antivirus_verdict glossary observer failed: ' . $e->getMessage(), \DEBUG_DEVELOPER);
        }
    }

    /**
     * Queue a restore sweep after a course is restored.
     *
     * @param \core\event\base $event Moodle event.
     */
    /**
     * Queue database activity files when a record is created.
     *
     * @param \core\event\base $event Moodle event.
     */
    public static function data_record_created(\core\event\base $event): void {
        try {
            if (!$event instanceof \mod_data\event\record_created) {
                return;
            }
            $config = plugin_config::from_site_config();
            if (!$config->data_auto_scan_enabled()) {
                return;
            }
            $context = $event->get_context();
            if (!$context instanceof \context_module) {
                return;
            }
            file_area_scanner::from_site_config()->scan_area_files(
                $context,
                'mod_data',
                'content',
                (int) $event->objectid,
                scan_source::DATA,
                (int) $event->userid
            );
        } catch (\Throwable $e) {
            debugging('antivirus_verdict data observer failed: ' . $e->getMessage(), \DEBUG_DEVELOPER);
        }
    }

    /**
     * Queue database activity files when a record is updated.
     *
     * @param \core\event\base $event Moodle event.
     */
    public static function data_record_updated(\core\event\base $event): void {
        try {
            if (!$event instanceof \mod_data\event\record_updated) {
                return;
            }
            $config = plugin_config::from_site_config();
            if (!$config->data_auto_scan_enabled()) {
                return;
            }
            $context = $event->get_context();
            if (!$context instanceof \context_module) {
                return;
            }
            file_area_scanner::from_site_config()->scan_area_files(
                $context,
                'mod_data',
                'content',
                (int) $event->objectid,
                scan_source::DATA,
                (int) $event->userid
            );
        } catch (\Throwable $e) {
            debugging('antivirus_verdict data observer failed: ' . $e->getMessage(), \DEBUG_DEVELOPER);
        }
    }

    /**
     * Queue wiki attachments after a page is created.
     *
     * @param \core\event\base $event Moodle event.
     */
    public static function wiki_page_created(\core\event\base $event): void {
        self::wiki_page_changed($event, \mod_wiki\event\page_created::class);
    }

    /**
     * Queue wiki attachments after a page is updated.
     *
     * @param \core\event\base $event Moodle event.
     */
    public static function wiki_page_updated(\core\event\base $event): void {
        self::wiki_page_changed($event, \mod_wiki\event\page_updated::class);
    }

    /**
     * Queue SCORM package files when the activity is created or updated.
     *
     * @param \core\event\base $event Moodle event.
     */
    public static function course_module_scorm_changed(\core\event\base $event): void {
        try {
            if (
                !$event instanceof \core\event\course_module_created
                && !$event instanceof \core\event\course_module_updated
            ) {
                return;
            }
            if (($event->other['modulename'] ?? '') !== 'scorm') {
                return;
            }
            $config = plugin_config::from_site_config();
            if (!$config->scorm_auto_scan_enabled()) {
                return;
            }
            $context = $event->get_context();
            if (!$context instanceof \context_module) {
                return;
            }
            file_area_scanner::from_site_config()->scan_area_files(
                $context,
                'mod_scorm',
                'package',
                0,
                scan_source::SCORM,
                (int) $event->userid
            );
        } catch (\Throwable $e) {
            debugging('antivirus_verdict scorm observer failed: ' . $e->getMessage(), \DEBUG_DEVELOPER);
        }
    }

    /**
     * Queue question bank assets after create.
     *
     * @param \core\event\base $event Moodle event.
     */
    public static function question_created(\core\event\base $event): void {
        self::question_changed($event, \core\event\question_created::class);
    }

    /**
     * Queue question bank assets after update.
     *
     * @param \core\event\base $event Moodle event.
     */
    public static function question_updated(\core\event\base $event): void {
        self::question_changed($event, \core\event\question_updated::class);
    }

    /**
     * Queue retrospective scan after a course restore completes.
     *
     * @param \core\event\base $event Moodle event.
     */
    public static function course_restored(\core\event\base $event): void {
        try {
            if (!$event instanceof \core\event\course_restored) {
                return;
            }
            restore_course_scanner::from_site_config()->queue_course(
                (int) $event->courseid,
                (int) $event->userid
            );
        } catch (\Throwable $e) {
            debugging('antivirus_verdict restore observer failed: ' . $e->getMessage(), \DEBUG_DEVELOPER);
        }
    }

    /**
     * Shared wiki page create/update handler.
     *
     * @param \core\event\base $event Moodle event.
     * @param class-string $expectedclass Expected event class.
     */
    private static function wiki_page_changed(\core\event\base $event, string $expectedclass): void {
        global $DB;
        try {
            if (!$event instanceof $expectedclass) {
                return;
            }
            $config = plugin_config::from_site_config();
            if (!$config->wiki_auto_scan_enabled()) {
                return;
            }
            $page = $DB->get_record('wiki_pages', ['id' => (int) $event->objectid], 'id, subwikiid', IGNORE_MISSING);
            if (!$page) {
                return;
            }
            $context = $event->get_context();
            if (!$context instanceof \context_module) {
                return;
            }
            file_area_scanner::from_site_config()->scan_area_files(
                $context,
                'mod_wiki',
                'attachments',
                (int) $page->subwikiid,
                scan_source::WIKI,
                (int) $event->userid
            );
        } catch (\Throwable $e) {
            debugging('antivirus_verdict wiki observer failed: ' . $e->getMessage(), \DEBUG_DEVELOPER);
        }
    }

    /**
     * Shared question create/update handler.
     *
     * @param \core\event\base $event Moodle event.
     * @param class-string $expectedclass Expected event class.
     */
    private static function question_changed(\core\event\base $event, string $expectedclass): void {
        try {
            if (!$event instanceof $expectedclass) {
                return;
            }
            question_bank_scanner::from_site_config()->scan_question(
                $event->get_context(),
                (int) $event->objectid,
                (int) $event->userid
            );
        } catch (\Throwable $e) {
            debugging('antivirus_verdict question observer failed: ' . $e->getMessage(), \DEBUG_DEVELOPER);
        }
    }

    /**
     * Shared handler for core assessable_uploaded events with pathname hashes.
     *
     * @param \core\event\base $event Moodle event.
     * @param string $source Scan source constant.
     * @param string $configmethod plugin_config method name returning bool.
     */
    private static function assessable_uploaded_consumer(
        \core\event\base $event,
        string $source,
        string $configmethod
    ): void {
        try {
            if (!$event instanceof \core\event\assessable_uploaded) {
                return;
            }
            $config = plugin_config::from_site_config();
            if (!method_exists($config, $configmethod) || !$config->{$configmethod}()) {
                return;
            }
            $hashes = $event->other['pathnamehashes'] ?? [];
            if (!is_array($hashes) || $hashes === []) {
                return;
            }
            file_area_scanner::from_site_config()->scan_pathname_hashes(
                $hashes,
                $source,
                (int) $event->userid
            );
        } catch (\Throwable $e) {
            debugging('antivirus_verdict assessable observer failed: ' . $e->getMessage(), \DEBUG_DEVELOPER);
        }
    }
}
