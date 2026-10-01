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
 * Question bank file consumer.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

use antivirus_verdict\scan_source;


/**
 * Queues embedded question assets after create/update events.
 */
class question_bank_scanner {
    /** @var file_area_scanner File consumer. */
    private file_area_scanner $scanner;

    /** @var plugin_config Operational settings. */
    private plugin_config $config;

    /**
     * Internal helper.
     *
     * @param file_area_scanner $scanner File consumer.
     * @param plugin_config $config Operational settings.
     */
    public function __construct(file_area_scanner $scanner, plugin_config $config) {
        $this->scanner = $scanner;
        $this->config = $config;
    }

    /**
     * Internal helper.
     *
     * @return self
     */
    public static function from_site_config(): self {
        return new self(file_area_scanner::from_site_config(), plugin_config::from_site_config());
    }

    /**
     * Whether question bank backfill is enabled.
     *
     * @return bool
     */
    public function is_enabled(): bool {
        return $this->config->question_auto_scan_enabled();
    }

    /**
     * Queue files attached to one question in its bank context.
     *
     * @param \context $context Question bank context from the event.
     * @param int $questionid Question id.
     * @param int $userid Acting user.
     */
    public function scan_question(\context $context, int $questionid, int $userid): void {
        if (!$this->is_enabled() || $questionid <= 0) {
            return;
        }

        $fs = get_file_storage();
        $files = $fs->get_area_files($context->id, 'question', 'questiontext', $questionid, 'id', false);
        foreach ($files as $file) {
            $this->scanner->queue_file($file, scan_source::QUESTION, $userid);
        }

        // Question-type embedded media (essay attachments, ddmarker images, etc.).
        global $DB;
        $question = $DB->get_record('question', ['id' => $questionid], 'id,qtype', IGNORE_MISSING);
        if (!$question || empty($question->qtype)) {
            return;
        }
        $component = 'qtype_' . $question->qtype;
        foreach ($fs->get_area_files($context->id, $component, 'questiontext', $questionid, 'id', false) as $file) {
            $this->scanner->queue_file($file, scan_source::QUESTION, $userid);
        }
        foreach ($fs->get_area_files($context->id, $component, 'answer', $questionid, 'id', false) as $file) {
            $this->scanner->queue_file($file, scan_source::QUESTION, $userid);
        }
        foreach ($fs->get_area_files($context->id, $component, 'answerfeedback', $questionid, 'id', false) as $file) {
            $this->scanner->queue_file($file, scan_source::QUESTION, $userid);
        }
    }
}
