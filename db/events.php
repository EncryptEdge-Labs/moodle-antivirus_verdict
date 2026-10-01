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




defined('MOODLE_INTERNAL') || die();

$observers = [
    [
        'eventname' => '\mod_assign\event\assessable_submitted',
        'callback' => '\antivirus_verdict\observer::assessable_submitted',
    ],
    [
        'eventname' => '\mod_forum\event\assessable_uploaded',
        'callback' => '\antivirus_verdict\observer::forum_assessable_uploaded',
    ],
    [
        'eventname' => '\mod_workshop\event\assessable_uploaded',
        'callback' => '\antivirus_verdict\observer::workshop_assessable_uploaded',
    ],
    [
        'eventname' => '\mod_glossary\event\entry_created',
        'callback' => '\antivirus_verdict\observer::glossary_entry_created',
    ],
    [
        'eventname' => '\mod_data\event\record_created',
        'callback' => '\antivirus_verdict\observer::data_record_created',
    ],
    [
        'eventname' => '\mod_data\event\record_updated',
        'callback' => '\antivirus_verdict\observer::data_record_updated',
    ],
    [
        'eventname' => '\mod_wiki\event\page_created',
        'callback' => '\antivirus_verdict\observer::wiki_page_created',
    ],
    [
        'eventname' => '\mod_wiki\event\page_updated',
        'callback' => '\antivirus_verdict\observer::wiki_page_updated',
    ],
    [
        'eventname' => '\core\event\course_module_created',
        'callback' => '\antivirus_verdict\observer::course_module_scorm_changed',
    ],
    [
        'eventname' => '\core\event\course_module_updated',
        'callback' => '\antivirus_verdict\observer::course_module_scorm_changed',
    ],
    [
        'eventname' => '\core\event\question_created',
        'callback' => '\antivirus_verdict\observer::question_created',
    ],
    [
        'eventname' => '\core\event\question_updated',
        'callback' => '\antivirus_verdict\observer::question_updated',
    ],
    [
        'eventname' => '\core\event\course_restored',
        'callback' => '\antivirus_verdict\observer::course_restored',
    ],
];
