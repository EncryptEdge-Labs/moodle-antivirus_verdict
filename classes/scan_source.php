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
 * Scan request sources (consumers of the scanning domain).
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;


/**
 * Identifies which Moodle integration requested a scan.
 *
 * Additional file-area consumers should add a source constant rather than
 * changing the VirusTotal client.
 */
class scan_source {
    /** Manual scan requested from the plugin UI. */
    public const MANUAL = 'manual';

    /** Automatic or operator scan of an assignment submission. */
    public const ASSIGN = 'assign';

    /** Native Moodle Antivirus upload gate. */
    public const ANTIVIRUS = 'antivirus';

    /** Forum attachment backfill. */
    public const FORUM = 'forum';

    /** Workshop submission attachment backfill. */
    public const WORKSHOP = 'workshop';

    /** Glossary entry attachment backfill. */
    public const GLOSSARY = 'glossary';

    /** Course restore materialisation sweep. */
    public const RESTORE = 'restore';

    /** Administrator bulk or retrospective scan. */
    public const BULK = 'bulk';

    /** Member file extracted from an archive container. */
    public const ARCHIVE = 'archive';

    /** Database activity record content files. */
    public const DATA = 'data';

    /** Wiki page attachments. */
    public const WIKI = 'wiki';

    /** SCORM package files. */
    public const SCORM = 'scorm';

    /** Question bank embedded assets. */
    public const QUESTION = 'question';

    /** User private files area. */
    public const PRIVATE = 'private';

    /**
     * Return all known source values.
     *
     * @return string[]
     */
    public static function all(): array {
        return [
            self::MANUAL,
            self::ASSIGN,
            self::ANTIVIRUS,
            self::FORUM,
            self::WORKSHOP,
            self::GLOSSARY,
            self::RESTORE,
            self::BULK,
            self::ARCHIVE,
            self::DATA,
            self::WIKI,
            self::SCORM,
            self::QUESTION,
            self::PRIVATE,
        ];
    }

    /**
     * Whether the value is a known scan source.
     *
     * @param string $source Candidate source.
     * @return bool
     */
    public static function is_valid(string $source): bool {
        return in_array($source, self::all(), true);
    }
}
