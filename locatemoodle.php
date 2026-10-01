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
 * Locate Moodle config.php for plugin entry pages.
 *
 * Prefer the native lib/antivirus/verdict relative path. When PHP resolves
 * __DIR__ through a Windows junction to a workspace outside Moodle, fall back
 * to the web document root so the in-app pages still bootstrap.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

// phpcs:disable moodle.Files.MoodleInternal,moodle.Files.RequireLogin

if (is_readable(__DIR__ . '/../../../config.php')) {
    require_once(__DIR__ . '/../../../config.php');
    return;
}

if (!empty($_SERVER['DOCUMENT_ROOT'])) {
    $fromdocroot = rtrim((string) $_SERVER['DOCUMENT_ROOT'], '/\\') . '/config.php';
    if (is_readable($fromdocroot)) {
        require_once($fromdocroot);
        return;
    }
}

fwrite(STDERR, 'Moodle config.php was not found.');
exit(1);
