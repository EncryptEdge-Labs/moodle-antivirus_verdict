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
 * Administrator switch for which Verdict pages teachers may open.
 *
 * Settings is never included. Site managers are not limited by these switches.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

/**
 * Reads the teacher-access settings and applies them to navigation and pages.
 */
class teacher_access {
    /**
     * Pages an administrator may show to teachers, in navigation order.
     *
     * Settings is intentionally absent.
     *
     * @var array<string,array{script:string,config:string,default:int,capability:string,label:string}>
     */
    private const PAGES = [
        'overview' => [
            'script' => 'index.php',
            'config' => 'teacherpageoverview',
            'default' => 1,
            'capability' => '',
            'label' => 'navoverview',
        ],
        'manualscan' => [
            'script' => 'scan.php',
            'config' => 'teacherpagescan',
            'default' => 1,
            'capability' => 'antivirus/verdict:scan',
            'label' => 'manualscan',
        ],
        'bulkscan' => [
            'script' => 'bulk.php',
            'config' => 'teacherpagebulk',
            'default' => 1,
            'capability' => 'antivirus/verdict:scan',
            'label' => 'bulkscanheading',
        ],
        'scanhistory' => [
            'script' => 'history.php',
            'config' => 'teacherpagehistory',
            'default' => 1,
            'capability' => 'antivirus/verdict:viewhistory',
            'label' => 'scanhistory',
        ],
        'coverage' => [
            'script' => 'coverage.php',
            'config' => 'teacherpagecoverage',
            'default' => 0,
            'capability' => 'antivirus/verdict:viewreports',
            'label' => 'coverageheading',
        ],
        'quarantine' => [
            'script' => 'quarantine.php',
            'config' => 'teacherpagequarantine',
            'default' => 1,
            'capability' => 'antivirus/verdict:viewhistory',
            'label' => 'quarantineheading',
        ],
    ];

    /**
     * Whether administrators have enabled Verdict for teachers.
     *
     * @return bool
     */
    public static function enabled(): bool {
        return self::flag('teacheraccess', 0);
    }

    /**
     * Whether this page is selected for teachers.
     *
     * The master switch is not applied here, so the settings form can keep
     * the saved choices while they are hidden.
     *
     * @param string $page Page key.
     * @return bool
     */
    public static function page_enabled(string $page): bool {
        if (!isset(self::PAGES[$page])) {
            return false;
        }
        return self::flag(self::PAGES[$page]['config'], self::PAGES[$page]['default']);
    }

    /**
     * Whether this user may open the page.
     *
     * Site managers always may. Teachers may when the master switch is on,
     * the page is selected, and they hold that page's course capability.
     *
     * @param string $page Page key.
     * @param int|null $userid User id, or null for the current user.
     * @return bool
     */
    public static function allows(string $page, ?int $userid = null): bool {
        if (!isset(self::PAGES[$page])) {
            return false;
        }
        if (scan_access::can_manage_site($userid)) {
            return true;
        }
        if (!self::enabled() || !self::page_enabled($page)) {
            return false;
        }
        if (!scan_access::has_teaching_access($userid)) {
            return false;
        }
        $capability = self::PAGES[$page]['capability'];
        if ($capability === '') {
            return true;
        }
        return scan_access::has_capability_in_any_course($capability, $userid);
    }

    /**
     * Whether the page may appear in navigation, actions, and overview links.
     *
     * @param string $page Page key.
     * @param \context $context Page context for course-level capabilities.
     * @param int|null $userid User id, or null for the current user.
     * @return bool
     */
    public static function can_use_page(string $page, \context $context, ?int $userid = null): bool {
        if (!self::allows($page, $userid)) {
            return false;
        }
        if (scan_access::can_manage_site($userid)) {
            return true;
        }
        return match ($page) {
            'overview' => true,
            'manualscan', 'bulkscan' => scan_access::can_scan($context, $userid),
            'scanhistory' => scan_access::can_view_history_page($context, $userid),
            'coverage' => scan_access::has_capability_in_any_course('antivirus/verdict:viewreports', $userid),
            'quarantine' => scan_access::can_view_quarantine($userid),
            default => false,
        };
    }

    /**
     * Whether the Moodle navigation item should appear for a teacher.
     *
     * @param int|null $userid User id, or null for the current user.
     * @return bool
     */
    public static function show_in_navigation(?int $userid = null): bool {
        if (!self::enabled() || !scan_access::has_teaching_access($userid)) {
            return false;
        }
        foreach (array_keys(self::PAGES) as $page) {
            if (self::allows($page, $userid)) {
                return true;
            }
        }
        return false;
    }

    /**
     * First page this user is allowed to open.
     *
     * @param array $params Optional query parameters.
     * @return \moodle_url
     */
    public static function entry_url(array $params = []): \moodle_url {
        if (!scan_access::can_manage_site()) {
            foreach (self::PAGES as $page => $meta) {
                if (self::allows($page)) {
                    return new \moodle_url('/lib/antivirus/verdict/' . $meta['script'], $params);
                }
            }
        }
        return new \moodle_url('/lib/antivirus/verdict/index.php', $params);
    }

    /**
     * Stop a teacher from opening a page the administrator has not enabled.
     *
     * @param string $page Page key.
     */
    public static function require_page(string $page): void {
        if (self::allows($page)) {
            return;
        }
        $capability = 'antivirus/verdict:viewhistory';
        if (isset(self::PAGES[$page]['capability']) && self::PAGES[$page]['capability'] !== '') {
            $capability = self::PAGES[$page]['capability'];
        }
        throw new \required_capability_exception(
            \context_system::instance(),
            $capability,
            'nopermissions',
            ''
        );
    }

    /**
     * Gate scan detail for teachers: manual scan owners may open their row without history access.
     *
     * @param \stdClass $scan Scan row.
     */
    public static function require_scan_detail(\stdClass $scan): void {
        global $USER;

        if (scan_access::can_manage_site()) {
            return;
        }
        if (
            scan_access::can_view_own_manual_scan($scan, (int) $USER->id)
            && self::allows('manualscan')
        ) {
            return;
        }
        self::require_page('scanhistory');
    }

    /**
     * Apply the page switch for a plugin script. Unknown scripts are ignored.
     *
     * @param string $script Plugin-relative script name.
     */
    public static function require_script(string $script): void {
        foreach (self::PAGES as $page => $meta) {
            if ($meta['script'] === $script) {
                self::require_page($page);
                return;
            }
        }
    }

    /**
     * Config keys for the per-page switches.
     *
     * @return string[]
     */
    public static function config_names(): array {
        $names = [];
        foreach (self::PAGES as $meta) {
            $names[] = $meta['config'];
        }
        return $names;
    }

    /**
     * Checkbox rows for the settings screen.
     *
     * @return array<int,array{name:string,label:string,checked:bool}>
     */
    public static function page_choices(): array {
        $choices = [];
        foreach (self::PAGES as $page => $meta) {
            $choices[] = [
                'name' => $meta['config'],
                'label' => get_string($meta['label'], 'antivirus_verdict'),
                'checked' => self::page_enabled($page),
            ];
        }
        return $choices;
    }

    /**
     * Read a boolean plugin config value, using the default when it is unset.
     *
     * @param string $name Config name.
     * @param int $default 1 or 0.
     * @return bool
     */
    private static function flag(string $name, int $default): bool {
        $value = get_config('antivirus_verdict', $name);
        if ($value === false) {
            return $default === 1;
        }
        return (int) $value === 1;
    }
}
