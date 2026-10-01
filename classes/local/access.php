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
 * Capability helpers for the antivirus_verdict plugin.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;


/**
 * Authorisation helpers. Role names are never used as the access check.
 */
class access {
    /**
     * Plugin capabilities that grant some UI access.
     *
     * @return string[]
     */
    public static function plugin_capabilities(): array {
        return [
            'antivirus/verdict:manage',
            'antivirus/verdict:scan',
            'antivirus/verdict:viewreports',
            'antivirus/verdict:viewhistory',
            'antivirus/verdict:rescan',
        ];
    }

    /**
     * Whether the user has any plugin capability in the given context.
     *
     * @param \context $context Context to check.
     * @param int|null $userid User id, or null for the current user.
     * @return bool
     */
    public static function has_any_plugin_capability(\context $context, ?int $userid = null): bool {
        return has_any_capability(self::plugin_capabilities(), $context, $userid);
    }

    /**
     * Whether the primary navigation item should be shown for this request.
     *
     * @param \context $pagecontext Current page context.
     * @return bool
     */
    public static function can_see_navigation(\context $pagecontext): bool {
        if (!isloggedin() || isguestuser()) {
            return false;
        }

        if (scan_access::can_manage_site()) {
            return true;
        }
        $system = \context_system::instance();
        if (has_capability('moodle/site:config', $system)) {
            return true;
        }
        return teacher_access::show_in_navigation();
    }

    /**
     * Require a specific capability, or any plugin capability when none is given.
     *
     * @param \context $context Context to check.
     * @param string $capability Capability name, or empty for any plugin capability.
     */
    public static function require_access(\context $context, string $capability = ''): void {
        if ($capability !== '') {
            if (has_capability($capability, $context) || has_capability('antivirus/verdict:manage', $context)) {
                return;
            }
            require_capability($capability, $context);
            return;
        }

        if (!self::has_any_plugin_capability($context)) {
            throw new \required_capability_exception(
                $context,
                'antivirus/verdict:viewreports',
                'nopermissions',
                ''
            );
        }
    }
}
