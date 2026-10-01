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
 * Hook callbacks for the antivirus_verdict plugin.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;


/**
 * Static hook listeners.
 */
class hook_callbacks {
    /**
     * Add Verdict to primary navigation when the user is allowed.
     * Marks the node active on every /lib/antivirus/verdict/ page.
     *
     * @param \core\hook\navigation\primary_extend $hook Hook payload.
     */
    public static function extend_primary(\core\hook\navigation\primary_extend $hook): void {
        global $PAGE;

        if (during_initial_install()) {
            return;
        }

        if (!get_config('antivirus_verdict', 'version')) {
            return;
        }

        if (!isloggedin() || isguestuser()) {
            return;
        }

        $pagecontext = !empty($PAGE->context) ? $PAGE->context : \context_system::instance();
        if (!access::can_see_navigation($pagecontext)) {
            return;
        }

        $path = !empty($PAGE->url) ? $PAGE->url->get_path() : '';
        $onverdictpage = str_contains($path, '/lib/antivirus/verdict/');
        $params = [];
        if (!$onverdictpage && !empty($PAGE->course) && $PAGE->course->id > \SITEID) {
            $coursecontext = \context_course::instance((int) $PAGE->course->id);
            if (access::has_any_plugin_capability($coursecontext)) {
                $params['courseid'] = $PAGE->course->id;
            }
        }

        $node = $hook->get_primaryview()->add(
            get_string('pluginbrand', 'antivirus_verdict'),
            teacher_access::entry_url($params),
            \navigation_node::TYPE_CUSTOM,
            null,
            'antivirus_verdict',
            new \pix_icon('icon-dark-mode', get_string('pluginbrand', 'antivirus_verdict'), 'antivirus_verdict')
        );

        if ($onverdictpage) {
            $node->make_active();
        }
    }
}
