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
 * Shared page bootstrap for Verdict for Moodle.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;


/**
 * Sets up plugin pages with login, context, and capability checks.
 */
class page {
    /**
     * Bootstrap a plugin page and return the active context.
     *
     * Site-level pages (no course id) require antivirus/verdict:manage
     * unless the user already has a plugin capability at system context.
     * Course-level pages require any plugin capability in that course.
     *
     * @param string $script Plugin-relative script name, for example index.php.
     * @param string $titlekey Language string id for the page title.
     * @param string $capability Capability to require, or empty for any plugin capability.
     * @return \context
     */
    public static function setup(string $script, string $titlekey, string $capability = ''): \context {
        $context = self::prepare($script, $titlekey);

        $courseid = $context->contextlevel === \CONTEXT_COURSE ? $context->instanceid : 0;
        if ($courseid) {
            access::require_access($context, $capability);
            teacher_access::require_script($script);
            return $context;
        }

        if ($capability === '' || $capability === 'antivirus/verdict:manage') {
            if ($capability === 'antivirus/verdict:manage') {
                require_capability('antivirus/verdict:manage', $context);
                teacher_access::require_script($script);
                return $context;
            }
            if (!self::may_open_unscoped_page($context)) {
                throw new \required_capability_exception(
                    $context,
                    'antivirus/verdict:manage',
                    'nopermissions',
                    ''
                );
            }
            teacher_access::require_script($script);
            return $context;
        }

        if (
            !has_capability($capability, $context)
            && !has_capability('antivirus/verdict:manage', $context)
            && !scan_access::has_capability_in_any_course($capability)
        ) {
            require_capability($capability, $context);
        }

        teacher_access::require_script($script);
        return $context;
    }

    /**
     * Whether a site-level Verdict page may open for this user.
     *
     * @param \context $context System context.
     * @return bool
     */
    private static function may_open_unscoped_page(\context $context): bool {
        return has_capability('antivirus/verdict:manage', $context)
            || access::has_any_plugin_capability($context)
            || scan_access::has_teaching_access();
    }

    /**
     * Login, URL, and context without a capability check.
     *
     * Always uses a course or system context so assignment module chrome is
     * not injected into Verdict pages.
     *
     * @param string $script Plugin-relative script name.
     * @param string $titlekey Language string id for the page title.
     * @return \context
     */
    public static function prepare(string $script, string $titlekey): \context {
        global $PAGE;

        $courseid = optional_param('courseid', 0, \PARAM_INT);
        $params = [];
        if ($courseid) {
            $params['courseid'] = $courseid;
        }

        $url = new \moodle_url('/lib/antivirus/verdict/' . $script, $params);
        $PAGE->set_url($url);

        if ($courseid) {
            $course = get_course($courseid);
            require_login($course);
            $context = \context_course::instance($courseid);
        } else {
            require_login();
            $context = \context_system::instance();
        }

        $PAGE->set_context($context);
        self::apply_chrome($titlekey);

        $brand = get_string('pluginbrand', 'antivirus_verdict');
        $PAGE->navbar->add($brand, new \moodle_url('/lib/antivirus/verdict/index.php', $params));

        return $context;
    }

    /**
     * Apply the Verdict application page chrome.
     *
     * Uses the report layout so Boost does not apply the standard 830px
     * limited-width content column. Styles remain scoped to Verdict pages.
     * Keeps the Moodle primary "Verdict" tab active on every plugin page.
     *
     * @param string $titlekey Language string id for the page title.
     * @return void
     */
    public static function apply_chrome(string $titlekey): void {
        global $PAGE, $CFG;

        $pagetitle = get_string($titlekey, 'antivirus_verdict');
        $brand = get_string('pluginbrand', 'antivirus_verdict');
        $PAGE->set_pagelayout('report');
        $PAGE->add_body_class('antivirus-verdict-app');
        $PAGE->set_title($pagetitle . ': ' . $brand);
        $PAGE->set_heading($brand);
        $PAGE->set_secondary_navigation(false);
        if (isset($PAGE->activityheader) && method_exists($PAGE->activityheader, 'disable')) {
            $PAGE->activityheader->disable();
        }
        // Antivirus plugins under lib/antivirus/ are not theme-aggregated like mod_* plugins;
        // explicit loading keeps styles scoped to Verdict application pages only.
        $cssfile = $CFG->dirroot . '/lib/antivirus/verdict/styles.css';
        $PAGE->requires->css(new \moodle_url('/lib/antivirus/verdict/styles.css', [
            'rev' => is_readable($cssfile) ? filemtime($cssfile) : ($CFG->themerev ?? ''),
        ]));
        $PAGE->requires->js(new \moodle_url('/lib/antivirus/verdict/javascript/theme-boot.js'), true);
        $PAGE->requires->js(new \moodle_url('/lib/antivirus/verdict/javascript/ui.js'));
        $PAGE->set_primary_active_tab('antivirus_verdict');
    }

    /**
     * Apply Verdict chrome at site context without course-page navigation.
     *
     * Callers must not use require_login($course) first. That binds $PAGE to
     * the course format and rewrites Moodle course-index links onto the current
     * plugin URL. Course ids remain valid for capability and display data.
     *
     * @param string $titlekey Language string id for the page title.
     * @return void
     */
    public static function apply_site_application_chrome(string $titlekey): void {
        global $PAGE, $SITE;

        $PAGE->set_context(\context_system::instance());
        if (!empty($SITE->id)) {
            $PAGE->set_course($SITE);
        }
        self::apply_chrome($titlekey);
    }

    /**
     * Dark-shell settings URL. Native admin/settings.php remains as Moodle fallback.
     *
     * @return \moodle_url
     */
    public static function settings_url(): \moodle_url {
        return new \moodle_url('/lib/antivirus/verdict/configure.php');
    }

    /**
     * Moodle's native Antivirus enable/order page.
     *
     * @return \moodle_url
     */
    public static function antivirus_manage_url(): \moodle_url {
        return new \moodle_url('/admin/settings.php', ['section' => 'manageantiviruses']);
    }
}
