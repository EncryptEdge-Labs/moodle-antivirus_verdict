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
 * Plugin renderer for Verdict for Moodle.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\output;

use antivirus_verdict\local\page;


/**
 * HTML rendering for product chrome, history empty states, and scan detail.
 */
class renderer extends \plugin_renderer_base {
    /**
     * Open the scoped Verdict product shell.
     *
     * @param string $selected Selected nav key.
     * @param \context $context Page context.
     * @param string $crumb Current crumb label.
     * @return string
     */
    public function product_start(string $selected, \context $context, string $crumb): string {
        global $CFG;
        $nav = $this->nav_items($selected, $context);
        $system = \context_system::instance();
        $hastest = has_capability('moodle/site:config', $system);
        $canscan = \antivirus_verdict\local\teacher_access::can_use_page('manualscan', $context);
        $scanparams = $this->context_params($context);
        $scannerlive = \antivirus_verdict\local\plugin_config::from_site_config()->enabled
            && (new \antivirus_verdict\local\config_credentials())->has_api_key();
        $jsdir = $CFG->dirroot . '/lib/antivirus/verdict/javascript';
        $rev = is_readable($jsdir . '/ui.js') ? filemtime($jsdir . '/ui.js') : ($CFG->themerev ?? '');
        $scripts = \html_writer::tag('script', '', [
            'src' => (new \moodle_url('/lib/antivirus/verdict/javascript/theme-boot.js', ['rev' => $rev]))->out(false),
        ]);
        $scripts .= \html_writer::tag('script', '', [
            'src' => (new \moodle_url('/lib/antivirus/verdict/javascript/ui.js', ['rev' => $rev]))->out(false),
        ]);
        return $scripts . $this->render_from_template('antivirus_verdict/product_start', [
            'brandiconurl' => $this->image_url('icon-dark-mode', 'antivirus_verdict')->out(false),
            'brandiconlighturl' => $this->image_url('icon-light-mode', 'antivirus_verdict')->out(false),
            'brand' => get_string('brandproduct', 'antivirus_verdict'),
            'navmonitor' => get_string('navmonitor', 'antivirus_verdict'),
            'navact' => get_string('navact', 'antivirus_verdict'),
            'navtoggle' => get_string('navtoggle', 'antivirus_verdict'),
            'crumbnav' => get_string('crumbnav', 'antivirus_verdict'),
            'crumbhome' => get_string('home'),
            'crumb' => $crumb,
            'poweredby' => get_string('poweredby', 'antivirus_verdict'),
            'scannerlive' => $scannerlive,
            'themetoggle' => get_string('themetoggle', 'antivirus_verdict'),
            'themetolight' => get_string('themetolight', 'antivirus_verdict'),
            'themetodark' => get_string('themetodark', 'antivirus_verdict'),
            'hastestconnection' => $hastest,
            'testconnectionurl' => $hastest
                ? (new \moodle_url('/lib/antivirus/verdict/test_connection.php'))->out(false)
                : '',
            'testconnectionlabel' => get_string('testconnectionshort', 'antivirus_verdict'),
            'hasscanaction' => $canscan,
            'scanurl' => $canscan
                ? (new \moodle_url('/lib/antivirus/verdict/scan.php', $scanparams))->out(false)
                : '',
            'scanlabel' => get_string('manualscan', 'antivirus_verdict'),
            'monitoritems' => array_values($monitoritems = array_filter(
                $nav,
                static fn(array $item): bool => $item['group'] === 'monitor'
            )),
            'actitems' => array_values($actitems = array_filter(
                $nav,
                static fn(array $item): bool => $item['group'] === 'act'
            )),
            'hasmonitoritems' => $monitoritems !== [],
            'hasactitems' => $actitems !== [],
        ]);
    }

    /**
     * Close the product shell.
     *
     * @return string
     */
    public function product_end(): string {
        // Closing tags for product_start.mustache; not a standalone Mustache template (see qa step 6).
        return "\n            </div>\n        </div>\n    </div>\n</div>\n";
    }

    /**
     * Primary plugin section links.
     *
     * @param string $selected Selected tab key.
     * @param \context $context Page context.
     * @return string
     */
    public function plugin_tabs(string $selected, \context $context): string {
        return $this->product_start(
            $selected,
            $context,
            $this->crumb_for_selected($selected)
        );
    }

    /**
     * Landing links to implemented workflows. Not a dashboard.
     *
     * @param \context $context Page context.
     * @return string
     */
    public function launch_links(\context $context): string {
        $params = $this->context_params($context);
        $items = [];
        if (\antivirus_verdict\local\teacher_access::can_use_page('manualscan', $context)) {
            $url = new \moodle_url('/lib/antivirus/verdict/scan.php', $params);
            $items[] = \html_writer::link($url, get_string('manualscan', 'antivirus_verdict'));
        }
        if (\antivirus_verdict\local\teacher_access::can_use_page('scanhistory', $context)) {
            $url = new \moodle_url('/lib/antivirus/verdict/history.php', $params);
            $items[] = \html_writer::link($url, get_string('scanhistory', 'antivirus_verdict'));
        }
        if ($items === []) {
            return '';
        }
        return \html_writer::alist($items);
    }

    /**
     * Empty history message.
     *
     * @param bool $filtered Whether filters are active.
     * @param \moodle_url|null $scanurl Manual scan URL when the user can scan.
     * @return string
     */
    public function history_empty(bool $filtered, ?\moodle_url $scanurl = null): string {
        $message = $filtered
            ? get_string('noscansfiltered', 'antivirus_verdict')
            : get_string('noscans', 'antivirus_verdict');
        $html = \html_writer::div(s($message), 'antivirus-verdict-banner', ['role' => 'status']);
        if (!$filtered && $scanurl) {
            $html .= \html_writer::div(
                \html_writer::link($scanurl, get_string('noscans_action', 'antivirus_verdict'), [
                    'class' => 'antivirus-verdict-btn antivirus-verdict-btn-primary',
                ]),
                'antivirus-verdict-quick-actions'
            );
        }
        return $html;
    }

    /**
     * Render scan detail from a templatable.
     *
     * @param scan_detail $detail Detail view.
     * @return string
     */
    public function render_scan_detail(scan_detail $detail): string {
        return $this->render_from_template('antivirus_verdict/scan_detail', $detail->export_for_template($this));
    }

    /**
     * Render the administrator overview.
     *
     * @param overview $overview Overview view.
     * @return string
     */
    public function render_overview(overview $overview): string {
        return $this->render_from_template('antivirus_verdict/overview', $overview->export_for_template($this));
    }

    /**
     * Render the dark-shell settings page.
     *
     * @param settings_page $settings Settings view.
     * @return string
     */
    public function render_settings_page(settings_page $settings): string {
        return $this->render_from_template('antivirus_verdict/settings', $settings->export_for_template($this));
    }

    /**
     * Course-aware query params for plugin URLs.
     *
     * @param \context $context Page context.
     * @return array
     */
    private function context_params(\context $context): array {
        $params = [];
        if ($context->contextlevel === \CONTEXT_COURSE) {
            $params['courseid'] = $context->instanceid;
        } else if ($context->contextlevel === \CONTEXT_MODULE) {
            $coursecontext = $context->get_course_context(false);
            if ($coursecontext) {
                $params['courseid'] = $coursecontext->instanceid;
            }
        }
        return $params;
    }

    /**
     * Navigation items for the product sidebar.
     *
     * @param string $selected Selected key.
     * @param \context $context Page context.
     * @return array
     */
    private function nav_items(string $selected, \context $context): array {
        $params = $this->context_params($context);
        $items = [];
        $system = \context_system::instance();

        if (\antivirus_verdict\local\teacher_access::can_use_page('overview', $context)) {
            $items[] = $this->nav_item(
                'overview',
                (new \moodle_url('/lib/antivirus/verdict/index.php', $params))->out(false),
                get_string('navoverview', 'antivirus_verdict'),
                $selected,
                'monitor'
            );
        }

        if (\antivirus_verdict\local\teacher_access::can_use_page('manualscan', $context)) {
            $items[] = $this->nav_item(
                'manualscan',
                (new \moodle_url('/lib/antivirus/verdict/scan.php', $params))->out(false),
                get_string('manualscan', 'antivirus_verdict'),
                $selected,
                'act'
            );
        }
        if (\antivirus_verdict\local\teacher_access::can_use_page('bulkscan', $context)) {
            $items[] = $this->nav_item(
                'bulkscan',
                (new \moodle_url('/lib/antivirus/verdict/bulk.php', $params))->out(false),
                get_string('bulkscanheading', 'antivirus_verdict'),
                $selected,
                'act'
            );
        }
        if (\antivirus_verdict\local\teacher_access::can_use_page('scanhistory', $context)) {
            $items[] = $this->nav_item(
                'scanhistory',
                (new \moodle_url('/lib/antivirus/verdict/history.php', $params))->out(false),
                get_string('scanhistory', 'antivirus_verdict'),
                $selected,
                'monitor'
            );
        }
        if (\antivirus_verdict\local\teacher_access::can_use_page('coverage', $context)) {
            $items[] = $this->nav_item(
                'coverage',
                (new \moodle_url('/lib/antivirus/verdict/coverage.php', $params))->out(false),
                get_string('coverageheading', 'antivirus_verdict'),
                $selected,
                'monitor'
            );
        }
        if (\antivirus_verdict\local\teacher_access::can_use_page('quarantine', $context)) {
            $items[] = $this->nav_item(
                'quarantine',
                (new \moodle_url('/lib/antivirus/verdict/quarantine.php', $params))->out(false),
                get_string('quarantineheading', 'antivirus_verdict'),
                $selected,
                'monitor'
            );
        }
        if (has_capability('moodle/site:config', $system)) {
            $items[] = $this->nav_item(
                'settings',
                page::settings_url()->out(false),
                get_string('settings'),
                $selected,
                'act'
            );
        }
        return $items;
    }

    /**
     * Crumb text for a selected nav key.
     *
     * @param string $selected Selected key.
     * @return string
     */
    private function crumb_for_selected(string $selected): string {
        return match ($selected) {
            'manualscan' => get_string('manualscan', 'antivirus_verdict'),
            'scanhistory' => get_string('scanhistory', 'antivirus_verdict'),
            'coverage' => get_string('coverageheading', 'antivirus_verdict'),
            'bulkscan' => get_string('bulkscanheading', 'antivirus_verdict'),
            'quarantine' => get_string('quarantineheading', 'antivirus_verdict'),
            'settings' => get_string('settingscrumb', 'antivirus_verdict'),
            default => get_string('navoverview', 'antivirus_verdict'),
        };
    }

    /**
     * One sidebar navigation item.
     *
     * @param string $key Item key.
     * @param string $url Item URL.
     * @param string $label Visible label.
     * @param string $selected Selected key.
     * @param string $group Nav group.
     * @return array
     */
    private function nav_item(string $key, string $url, string $label, string $selected, string $group): array {
        return [
            'key' => $key,
            'url' => $url,
            'label' => $label,
            'selected' => $selected === $key,
            'group' => $group,
            'iconoverview' => $key === 'overview',
            'iconhistory' => $key === 'scanhistory',
            'iconscan' => $key === 'manualscan',
            'iconbulk' => $key === 'bulkscan',
            'iconcoverage' => $key === 'coverage',
            'iconquarantine' => $key === 'quarantine',
            'iconsettings' => $key === 'settings',
        ];
    }
}
