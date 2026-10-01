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
 * File coverage registry templatable.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\output;

use antivirus_verdict\local\file_coverage_registry;
use renderer_base;


/**
 * Exports the coverage registry (site managers and teachers with access share this UI).
 */
class coverage_page implements \renderable, \templatable {
    /**
     * Template context.
     *
     * @param renderer_base $output Renderer.
     * @return array
     */
    public function export_for_template(renderer_base $output): array {
        $rows = file_coverage_registry::rows();
        $table = [];
        foreach ($rows as $row) {
            $table[] = [
                'title' => (string) $row['title'],
                'component' => (string) $row['component'],
                'filearea' => (string) $row['filearea'],
                'mechanism' => (string) $row['mechanismlabel'],
                'state' => (string) $row['statelabel'],
                'stateclass' => $this->state_badge_class((string) $row['state']),
            ];
        }

        return [
            'pagetitle' => get_string('coverageheading', 'antivirus_verdict'),
            'pagesubtitle' => get_string('coveragesubtitle', 'antivirus_verdict'),
            'columncomponent' => get_string('coveragecolumn_component', 'antivirus_verdict'),
            'columnarea' => get_string('coveragecolumn_area', 'antivirus_verdict'),
            'columnmechanism' => get_string('coveragecolumn_mechanism', 'antivirus_verdict'),
            'columnstate' => get_string('coveragecolumn_state', 'antivirus_verdict'),
            'rows' => $table,
        ];
    }

    /**
     * Verdict status badge class for a coverage registry state.
     *
     * @param string $state Registry state key.
     * @return string
     */
    private function state_badge_class(string $state): string {
        $tone = match ($state) {
            file_coverage_registry::STATE_ACTIVE => 'clean',
            file_coverage_registry::STATE_PENDING => 'pending',
            file_coverage_registry::STATE_BLOCKED => 'error',
            default => 'notscanned',
        };
        return 'antivirus-verdict-badge antivirus-verdict-badge--' . $tone;
    }
}
