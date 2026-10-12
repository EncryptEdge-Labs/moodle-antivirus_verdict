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
 * Behat entity generator for Verdict scan fixtures.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

/**
 * Supports: Given the following "antivirus_verdict > Scans" exist:
 */
class behat_antivirus_verdict_generator extends behat_generator_base {
    /**
     * Behat creatable entities for scan fixtures.
     *
     * @return array
     */
    protected function get_creatable_entities(): array {
        return [
            'Scans' => [
                'singular' => 'Scan',
                'datagenerator' => 'scan',
                'required' => ['filename'],
            ],
        ];
    }

    /**
     * Insert one scan row via the PHPUnit data generator.
     *
     * @param array $data Generator fields after switchids.
     * @return \stdClass Scan row.
     */
    public function process_scan(array $data): \stdClass {
        /** @var antivirus_verdict_generator $gen */
        $gen = $this->componentdatagenerator;
        return $gen->create_scan($data);
    }
}
