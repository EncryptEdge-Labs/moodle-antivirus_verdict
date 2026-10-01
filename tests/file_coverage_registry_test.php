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

namespace antivirus_verdict;

use antivirus_verdict\local\file_coverage_registry;
use antivirus_verdict\local\plugin_config;
use antivirus_verdict\tests\test_credentials;

/**
 * Tests for the file coverage registry.
 *
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @covers \antivirus_verdict\local\file_coverage_registry
 */
final class file_coverage_registry_test extends \advanced_testcase {
    /**
     * Registry definitions stay stable and include core commercial rows.
     */
    public function test_definitions_include_assignment_and_restore(): void {
        $this->resetAfterTest();
        $ids = array_column(file_coverage_registry::definitions(), 'id');
        $this->assertContains('assignsubmission_file', $ids);
        $this->assertContains('backup_restore', $ids);
        $this->assertContains('mod_forum_attachment', $ids);
        $this->assertContains('archive_nested', $ids);
    }

    /**
     * Indirect native-gate rows appear first in a stable order.
     */
    public function test_rows_sort_indirect_native_gate_first(): void {
        $this->resetAfterTest();
        $rows = file_coverage_registry::rows();
        $indirect = array_values(array_filter(
            $rows,
            static fn(array $row): bool => $row['mechanism'] === file_coverage_registry::MECHANISM_INDIRECT
        ));
        $this->assertCount(3, $indirect);
        $this->assertSame(
            ['h5p_package', 'mod_resource_content', 'repository_upload'],
            array_column($indirect, 'id')
        );
        $firstnon = null;
        foreach ($rows as $row) {
            if ($row['mechanism'] !== file_coverage_registry::MECHANISM_INDIRECT) {
                $firstnon = $row['id'];
                break;
            }
        }
        $this->assertNotNull($firstnon);
        $lastindirect = $indirect[2]['id'];
        $lastindex = array_search($lastindirect, array_column($rows, 'id'), true);
        $firstnonindex = array_search($firstnon, array_column($rows, 'id'), true);
        $this->assertLessThan($firstnonindex, $lastindex);
    }

    /**
     * Rows compute blocked state when credentials are missing.
     */
    public function test_rows_blocked_without_credentials(): void {
        $this->resetAfterTest();
        $config = new plugin_config(true, 1048576, true);
        $rows = file_coverage_registry::rows($config, new test_credentials(''));
        $assign = $this->row_by_id($rows, 'assignsubmission_file');
        $this->assertSame(file_coverage_registry::STATE_BLOCKED, $assign['state']);
    }

    /**
     * Internal helper.
     *
     * @param array<int,array<string,mixed>> $rows Registry rows.
     * @param string $id Row id.
     * @return array<string,mixed>
     */
    private function row_by_id(array $rows, string $id): array {
        foreach ($rows as $row) {
            if ($row['id'] === $id) {
                return $row;
            }
        }
        $this->fail('Missing registry row ' . $id);
    }
}
