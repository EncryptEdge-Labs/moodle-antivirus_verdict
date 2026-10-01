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
 * Tests for adhoc retry scheduling across Moodle 4.5–5.2.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use antivirus_verdict\local\adhoc_scan_scheduler;
use antivirus_verdict\task\process_scan;
use antivirus_verdict\tests\legacy_retry_scheduler;


/**
 * Verifies 5.1/5.2 soft retry and the 4.5/5.0 delayed-successor fallback.
 *
 * @covers \antivirus_verdict\local\adhoc_scan_scheduler
 */
final class adhoc_scan_scheduler_test extends \advanced_testcase {
    /**
     * Scan engine must not call set_soft_retry_delay itself.
     */
    public function test_scan_service_does_not_call_soft_retry_directly(): void {
        global $CFG;

        $source = file_get_contents($CFG->dirroot . '/lib/antivirus/verdict/classes/local/scan_service.php');
        $this->assertStringNotContainsString('set_soft_retry_delay', $source);
        $this->assertStringContainsString('schedule_retry', $source);
    }

    /**
     * Moodle 5.1 and 5.2 delay the running task in place without a successor.
     */
    public function test_soft_retry_delays_current_task_when_available(): void {
        global $DB;

        $this->resetAfterTest();
        if (!method_exists(\core\task\adhoc_task::class, 'set_soft_retry_delay')) {
            $this->markTestSkipped('set_soft_retry_delay is not available on this Moodle version.');
        }

        $task = new process_scan();
        $task->set_custom_data(['scanid' => 7]);
        $before = $DB->count_records('task_adhoc');

        (new adhoc_scan_scheduler())->schedule_retry($task, 45);

        $this->assertTrue($task->is_adhoc_task_delayed());
        $this->assertSame(45, $task->get_soft_retry_delay());
        $this->assertSame($before, $DB->count_records('task_adhoc'));
    }

    /**
     * Moodle 4.5 and 5.0 must insert a future process_scan row before execute() returns.
     */
    public function test_fallback_queues_delayed_successor_without_soft_retry(): void {
        global $DB;

        $this->resetAfterTest();
        $task = new process_scan();
        $task->set_custom_data(['scanid' => 12]);
        $now = time();

        (new legacy_retry_scheduler())->schedule_retry($task, 90);

        if (method_exists($task, 'is_adhoc_task_delayed')) {
            $this->assertFalse($task->is_adhoc_task_delayed());
        }

        $records = $DB->get_records('task_adhoc', [], 'id DESC');
        $this->assertNotEmpty($records);
        $queued = null;
        foreach ($records as $record) {
            if (!str_contains($record->classname, 'process_scan')) {
                continue;
            }
            $data = json_decode($record->customdata);
            if (is_object($data) && (int) $data->scanid === 12) {
                $queued = $record;
                break;
            }
        }
        $this->assertNotNull($queued);
        $this->assertGreaterThanOrEqual($now + 89, (int) $queued->nextruntime);
        $this->assertStringNotContainsString('set_soft_retry_delay', json_encode($queued));
    }

    /**
     * Moodle 4.5 and 5.0 production scheduler must insert a successor, not a test double.
     */
    public function test_production_scheduler_queues_successor_when_soft_retry_unavailable(): void {
        global $DB;

        $this->resetAfterTest();
        if (method_exists(\core\task\adhoc_task::class, 'set_soft_retry_delay')) {
            $this->markTestSkipped('This Moodle version uses native soft retry.');
        }

        $user = $this->getDataGenerator()->create_user();
        $task = new process_scan();
        $task->set_custom_data(['scanid' => 21]);
        $task->set_userid((int) $user->id);
        $now = time();
        $before = $DB->count_records_select(
            'task_adhoc',
            $DB->sql_like('classname', ':c'),
            ['c' => '%process_scan%']
        );

        (new adhoc_scan_scheduler())->schedule_retry($task, 75);

        $records = $DB->get_records('task_adhoc', [], 'id DESC');
        $queued = null;
        foreach ($records as $record) {
            if (!str_contains($record->classname, 'process_scan')) {
                continue;
            }
            $data = json_decode($record->customdata);
            if (is_object($data) && (int) $data->scanid === 21) {
                $queued = $record;
                break;
            }
        }
        $this->assertNotNull($queued);
        $this->assertGreaterThanOrEqual($now + 74, (int) $queued->nextruntime);
        $this->assertSame((int) $user->id, (int) $queued->userid);
        $this->assertStringNotContainsString('apikey', (string) $queued->customdata);
        $this->assertSame(
            $before + 1,
            $DB->count_records_select(
                'task_adhoc',
                $DB->sql_like('classname', ':c'),
                ['c' => '%process_scan%']
            )
        );
    }

    /**
     * Only a forced rescan writes the force flag into task custom data.
     */
    public function test_forced_rescan_flag_is_written_to_custom_data(): void {
        global $DB;

        $this->resetAfterTest();
        $scheduler = new adhoc_scan_scheduler();
        $scheduler->queue_scan(41);
        $scheduler->queue_scan(42, true);

        $ordinary = $this->find_queued_custom_data(41);
        $forced = $this->find_queued_custom_data(42);
        $this->assertNotNull($ordinary);
        $this->assertNotNull($forced);
        $this->assertFalse(property_exists($ordinary, 'force'));
        $this->assertTrue($forced->force);
        $this->assertSame(2, $DB->count_records_select(
            'task_adhoc',
            $DB->sql_like('classname', ':c'),
            ['c' => '%process_scan%']
        ));
    }

    /**
     * Decoded custom data of the queued process_scan task for a scan id.
     *
     * @param int $scanid Scan record id.
     * @return \stdClass|null
     */
    private function find_queued_custom_data(int $scanid): ?\stdClass {
        global $DB;

        foreach ($DB->get_records('task_adhoc', [], 'id DESC') as $record) {
            if (!str_contains($record->classname, 'process_scan')) {
                continue;
            }
            $data = json_decode((string) $record->customdata);
            if (is_object($data) && (int) $data->scanid === $scanid) {
                return $data;
            }
        }
        return null;
    }

    /**
     * A non-positive delay must not claim that a retry was scheduled.
     */
    public function test_non_positive_delay_is_rejected(): void {
        $this->expectException(\coding_exception::class);
        (new adhoc_scan_scheduler())->schedule_retry(new process_scan(), 0);
    }
}
