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

use antivirus_verdict\archive_outcome;
use antivirus_verdict\local\archive_orchestrator;
use antivirus_verdict\local\scan_repository;

/**
 * Tests for archive orchestration.
 *
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @covers \antivirus_verdict\local\archive_orchestrator
 */
final class archive_orchestrator_test extends \advanced_testcase {
    /**
     * Parent status elevates to malicious when a child is malicious.
     */
    public function test_parent_elevates_on_malicious_child(): void {
        global $DB;
        $this->resetAfterTest();
        $repo = new scan_repository();
        $parent = $this->base_row();
        $parent->status = scan_status::CLEAN;
        $parent->archiveoutcome = archive_outcome::PROCESSING;
        $parent->id = $repo->insert($parent);

        $child = $this->base_row();
        $child->parentscanid = (int) $parent->id;
        $child->status = scan_status::MALICIOUS;
        $child->phase = scan_phase::COMPLETED;
        $child->id = $repo->insert($child);

        $orchestrator = archive_orchestrator::from_site_config();
        $orchestrator->maybe_finalize_parent((int) $parent->id);

        $updated = $repo->get_by_id((int) $parent->id);
        $this->assertSame(scan_status::MALICIOUS, $updated->status);
        $this->assertSame(archive_outcome::COMPLETE, $updated->archiveoutcome);
    }

    /**
     * Uninspectable containers must not remain clean.
     */
    public function test_mark_uninspectable_elevates_clean_parent(): void {
        $this->resetAfterTest();
        $repo = new scan_repository();
        $parent = $this->base_row();
        $parent->status = scan_status::CLEAN;
        $parent->id = $repo->insert($parent);

        $orchestrator = archive_orchestrator::from_site_config();
        $orchestrator->mark_uninspectable(
            $repo->get_by_id((int) $parent->id),
            archive_outcome::UNSUPPORTED,
            'error_archive_unsupported'
        );

        $updated = $repo->get_by_id((int) $parent->id);
        $this->assertSame(scan_status::ERROR, $updated->status);
        $this->assertSame(archive_outcome::UNSUPPORTED, $updated->archiveoutcome);
        $this->assertSame('error_archive_unsupported', $updated->errorcode);
    }

    /**
     * Incomplete archive with only clean children still applies limit error elevation.
     */
    public function test_incomplete_limits_elevate_to_error(): void {
        $this->resetAfterTest();
        $repo = new scan_repository();
        $parent = $this->base_row();
        $parent->status = scan_status::CLEAN;
        $parent->archiveoutcome = archive_outcome::INCOMPLETE;
        $parent->id = $repo->insert($parent);

        $child = $this->base_row();
        $child->parentscanid = (int) $parent->id;
        $child->status = scan_status::CLEAN;
        $child->phase = scan_phase::COMPLETED;
        $repo->insert($child);

        archive_orchestrator::from_site_config()->maybe_finalize_parent((int) $parent->id);
        $updated = $repo->get_by_id((int) $parent->id);
        $this->assertSame(scan_status::ERROR, $updated->status);
        $this->assertSame('error_archive_limits', $updated->errorcode);
    }

    /**
     * Internal helper.
     *
     * @return \stdClass
     */
    private function base_row(): \stdClass {
        $row = new \stdClass();
        $row->fileid = 0;
        $row->contenthash = null;
        $row->pathnamehash = null;
        $row->contextid = \context_system::instance()->id;
        $row->courseid = 0;
        $row->component = 'antivirus_verdict';
        $row->filearea = 'unittest';
        $row->itemid = 0;
        $row->filepath = '/';
        $row->filename = 'test.zip';
        $row->userid = 2;
        $row->source = scan_source::MANUAL;
        $row->sha256 = str_repeat('a', 64);
        $row->filesize = 1;
        $row->mimetype = 'application/zip';
        $row->status = scan_status::PENDING;
        $row->phase = scan_phase::COMPLETED;
        $row->vtanalysisid = null;
        $row->vtfileid = null;
        $row->malicious = null;
        $row->suspicious = null;
        $row->undetected = null;
        $row->harmless = null;
        $row->timeout = null;
        $row->totalengines = null;
        $row->errorcode = null;
        $row->enforcement = enforcement_state::NONE;
        $row->pollattempts = 0;
        $row->timelastpoll = 0;
        $row->timesubmitted = 0;
        $row->timecreated = time();
        $row->timemodified = time();
        $row->timecompleted = time();
        $row->parentscanid = 0;
        $row->archiveoutcome = archive_outcome::NONE;
        return $row;
    }
}
