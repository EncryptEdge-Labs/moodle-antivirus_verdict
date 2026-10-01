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
 * Resolved Moodle context for a scan record (display DTO).
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;


/**
 * Capability-filtered Moodle-native context labels for UI/export.
 *
 * Values are plain text; Mustache escapes them.
 */
final class scan_context_result {
    /** @var string Localised "Scanned by" label. */
    public string $scannedbylabel = '';

    /** @var string Scanned by label value or not-available string. */
    public string $scannedby = '';

    /** @var bool Whether scanned-by is shown (field present for this source). */
    public bool $showscannedby = false;

    /** @var string Localised file-associated user label. */
    public string $fileownerlabel = '';

    /** @var string Submitted/uploaded by value. */
    public string $fileowner = '';

    /** @var bool Whether file-owner row is applicable. */
    public bool $showfileowner = false;

    /** @var bool Whether upload-session user is shown (linked gate scans). */
    public bool $showuploadsession = false;

    /** @var string Upload-session label. */
    public string $uploadsessionlabel = '';

    /** @var string Upload-session user display. */
    public string $uploadsessionuser = '';

    /** @var string Course display. */
    public string $course = '';

    /** @var bool Whether course row applies. */
    public bool $showcourse = false;

    /** @var string Course URL or empty. */
    public string $courseurl = '';

    /** @var string Activity name from Moodle modinfo. */
    public string $activity = '';

    /** @var bool Whether activity row applies. */
    public bool $showactivity = false;

    /** @var string Activity URL or empty. */
    public string $activityurl = '';

    /** @var string Localised activity type (module name). */
    public string $activitytype = '';

    /** @var bool Whether activity type row applies. */
    public bool $showactivitytype = false;

    /** @var string Submission reference label. */
    public string $submission = '';

    /** @var bool Whether submission row applies. */
    public bool $showsubmission = false;

    /** @var string Submission URL or empty. */
    public string $submissionurl = '';

    /** @var string File location summary (component / file area). */
    public string $filelocation = '';

    /** @var bool Whether file location is shown. */
    public bool $showfilelocation = false;

    /** @var string Authoritative assignment submission file area when gate scan is linked. */
    public string $submissionfilelocation = '';

    /** @var bool Whether submission file location is shown. */
    public bool $showsubmissionfilelocation = false;

    /** @var string One-line summary for history tables. */
    public string $summaryline = '';

    /**
     * Export for Mustache templates.
     *
     * @return array<string,mixed>
     */
    public function export_for_template(): array {
        return [
            'showscannedby' => $this->showscannedby,
            'scannedbylabel' => $this->scannedbylabel,
            'scannedby' => $this->scannedby,
            'showfileowner' => $this->showfileowner,
            'fileownerlabel' => $this->fileownerlabel,
            'fileowner' => $this->fileowner,
            'showuploadsession' => $this->showuploadsession,
            'uploadsessionlabel' => $this->uploadsessionlabel,
            'uploadsessionuser' => $this->uploadsessionuser,
            'showcourse' => $this->showcourse,
            'course' => $this->course,
            'hascourseurl' => $this->courseurl !== '',
            'courseurl' => $this->courseurl,
            'showactivity' => $this->showactivity,
            'activity' => $this->activity,
            'hasactivityurl' => $this->activityurl !== '',
            'activityurl' => $this->activityurl,
            'showactivitytype' => $this->showactivitytype,
            'activitytype' => $this->activitytype,
            'showsubmission' => $this->showsubmission,
            'submission' => $this->submission,
            'hassubmissionurl' => $this->submissionurl !== '',
            'submissionurl' => $this->submissionurl,
            'showfilelocation' => $this->showfilelocation,
            'filelocation' => $this->filelocation,
            'showsubmissionfilelocation' => $this->showsubmissionfilelocation,
            'submissionfilelocation' => $this->submissionfilelocation,
            'summaryline' => $this->summaryline,
        ];
    }
}
