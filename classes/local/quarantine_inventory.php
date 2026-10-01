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
 * Verdict-facing quarantine inventory (wraps Moodle core quarantine data).
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

use antivirus_verdict\scan_status;
use core\antivirus\quarantine;


/**
 * Correlates Verdict scan rows with Moodle infected_files records.
 */
class quarantine_inventory {
    /** @var scan_repository Scan persistence. */
    private scan_repository $repository;

    /**
     * Internal helper.
     *
     * @param scan_repository $repository Scan persistence.
     */
    public function __construct(scan_repository $repository) {
        $this->repository = $repository;
    }

    /**
     * Internal helper.
     *
     * @return self
     */
    public static function from_site_config(): self {
        return new self(new scan_repository());
    }

    /**
     * Limit inventory rows to scans this user may see.
     *
     * @param int $userid Viewer user id.
     * @return self
     */
    public function for_viewer(int $userid): self {
        if (scan_access::can_manage_site($userid)) {
            return $this;
        }
        $copy = clone $this;
        $copy->repository = $this->repository->limited_to_viewer($userid);
        return $copy;
    }

    /**
     * Whether Moodle quarantine is enabled site-wide.
     *
     * @return bool
     */
    public function is_quarantine_enabled(): bool {
        return quarantine::is_quarantine_enabled();
    }

    /**
     * URL to Moodle's infected files report.
     *
     * @return \moodle_url
     */
    public function core_report_url(): \moodle_url {
        return new \moodle_url('/report/infectedfiles/index.php');
    }

    /**
     * Inventory rows for the administrator UI.
     *
     * @param int $limit Maximum scan rows.
     * @return array<int,array<string,mixed>>
     */
    public function rows(int $limit = 50): array {
        global $DB;

        $scans = $this->repository->find_quarantine_inventory($limit);
        if ($scans === []) {
            return [];
        }

        $filenames = array_unique(array_map(static fn(\stdClass $r): string => (string) $r->filename, $scans));
        $infected = [];
        if ($filenames !== []) {
            [$insql, $params] = $DB->get_in_or_equal($filenames, \SQL_PARAMS_NAMED, 'fn');
            $records = $DB->get_records_select(
                'infected_files',
                "filename {$insql}",
                $params,
                'timecreated DESC'
            );
            foreach ($records as $record) {
                $key = (string) $record->filename;
                if (!isset($infected[$key])) {
                    $infected[$key] = $record;
                }
            }
        }

        $rows = [];
        foreach ($scans as $scan) {
            $name = (string) $scan->filename;
            $match = $infected[$name] ?? null;
            $rows[] = [
                'scanid' => (int) $scan->id,
                'filename' => $name,
                'status' => scan_presenter::status_label((string) $scan->status),
                'enforcement' => scan_presenter::enforcement_label((string) $scan->enforcement),
                'time' => scan_presenter::format_time((int) $scan->timecompleted),
                'viewurl' => (new \moodle_url('/lib/antivirus/verdict/view.php', ['id' => (int) $scan->id]))->out(false),
                'hascore' => $match !== null,
                'coretime' => $match ? scan_presenter::format_time((int) $match->timecreated) : '',
                'corereporturl' => $this->core_report_url()->out(false),
            ];
        }
        return $rows;
    }

    /**
     * Summary counts for overview widgets.
     *
     * @return array{quarantined:int,malicious:int,coreenabled:bool}
     */
    public function summary(): array {
        return [
            'quarantined' => $this->repository->count_quarantine_inventory(),
            'malicious' => $this->repository->count_by_status(scan_status::MALICIOUS),
            'coreenabled' => $this->is_quarantine_enabled(),
        ];
    }
}
