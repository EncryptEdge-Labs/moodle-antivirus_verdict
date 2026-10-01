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
 * Related scan lookup for gate ↔ assignment lifecycle.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

use antivirus_verdict\scan_source;


/**
 * Finds paired scan rows without overloading parentscanid (archive members only).
 */
class scan_correlation {
    /** @var scan_repository Scan persistence. */
    private scan_repository $repository;

    /**
     * Create correlation helper with optional repository override.
     *
     * @param scan_repository|null $repository Scan persistence.
     */
    public function __construct(?scan_repository $repository = null) {
        $this->repository = $repository ?? new scan_repository();
    }

    /**
     * Optional related scan for detail-page cross-links.
     *
     * @param \stdClass $scan Scan row the user is viewing.
     * @return array{id:int,label:string,url:string,isgate:bool,isassign:bool}|null
     */
    public function related_scan_link(\stdClass $scan): ?array {
        $source = (string) ($scan->source ?? '');
        if ($source === scan_source::ANTIVIRUS) {
            $related = $this->repository->find_assign_scan_for_gate_context($scan);
            if (!$related) {
                return null;
            }
            return $this->link_payload($related, 'relatedassignscan');
        }
        if ($source === scan_source::ASSIGN) {
            $related = $this->repository->find_gate_scan_for_assign_context($scan);
            if (!$related) {
                return null;
            }
            return $this->link_payload($related, 'relatedgatescan');
        }
        return null;
    }

    /**
     * Build a detail URL payload when the viewer may see the related scan.
     *
     * @param \stdClass $related Related scan row.
     * @param string $langkey Language string key.
     * @return array{id:int,label:string,url:string,isgate:bool,isassign:bool}|null
     */
    private function link_payload(\stdClass $related, string $langkey): ?array {
        $relatedid = (int) ($related->id ?? 0);
        if ($relatedid <= 0) {
            return null;
        }
        if (!scan_access::can_view_scan($related)) {
            return null;
        }
        $url = (new \moodle_url('/lib/antivirus/verdict/view.php', ['id' => $relatedid]))->out(false);
        return [
            'id' => $relatedid,
            'label' => get_string($langkey, 'antivirus_verdict'),
            'url' => $url,
            'isgate' => $langkey === 'relatedgatescan',
            'isassign' => $langkey === 'relatedassignscan',
        ];
    }
}
