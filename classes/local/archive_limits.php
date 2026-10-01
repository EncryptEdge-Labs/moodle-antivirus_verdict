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
 * Bounded limits for archive extraction and member scanning.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;


/**
 * Conservative defaults for shared hosting, overridable via plugin_config.
 */
class archive_limits {
    /** Default maximum member files extracted from one container tree. */
    public const DEFAULT_MAX_MEMBERS = 50;

    /** Default maximum nested archive depth (0 = container only, 1 = one nested level). */
    public const DEFAULT_MAX_DEPTH = 1;

    /** Default maximum aggregate extracted bytes (200 MiB). */
    public const DEFAULT_MAX_EXTRACTED_MB = 200;

    /** Maximum entry path length accepted from a zip index. */
    public const MAX_ENTRY_PATH_LENGTH = 512;

    /** Maximum wall-clock seconds for one archive_process adhoc run. */
    public const MAX_WORK_SECONDS = 120;

    /**
     * Maximum declared uncompressed bytes per compressed byte.
     *
     * Checked before the member is inflated. Ordinary documents stay well
     * under this. A declared size far above the compressed size is rejected
     * so ZipArchive is not asked to allocate it.
     */
    public const MAX_COMPRESSION_RATIO = 1000;

    /** @var int Maximum member files to queue. */
    public readonly int $maxmembers;

    /** @var int Maximum nested archive depth. */
    public readonly int $maxdepth;

    /** @var int Maximum sum of extracted member bytes. */
    public readonly int $maxextractedbytes;

    /** @var int Maximum single member size (aligned with scan upload limit). */
    public readonly int $maxmemberbytes;

    /**
     * Create archive limit values.
     *
     * @param int $maxmembers Member cap.
     * @param int $maxdepth Recursion depth cap.
     * @param int $maxextractedbytes Aggregate extracted bytes cap.
     * @param int $maxmemberbytes Per-member size cap.
     */
    public function __construct(
        int $maxmembers,
        int $maxdepth,
        int $maxextractedbytes,
        int $maxmemberbytes
    ) {
        $this->maxmembers = max(1, $maxmembers);
        $this->maxdepth = max(0, $maxdepth);
        $this->maxextractedbytes = max(1, $maxextractedbytes);
        $this->maxmemberbytes = max(1, $maxmemberbytes);
    }

    /**
     * Load limits from site configuration.
     *
     * @param plugin_config|null $config Operational settings.
     * @return self
     */
    public static function from_site_config(?plugin_config $config = null): self {
        $config = $config ?? plugin_config::from_site_config();
        return new self(
            $config->archivemaxmembers,
            $config->archivemaxdepth,
            $config->archivemaxextractedmb * 1024 * 1024,
            $config->maxbytes
        );
    }

    /**
     * Normalise administrator member limit.
     *
     * @param int $value Posted value.
     * @return int
     */
    public static function normalise_max_members(int $value): int {
        if ($value <= 0) {
            return self::DEFAULT_MAX_MEMBERS;
        }
        return min($value, 500);
    }

    /**
     * Normalise administrator recursion depth.
     *
     * @param int $value Posted value.
     * @return int
     */
    public static function normalise_max_depth(int $value): int {
        if ($value < 0) {
            return self::DEFAULT_MAX_DEPTH;
        }
        return min($value, 5);
    }

    /**
     * Normalise administrator aggregate extraction limit in megabytes.
     *
     * @param int $value Posted value.
     * @return int
     */
    public static function normalise_max_extracted_mb(int $value): int {
        if ($value <= 0) {
            return self::DEFAULT_MAX_EXTRACTED_MB;
        }
        return min($value, 1024);
    }
}
