# Verdict for Moodle — Roadmap

## Current release

| | |
| - | - |
| **Version** | 1.0.0 (build **`2026101100`**, `MATURITY_STABLE`) |
| **Moodle** | **4.5, 5.0, 5.1, 5.2** (`supported` 405–502 in `version.php`) |
| **Provider** | VirusTotal API v3 (only implemented provider) |

## Completed (1.0.0)

* Native antivirus scanner + synchronous hash-lookup gate and policies
* Async `process_scan`, retries, stale recovery, availability circuit
* VirusTotal client, optional operation ceilings, shared poll fan-out
* Late File API enforcement and core quarantine integration
* Optional archive member scanning (ZIP/MBZ)
* Assignment/activity/restore/private-files backfill (optional toggles)
* Manual scan, bulk scan, overview, history, detail, coverage, quarantine UI
* Privacy API, retention purge, administrator notifications
* Teacher-access toggles; light/dark product chrome
* PHPUnit suite (556 tests × four branches, documented in `CHANGES.md`)
* Behat functional suite (18 scenarios); optional live VT certification workflow (operator opt-in)
* Build **2026101100** UI/accessibility fixes (tables, BS4 visually-hidden, radar pause without API key)

## Remaining quality and release work

* **Marketplace upload:** maintainer completes Moodle plugins directory listing (screenshots, public repo URL, support contact)—see checklist in [`CHANGES.md`](../CHANGES.md).
* **Release ZIP:** rebuild from tagged commit when needed; validate with `scripts/validate-release-zip.php` (production packages exclude `docs/` by design).
* **Full PHPUnit matrix:** re-run on all four branches after material code changes (use `--testsuite antivirus_verdict_testsuite`).
* **Aggregate Behat:** multi-branch runner may flake on ChromeDriver; rely on per-branch 18/18 evidence or rerun single branch.
* **In-app Settings:** operation guardrails section parity with native admin settings (ceilings remain on Moodle admin page today).
* **Manual browser matrix:** responsive/device checks remain operator responsibility.

## Known limitations (not defects)

* Files never passing `\core\antivirus\manager` are not scanned (Moodle core).
* Verdict is not endpoint antivirus and does not guarantee malware-free sites.
* VirusTotal cannot retract submitted hashes/files.
* Archives: ZIP/MBZ only; other formats are uninspectable, not implicitly clean.
* SQL Server: site operation ceilings not enforced (reservation limitation).
* Provider quotas, outages, and 429 rate limits affect pending queue depth.

## Future enhancements (planned, not implemented)

* Additional analysis providers beyond VirusTotal
* Independent scanning of every File API write without manager involvement
* Default CI live VirusTotal calls (remain opt-in by design)
* Extra archive formats only with bounded extractors and explicit uninspectable handling
* Support for new Moodle branches after they exist and are tested

## Intentionally out of scope

* Plugin-owned master enable switch (Moodle `$CFG->antiviruses` remains authoritative)
* Shared VirusTotal quota or hosted keys from EncryptEdge Labs
* Replacing Moodle core infected-files or antivirus management UI
