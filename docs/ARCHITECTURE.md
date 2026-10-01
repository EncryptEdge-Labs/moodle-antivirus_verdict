# Verdict for Moodle — Architecture

Authoritative technical description of the **implemented** plugin (`antivirus_verdict`, folder `verdict`, release 1.0.0 / `2026092801`). For externally observable behaviour and settings, see **`FEATURES.md`**.

## Plugin structure

Moodle antivirus plugin under `lib/antivirus/verdict/` (4.5/5.0) or `public/lib/antivirus/verdict/` (5.1/5.2).

| Area | Role |
| ---- | ---- |
| `classes/scanner.php` | Moodle `\core\antivirus\scanner` adapter |
| `classes/local/antivirus_gate.php` | Synchronous hash-lookup gate |
| `classes/local/scan_service.php` | Async analysis, polling, archive hooks, notifications |
| `classes/provider/virustotal/client.php` | VirusTotal API v3 client |
| `classes/local/provider_health.php` | Availability circuit |
| `classes/local/retry_policy.php` | Retry budget, delays, Retry-After cap |
| `classes/local/malicious_enforcer.php` | Late malicious File API enforcement |
| `classes/local/scan_repository.php` | `antivirus_verdict_scans` persistence |
| `classes/local/scan_context_resolver.php` | Attribution for UI/privacy |
| `classes/task/*` | Adhoc and scheduled workers |
| `classes/observer.php` | Activity/restore events |
| `classes/privacy/provider.php` | Privacy API |
| `javascript/ui.js`, `javascript/theme-boot.js` | Theme, dropzone, overview widgets (loaded via `$PAGE->requires->js`, not AMD) |
| `classes/local/teacher_access.php` | Administrator toggles for teacher-visible pages |
| `classes/local/operation_reservation.php`, `operation_counts.php` | Site operation ceilings and lifetime accounting |

Moodle discovers the scanner, settings, hooks, events, tasks, caches, messages, and capabilities through standard plugin files in `db/` and `settings.php`.

## Native antivirus integration

`scanner::is_configured()` is true when an API key exists. Moodle also requires `verdict` in `$CFG->antiviruses`. Capability checks are not applied inside `scan_file()`; Moodle calls it as a system service.

Return values: `SCAN_RESULT_OK`, `SCAN_RESULT_FOUND`, `SCAN_RESULT_ERROR`. Unknown/pending is never mapped to clean. Provider errors never become `SCAN_RESULT_OK` except the dedicated 429/circuit-open pending path, which is queued analysis rather than a clean verdict.

## Synchronous gate

`antivirus_gate::scan_file()` hashes the path, takes a per-hash lock, reuses a completed verdict when present, otherwise looks up VirusTotal. Known malicious is `FOUND`. Unknown stores `pending` and queues `process_scan` when a gate copy can be stored. Transient unavailability (`retry_policy::is_transient_unavailability`) queues pending rather than blocking as malware.

## Asynchronous engine

`task\process_scan` continues hash lookup, upload (direct ≤32 MiB, upload URL above that), polling, retries, archive orchestration, notifications, and late enforcement. `recover_stale_scans` re-queues or fails stuck active rows (`STALE_REQUEUE_AFTER` 7200s, `STALE_FAIL_AFTER` 86400s). Moodle 5.1/5.2 delay the running adhoc task; 4.5/5.0 queue a delayed successor so a pending scan is not left without a worker.

Retryable codes include `error_network`, `error_server`, `error_ratelimit`, `error_generic`, `error_providerunavailable`, `error_uploadinterrupted`. Permanent codes include auth, forbidden, malformed, too large, disabled. Maximum attempts: 10. Retry-After (delta-seconds or HTTP-date) is capped at 3600 seconds. Large POST attempts: 2.

## Circuit breaker

`provider_health`: closed / open / half-open. Threshold 5 consecutive availability failures (429/5xx/timeout/connection). Open for 120 seconds. Half-open allows one probe (lock-serialised). Auth and malformed-success close the circuit rather than opening it. Cache miss is treated as closed. Administrator Test connection may force a probe.

## VirusTotal client

API v3. Key only in `x-apikey`. Connect timeout 10s, request timeout 20s, large upload timeout 60s. Host-validated upload URLs for large files. Responses parsed to lookup/analysis/submission objects. HTTP 429 maps to `error_ratelimit`.

## Hashing and files

`file_hasher` streams SHA-256. Plugin-owned copies live in `manual` and `gate` file areas. Cleanup is retention- and privacy-driven, not a substitute for Moodle file deletion.

## Archive scanning

Optional. ZIP/MBZ via PHP ZipArchive only. Nested depth, member count, extracted MB, per-member size, and a 120s work budget. Uninspectable formats are not clean. Aggregate: malicious > suspicious > error > pending/not scanned > clean. Member scans use `parentscanid`. Malicious **members** do not quarantine themselves; the parent Moodle file is enforced when the aggregate is malicious.

## Assignment and other backfill

Observers queue scans for optional activity types (assign, forum, workshop, glossary, data, wiki, SCORM, question bank) and restore. This is **not** the upload gate. Deduplication avoids a second VirusTotal lookup when the gate already recorded a verdict. Assignment attribution: student → submission → cm → course → file. Missing Moodle context is shown as **Not available**.

## Manual and bulk

Manual scan records the initiating user. Bulk scan enumerates accessible course files with operator `initiatedby`. Both require configured credentials and the relevant capabilities.

## Late enforcement

After async malicious completion, `malicious_enforcer` resolves the live file by File API identity, verifies contenthash and SHA-256, quarantines via core `\core\antivirus\quarantine`, emits `virus_infected_file_detected`, notifies via `manager::send_antivirus_messages()`, then deletes only a verified matching live file. Copies are never treated as the live file. Enforcement state prevents duplicate quarantine.

## Attribution

| Source | `userid` | `initiatedby` |
| ------ | -------- | ------------- |
| Manual | Operator | 0 or operator as designed |
| Assignment | Submission user | 0 |
| Bulk/restore | File owner / context user | Operator |

Fields: `userid`, `initiatedby`, `submissionid`, File API identity columns.

## Database

Primary table `antivirus_verdict_scans` (see `db/install.xml`). Supporting tables: `antivirus_verdict_opcounts` (lifetime totals), `antivirus_verdict_opreserve` (in-flight reservation slots against configured ceilings). Upgrade steps in `db/upgrade.php` through `2026092801`. Indexes include hash, status, phase, enforcement, context, user, course, source, times, parent scan, submission.

Atomic reservation uses conditional `UPDATE … WHERE column < ceiling` (MySQL/PostgreSQL); SQL Server returns `-1` from reservation (documented limitation: no site ceiling enforcement on that DB family).

## Privacy and retention

Privacy provider exports/deletes plugin-owned scan rows and copies. It does not retract VirusTotal data and does not delete original activity files.

`purge_scan_history` removes terminal rows after `scanretentiondays` (default 365; `-1` disables). Active phases and malicious rows with enforcement `none`/`pending` are kept.

## UI and theme

Product shell: `product_start.mustache` + `styles.css` scoped to `.antivirus-verdict`. Styles and scripts are loaded explicitly from `page::apply_chrome()` because antivirus plugins under `lib/antivirus/` are not included in the standard theme plugin CSS bundle. Theme: `data-theme` / `data-antivirus-verdict-theme` and `--lv-*` tokens. Overview radars use CSS `animation-play-state` driven by `overview_service::scanner_radar_active()` (`is_operational()`) and `provider_radar_active()` (circuit closed only). Reduced motion pauses animation.

History and overview lists resolve course/activity labels through `scan_context_resolver` with per-request caches (`get_fast_modinfo`, user and course caches) to avoid N+1 queries when rendering paginated rows.

## Compatibility

Version-specific adhoc delay is the main 4.5–5.2 branch. Antivirus manager call sites are the same across the supported range. Direct File API writes still bypass the manager.
