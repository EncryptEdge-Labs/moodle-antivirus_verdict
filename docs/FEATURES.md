# Verdict for Moodle — Features

Behaviour of features that exist in release 1.0.0. Configuration keys are Moodle plugin settings unless noted.

## Native scanner

**Purpose:** Participate in Moodle’s antivirus manager.  
**Success:** Explicit `SCAN_RESULT_*` for each upload that hits the manager.  
**Failure:** Invalid path fails closed. Missing key / disabled plugin: Moodle does not call a configured scan.  
**Limit:** Only manager call sites (repository upload, move_to_filepool, webservice upload, H5P ajax, and similar). `file_storage` itself does not scan.

## VirusTotal provider

Site-owned API key. Hash lookup, file submit, poll analysis. The key is never stored on scan rows, task payloads, logs, or ordinary plugin pages. Site configuration users can reveal it on Settings.

## Upload gate policies

| Policy | Default | Block | Allow / Report |
| ------ | ------- | ----- | -------------- |
| Unknown file | Allow | Refuse without claiming malware | Upload continues as pending |
| Suspicious | Allow | Refuse without claiming confirmed malware | Upload continues as suspicious |
| Provider error | Block | `scanner_exception` (core `SCAN_RESULT_ERROR` is fail-open) | Report returns `SCAN_RESULT_ERROR`; Moodle may still accept |
| Late malicious | Quarantine | Quarantine + delete verified live file | Report-only records enforcement without delete |

## Retry and rate limit

Async retries up to 10. 429 uses `error_ratelimit`, honours Retry-After, cap 3600s. Gate 429/circuit-open: pending queue, not malware.

## Circuit breaker

5 availability failures open for 120s. Half-open: one probe. Auth/malformed-success do not open the circuit. Overview VirusTotal radar moves only while the circuit is **closed**.

## Async analysis

Pending unknown files are uploaded and polled until complete, retry exhausted, or stale recovery fails them. Malicious results trigger enforcement.

## Archive scanning

Setting `archivescan` (on by default in a new install). ZIP/MBZ only. Defaults: 50 members, depth 1, 200 MB extracted. Limits yield incomplete/error, never silent clean.

When archive scanning is **off**, unknown archive containers on the upload gate are **allowed** without a provider lookup. A **known** completed malicious (or blocking suspicious) verdict for the container hash still blocks via local reuse. When archive scanning is **on**, containers are extracted and member files are scanned; parent status aggregates members (malicious > suspicious > error > pending/not scanned > clean).

## Teacher access

Master setting **Show Verdict to teachers** (`teacheraccess`). When off, teachers do not see Verdict navigation; page toggles are hidden on Settings. When on, administrators choose which pages teachers may open: overview, scan a file, bulk scan, history, coverage (default off), quarantine. Settings remains `moodle/site:config` only. Teachers require normal Verdict capabilities in course context; repositories scope overview, history, and quarantine to courses the viewer may access. Manual scan uses the same form as administrators (no course picker); bulk scan lists only permitted courses.

## Notifications

On terminal malicious, suspicious, or error outcomes (async path), Verdict sends Moodle messages (HTML + plain text) to **site administrators** via configured message providers. Copy includes course, detection counts, enforcement, and links where available. Teachers are not default recipients.

## Verdict semantics (UI and storage)

Statuses: **clean**, **malicious**, **suspicious**, **pending**, **error**, **notscanned**. Pending covers unknown hashes queued for analysis and transient 429/circuit-open queueing. **Not scanned** marks rows with no completed provider verdict (selected-area admission without lookup, or archive members not analysed). None of unknown/pending/not scanned are displayed or reused as clean for security decisions.

## Provider operation limits

Optional site ceilings for lookups, uploads, and polls (`0` = unlimited). Reservations increment immediately before HTTP; accounting increments after each attempt. Completed hash reuse and in-flight analysis joins do not consume lookup/upload budget. Shared polling performs one provider `get_analysis` per analysis id.

## Assignment automatic scanning

Setting `assignscan` (off by default). Observes `assessable_submitted`. Queues submission files. Duplicate hash reuses verdicts. Drafts/hidden/missing files are handled without invented context.

## Other activity / restore / private files

Optional backfill flags: forum, workshop, glossary, data, wiki, SCORM, question bank, restore (on by default), private-files sweep. Same asynchronous analysis path; not the native upload gate.

## Manual scan

Capability `antivirus/verdict:scan`. File picker. Requires API key, not `$CFG->antiviruses`. Records initiating user.

## Bulk scan

Users with `antivirus/verdict:scan` (and teacher-access page enabled when applicable) enumerate course files and queue bounded work. Operator in `initiatedby`. Cannot scan files the user cannot access; course menu is scoped to permitted courses.

## History and detail

Filterable history (status, source, filename). Detail shows status, detection counts, attribution, enforcement, related scans. Course context must not rewrite Moodle navigation chrome.

## Overview dashboard

Protection banner, scanner/provider/quarantine/coverage cards, statistics, 7-day volume, detection mix, system health, enforcement table, recent scans, quick actions. Light/Dark via `--lv-*`. Scanner radar follows operational state; provider radar follows circuit closed.

## Coverage and quarantine pages

Manage-capability inventories of scanned file coverage and enforcement outcomes. They summarise Verdict data; they are not Moodle core infected-files UI.

## Settings

In-app Settings plus Moodle admin settings page. Native enablement remains on Manage antivirus plugins. Credentials, policies, activity backfill, archive limits, retention, notifications.

## Privacy

Export and delete plugin-owned scans and copies for a user. Does not claim to delete VirusTotal’s copy. Does not delete original assignment/forum files on a privacy request.

## Retention

Scheduled purge of terminal history after N days (default 365). `-1` disables. Active and pending-enforcement malicious rows are kept.

## Theme, responsiveness, accessibility

Light/Dark toggle (`localStorage` key `antivirus_verdict_theme`). Scoped CSS. Sidebar drawer under 1024px. Tables use History-style headers and intentional overflow. Status uses text plus colour. Reduced motion pauses radars.

## Branding

Moodle primary navigation: **Verdict** (`pluginbrand`). In-plugin sidebar: **Verdict for Moodle** (`brandproduct`). Logos: `pix/icon-dark-mode.png`, `pix/icon-light-mode.png`.
