# Verdict for Moodle — Features

Authoritative feature overview for release **1.0.0** (build **`2026101100`**, Moodle **4.5–5.2**). Implementation detail: [`ARCHITECTURE.md`](ARCHITECTURE.md).

## Native Moodle antivirus integration

| | |
| - | - |
| **What** | `\core\antivirus\scanner` on manager call sites (repository upload, move to filepool, webservice upload, H5P ajax, and similar). |
| **Enable** | Site administration → Plugins → Antivirus plugins → **Manage antivirus plugins** (add `verdict`). |
| **Configure** | API key under Verdict settings; policies on admin settings page. |
| **Limit** | Does not scan arbitrary `file_storage` writes that bypass the manager. |

## VirusTotal provider

| | |
| - | - |
| **What** | Hash lookup at upload gate; file submit and analysis polling in the async worker. |
| **Credential** | Site-owned API v3 key (`settings.php` / in-app Settings). |
| **Security** | Key is not stored on scan rows, queued task payloads, or routine logs. Administrators may reveal the key on Settings after confirmation. |
| **External** | Quota, availability, terms, and any costs are the site’s VirusTotal account—not included with the plugin. Verdict does **not** guarantee detection. |

## Upload gate policies

Configurable under antivirus Verdict settings (defaults in parentheses):

| Policy | Default | Block behaviour | Allow / report |
| ------ | ------- | --------------- | -------------- |
| Unknown file | Allow | Refuse upload without claiming malware | Upload continues; scan **pending** |
| Suspicious | Allow | Refuse without claiming confirmed malware | Upload continues as suspicious |
| Provider error | Block | `scanner_exception` | Report: `SCAN_RESULT_ERROR` (Moodle may still accept) |
| Late malicious | Quarantine | Quarantine + delete verified live file | Report-only enforcement record |

## Async processing and deduplication

Unknown hashes queue **`process_scan`**. Retries handle transient errors and HTTP 429 (Retry-After, capped). Completed hash reuse and joining an in-flight analysis avoid duplicate provider lookups/uploads where implemented.

**Statuses:** clean, malicious, suspicious, pending, error, notscanned. Pending includes queued analysis and transient rate-limit/circuit queueing. None of unknown/pending/not scanned are shown or reused as **clean** for security decisions.

## Circuit breaker and overview indicators

Five availability failures open the circuit for 120 seconds; half-open allows one probe. Overview **scanner radar** animates when Verdict is operational (enabled + API key). **VirusTotal radar** animates when an API key is saved **and** the circuit is **closed**. Both are static when misconfigured, disabled, circuit open/half-open, or when the user prefers reduced motion.

## Archive scanning

Setting **`archivescan`** (on by default on new installs). **ZIP/MBZ** only; bounded member count, depth, and extracted size. Limits produce error/incomplete outcomes, never silent clean. With archives **off**, unknown containers may pass the gate without lookup; a **known** completed malicious container hash can still block via local reuse.

## Manual and bulk scan

| | Manual | Bulk |
| - | ------ | ---- |
| **Capability** | `antivirus/verdict:scan` | Same (+ teacher page toggle if applicable) |
| **Requires** | Saved API key | Saved API key |
| **Requires in `$CFG->antiviruses`** | No | No |
| **Scope** | File picker | Course files the operator can access |

*Browser workflow:* covered by PHPUnit and Behat navigation/manual-scan scenarios; end-to-end live VT result in browser is **not** a default automated gate.

## History, detail, coverage, quarantine

| Page | Capability (typical) | Notes |
| ---- | -------------------- | ----- |
| Scan history / detail | `viewhistory` / reports | Filters; attribution; enforcement; related scans |
| File coverage | `manage` (teachers if enabled) | Registry of how areas connect to Verdict—not core infected-files UI |
| Quarantine inventory | `manage` | Verdict enforcement correlated with core quarantine data |

## Assignment and activity backfill

Optional toggles (assignment **`assignscan`** off by default; restore scan on by default): queue files on events/observers—**not** the native upload gate. Duplicate SHA-256 reuses stored verdicts where applicable.

## Teacher access

**Show Verdict to teachers** (`teacheraccess`) master toggle. When on, administrators choose visible pages (overview, manual scan, bulk, history, coverage, quarantine). Settings remains `moodle/site:config`. Data scoped by course access and capabilities.

## Notifications

Terminal malicious, suspicious, or error (async path): Moodle messages to **site administrators** (HTML + plain text). Teachers are not default recipients.

## Operation limits

Optional ceilings for lookups, uploads, and polls (`0` = unlimited). Shared polling uses one `get_analysis` per analysis id.

## Retention and privacy

Scheduled purge of terminal history after **`scanretentiondays`** (default 365; `-1` disables). Active and pending-enforcement malicious rows retained. Privacy export/delete covers plugin-owned data only.

## Settings surfaces

* Moodle admin: **Plugins → Antivirus plugins → Verdict for Moodle** (policies, backfill, archives, retention, ceilings, native config).
* In-app **Settings** (`configure.php`): credentials, teacher access, notifications UX.

## Theme and accessibility

Light/Dark product chrome (`--lv-*` tokens). Bootstrap 4–compatible `.visually-hidden` shim for Moodle 4.5. Responsive sidebar; table layouts for overview recent scans and scan history (detection/queued columns). Status communicated with text and colour.

## Branding

Moodle nav label **Verdict**; in-product **Verdict for Moodle**. Icons: `pix/icon-dark-mode.png`, `pix/icon-light-mode.png`.

## Automated test coverage (honest summary)

| Layer | Coverage |
| ----- | -------- |
| PHPUnit `antivirus_verdict_testsuite` | **556** tests per supported branch (mocks/fakes; **6** skips including opt-in live VT). Historical four-branch PASS documented in [`CHANGES.md`](../CHANGES.md). |
| Behat `@antivirus_verdict` | **18** functional scenarios per branch in separate runs; aggregate multi-branch runner may fail on WebDriver timeouts (environment). |
| Live VirusTotal | Optional operator workflow (`VERDICT_LVT_OPT_IN=1`); not part of default regression. |
| Manual browser | Operator smoke (including post–UI-fix reports); not fully automated. |

Do not infer 100% UI or live-provider coverage from PHPUnit alone.
