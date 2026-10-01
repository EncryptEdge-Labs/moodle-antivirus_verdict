# Verdict for Moodle

Verdict is EncryptEdge Labs’ **Moodle security product**: a native antivirus scanner, an asynchronous analysis engine, late File API enforcement, and an operator console for administrators (and, if enabled, selected teacher pages).

It is **not** a ClamAV replacement, a VirusTotal dashboard pasted into Moodle, or a generic “scan uploads” plugin. VirusTotal API v3 is the **external analysis provider**. Verdict is the product: hashing, policy, persistence, archive member inspection, attribution, and enforcement.

| | |
| --- | --- |
| **Product** | Verdict for Moodle |
| **Moodle navigation** | Verdict |
| **Component** | `antivirus_verdict` |
| **Install folder** | `verdict` |
| **Release** | 1.0.0 (`MATURITY_STABLE`, `2026092801`) |
| **Official Moodle support** | 4.5–5.2 |
| **Licence** | [GNU GPL v3 or later](LICENSE) (required for Moodle plugins) |
| **Commercial maintainer** | EncryptEdge Labs Limited |

**Source of truth for behaviour:** [`docs/FEATURES.md`](docs/FEATURES.md).  
**Source of truth for implementation:** [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).  
This README is the public entry point. Language strings and admin help must match those documents.

---

## What it is

* A Moodle `\core\antivirus\scanner` that Moodle calls on **antivirus manager** paths (repository upload, `move_to_filepool`, webservice upload, H5P ajax, and similar).
* A **synchronous hash-lookup gate**: streaming SHA-256 of the real bytes, then VirusTotal lookup (or reuse of a stored completed verdict). The upload request does **not** wait for a full analysis.
* An **asynchronous engine** (`process_scan`) that uploads unknown samples, polls analysis, retries (including HTTP 429 / Retry-After, cap 3600s), recovers stale work, runs optional ZIP/MBZ member scanning, notifies administrators, and applies **late malicious enforcement**.
* A **policy layer** for unknown, suspicious, provider error, and late-malicious outcomes. Defaults are documented in FEATURES.md. Provider-error **Block** throws `scanner_exception` because Moodle core treats `SCAN_RESULT_ERROR` as fail-open.
* An **availability circuit** (5 failures / 120s open / half-open probe). Overview’s VirusTotal radar moves only while the circuit is **closed**.
* A **product UI** (Overview, history, scan detail, coverage registry, quarantine inventory, in-app Settings, manual scan, bulk scan) with Light/Dark tokens (`--lv-*`), not Boost admin chrome. Styles and scripts are loaded from `page::apply_chrome()` because antivirus plugins under `lib/antivirus/` are **not** in the standard theme CSS bundle.
* **Administrator-controlled teacher access**: off by default as a product surface. Settings stays `moodle/site:config`. Teachers never get site-wide data; repositories scope by course access.
* **Coverage and quarantine pages** that summarise *Verdict* data. They are not Moodle core infected-files UI.

Enablement is **only** Moodle’s native antivirus list (`$CFG->antiviruses` / Manage antivirus plugins). Verdict does **not** invent a second master on/off switch.

---

## What it is not

* **Not** a guarantee that every byte in Moodle was scanned. Direct `file_storage` writes that never call `\core\antivirus\manager` are **not** scanned. That is Moodle core behaviour (`docs/ROADMAP.md`, `docs/FEATURES.md`).
* **Not** endpoint or workstation antivirus.
* **Not** a shared VirusTotal account. Each site supplies and pays for its own API plan and quota.
* **Not** a retraction of data already sent to VirusTotal. Privacy export/delete covers **plugin-owned** rows and copies only.
* **Not** “the ZIP was 0/N on VirusTotal, therefore Verdict inspected the members.” Outer-hash lookup and **archive member scanning** are different. Member inspection is optional (`archivescan`, off by default), ZIP/MBZ only, bounded (default 50 members, depth 1, 200 MB extracted). Limits and uninspectable formats yield incomplete/error, **never silent clean**. Malicious **members** do not self-quarantine; the **parent** Moodle file is enforced when the aggregate is malicious.
* **Not** a claim that unknown, pending, not scanned, rate-limited, or provider-unavailable is **clean**. Those states are never displayed or reused as clean for security decisions.

---

## Security contract

Verdict statuses in storage and UI: **clean**, **malicious**, **suspicious**, **pending**, **error**, **notscanned**.

| Status | Meaning |
| ------ | ------- |
| Clean | Provider reported no detections |
| Malicious | Provider reported malware; gate and/or late enforcement apply policy |
| Suspicious | Heuristic detections; policy-driven (default Allow) |
| Pending | Unknown hash queued for analysis, or transient 429/circuit-open queueing |
| Error | Permanent failure after retries or policy |
| Not scanned | No completed provider verdict (admission without lookup, or archive member not analysed) |

**Gate results:** `SCAN_RESULT_OK`, `SCAN_RESULT_FOUND`, `SCAN_RESULT_ERROR`. Unknown/pending is never mapped to clean. The dedicated 429/circuit-open path queues analysis and returns `SCAN_RESULT_OK` as *queued pending*, not as a clean verdict.

**Late enforcement:** after async malicious completion, Verdict resolves the **live** Moodle file by File API identity, verifies `contenthash` and SHA-256, then quarantines via core `\core\antivirus\quarantine` (or report-only). Plugin-owned `manual` / `gate` copies are never treated as the live file.

**Notifications:** terminal malicious, suspicious, or error on the async path go to **site administrators**, not teachers by default.

**Capabilities:** `antivirus/verdict:manage`, `:scan`, `:viewreports`, `:viewhistory`, `:rescan`. `scan_file()` itself is a system service (no capability check inside the scanner).

---

## Upload-gate policies (defaults)

| Policy | Default | Block | Allow / report |
| ------ | ------- | ----- | -------------- |
| Unknown file | Allow | Refuse without claiming malware | Upload continues as **pending** |
| Suspicious | Allow | Refuse without claiming confirmed malware | Upload continues as suspicious |
| Provider error | **Block** | `scanner_exception` | Report: `SCAN_RESULT_ERROR`; Moodle may still accept |
| Late malicious | Quarantine | Quarantine + delete **verified** live file | Report-only: record enforcement without delete |

Optional **operation ceilings** (lookups, uploads, polls) reserve budget before HTTP. Hash reuse and joining an in-flight analysis do not consume lookup/upload budget.

---

## Product surface

| Area | Role |
| ---- | ---- |
| Overview | Protection banner, scanner/provider/quarantine/coverage, volume, detection mix, health, enforcement, recent scans. Scanner radar = operational; provider radar = circuit closed |
| Scan history / detail | Filterable history; counts, attribution, enforcement, related scans |
| File coverage | Registry of how Moodle file areas connect to Verdict |
| Quarantine inventory | Verdict enforcement outcomes correlated with core infected-files data |
| Scan a file | Manual queue (API key required; **does not** require Verdict to be in `$CFG->antiviruses`) |
| Bulk scan | Bounded course-file sweep; **not** the native upload gate |
| Settings | Credentials (key never on scan rows, tasks, logs, or ordinary pages), policies, backfill, archive limits, retention, notifications, teacher-access toggles |

Optional **backfill** (off by default): assignment submissions, forum, workshop, glossary, database, wiki, SCORM, question bank, restore, private-files sweep. Same engine as manual/async. **Not** the malware gate. Duplicate hashes reuse stored verdicts.

**Archive aggregate precedence:** malicious > suspicious > error > pending/not scanned > clean.

---

## Requirements

* Moodle 4.5, 5.0, 5.1, or 5.2
* PHP 8.1+ (8.2+ on Moodle 5.0/5.1, 8.3+ on Moodle 5.2)
* Site-owned VirusTotal API v3 key
* PHP `ZipArchive` if `archivescan` is enabled
* Connect timeout 10s, request timeout 20s; files above 32 MiB use VirusTotal upload URL (async). Site size limit default 100 MB (administrator-configurable)

---

## Installation

1. Install into `{moodle}/lib/antivirus/verdict/` (Moodle 4.5 / 5.0) or `{moodle}/public/lib/antivirus/verdict/` (Moodle 5.1 / 5.2). Folder name **must** be `verdict`.
2. **Site administration → Notifications**.
3. Save the API key under **Plugins → Antivirus plugins → Verdict for Moodle**.
4. Enable Verdict under **Plugins → Antivirus plugins → Manage antivirus plugins**.
5. Set unknown / suspicious / provider-error / late-malicious policies.
6. Optionally enable archive scanning and activity backfill.

The key is stored in plugin configuration and sent only as `x-apikey`.

---

## Commercial product, GPL source

EncryptEdge Labs **sells** implementation, support, and operational agreements. Moodle requires plugin source to be **GPL**. This repository is GPL-3.0-or-later.

GPL lets reviewers and operators inspect and redistribute the code under that licence. It does **not** include VirusTotal quota, an SLA, trademark rights, or EncryptEdge hosting. Do not open public issues for commercial terms, API keys, or customer files. See [`SECURITY.md`](SECURITY.md).

“Verdict”, “Verdict for Moodle”, and EncryptEdge Labs marks are product names. GPL on the source is not a trademark licence to ship a fork as official Verdict.

---

## Documentation

| Document | Purpose |
| -------- | ------- |
| [`docs/FEATURES.md`](docs/FEATURES.md) | Feature behaviour, settings, UI, limitations |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Gate, async engine, circuit, archives, enforcement, schema |
| [`docs/QA.md`](docs/QA.md) | Test strategy, PHPUnit testsuite, certification notes |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | 1.0.0 scope, known limitations, deferred work |
| [`SECURITY.md`](SECURITY.md) | Private vulnerability reporting |

---

## Tests

From a Moodle site tree, always:

```text
php vendor/bin/phpunit --testsuite antivirus_verdict_testsuite
```

`--filter` alone also loads core quiz CSV tests. Official automated gate in this tree: Moodle 5.2 / PHP 8.4, mocks and fakes only. Live VirusTotal certification is operator-only (`VERDICT_LVT_API_KEY`), never a committed secret. See [`docs/QA.md`](docs/QA.md).

---

## Copyright

Copyright 2026 M. Afzal Riaz, powered by EncryptEdge Labs Limited.

This program is free software under the GNU General Public License, version 3 or later. See [LICENSE](LICENSE).
