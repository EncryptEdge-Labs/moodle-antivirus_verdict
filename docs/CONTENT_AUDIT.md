# Verdict for Moodle — Content audit (terminology campaign)

Recorded **2026-10-01**. Content-only changes; no behaviour, schema, or architecture changes.

## Campaign summary

Reviewed English product copy in:

- `lang/en/antivirus_verdict.php` (settings, UI, errors, privacy, tasks, notifications, capabilities)
- `settings.php` and in-app `templates/settings.mustache` / `classes/output/settings_page.php`
- Mustache templates (settings section intros only)
- `README.md`, `docs/FEATURES.md`, `docs/ARCHITECTURE.md`
- PHPUnit test copy assertions (`scan_notification_content_test.php`)
- One PHPDoc comment (`plugin_config.php`, `tests/classes/fake_provider.php`)

Not rewritten in this pass (already accurate or out of scope):

- Full PHPDoc sweep across all PHP classes
- `docs/ROADMAP.md`, `docs/QA.md`, `SECURITY.md` (no conflicting claims found)
- JavaScript user-visible strings (minimal; theme labels live in lang)
- Marketplace packaging copy outside this repository

## Terminology decisions

| Concept | Preferred term | Avoid (unless precise) | Notes |
| -------- | --------------- | ---------------------- | ----- |
| Product name | Verdict for Moodle / Verdict | Verdict AV, VT Scanner | After introduction, **Verdict** is sufficient |
| External malware analysis | VirusTotal | Verdict “engine” | Verdict integrates; it does not operate VT engines |
| Generic integration role | provider / analysis provider | malware provider, AV engine | Used in errors and docs |
| Moodle upload interception | native upload gate | upload scanner, malware gate | Aligns with `\core\antivirus\manager` |
| File decision (normalised) | verdict | result, detection (for status) | **Detection** reserved for VT engine counts |
| SHA-256 reuse | deduplication / verdict reuse | duplicate scanning | Documented in README |
| Send bytes to VT | submission / submit | upload (when ambiguous) | Moodle **upload** vs provider **submission** |
| VT processing | analysis / poll analysis | scan (when ambiguous) | User-facing **scan** still means Verdict workflow |
| Delayed malicious outcome | late malicious verdict | post-upload detection | Matches setting `asyncenforcement` |
| Site-configured caps | local operation limit / operation guardrails | VT quota | Ceilings are Verdict-side |
| Overview banner | operational status | protection status (where hype) | Calmer enterprise tone |
| Backfill paths | backfill / event-driven backfill | second malware gate | Never blocks assignment submission |

### Status vocabulary (unchanged; validated against code)

**Clean**, **Malicious**, **Suspicious**, **Pending**, **Error**, **Not scanned** — distinct from enforcement labels (quarantined, reported, blocked at upload).

Provider errors and unknown hashes are never described as clean.

## Outdated content corrected

| Location | Was | Now |
| -------- | --- | --- |
| `README.md`, `FEATURES.md` | `archivescan` “off by default” | **On by default** in new installs (`settings.php` / `plugin_config`) |
| `README.md` | Backfill “off by default” including restore | **Restore backfill on by default**; other activity toggles off |
| `README.md`, `ARCHITECTURE.md` | “Asynchronous engine” | **Asynchronous analysis** (Verdict worker, not VT engine) |
| Lang | “malware gate” | **native upload gate** where referring to Moodle Antivirus |
| Lang | “malware provider” | **analysis provider** |
| Lang | “Protection status / Monitoring active” | **Operational status / Operational** |
| Notifications | “security alert — malicious file detected” | **Verdict — malicious verdict** (status vs sensationalism) |

## Product-truth corrections

- **Archive scanning default** documentation now matches `plugin_config::config_enabled_default('archivescan', 1)`.
- **Unknown-file policy** admin text grammar fixed (“Allow lets the upload continue…”).
- **Overview** subtitle distinguishes **verdict summary** from VT **engine detections** column (`Engine detections`).
- **Coverage caveat** says Verdict **applies to** upload paths, not “protects” (no over-claim).
- Settings section headings in Moodle admin now include short group descriptions (archive, policies, notifications, storage, limits).

## Documentation alignment

| Document | Role after campaign |
| -------- | ------------------- |
| `README.md` | Public overview; terminology aligned with lang strings |
| `FEATURES.md` | Observable behaviour; archive/restore defaults fixed |
| `ARCHITECTURE.md` | Implementation terms: asynchronous analysis, provider submission |
| `CONTENT_AUDIT.md` | This report; terminology reference for future edits |
| `QA.md` | Unchanged; still describes verification, not product marketing |

Hierarchy: behaviour → **FEATURES**; implementation → **ARCHITECTURE**; entry → **README**. Conflicting defaults were removed from README/FEATURES.

## Remaining content debt

- **Dedicated Settings UI** does not yet show operation guardrails section (native `settings.php` only); group desc exists in lang for future parity.
- **`colstatus` vs `columnstatus`**: Quarantine uses “Verdict” column header; history uses “Status” — intentional (enforcement inventory vs scan phase).
- **`assignscan_page` and other `*_page` strings**: Long-form copy on configure flow; not fully harmonised with shorter `*_desc` variants in this pass.
- **Full PHPDoc comment audit** across `classes/` deferred (large surface; most user-facing text is in lang).
- **Non-English languages**: Only `lang/en` maintained in this repository.

## Validation (post-campaign)

**2026-10-01**

| Check | Result |
| ----- | ------ |
| `qa-all-moodles.bat` (4.5, 5.0, 5.1, 5.2; PHPUnit skipped in script) | PASS |
| Targeted PHPUnit 5.2: `scan_notification_content_test`, `overview_service_test`, `settings_ui_test` | 26 tests, 0 failures |

Logs: `qa-logs/qa-moodle-405.log` … `qa-moodle-502.log`.
