# Changelog — Verdict for Moodle

## 1.0.0 (build 2026101100) — 2026-10-11

Presentation and QA release (no schema change; upgrade savepoint **2026101100**).

### UI / accessibility

* Overview recent-scans and Scan history: fixed **Engine detection** / **Queued** column overlap.
* Moodle **4.5** / Bootstrap 4: `.visually-hidden` shim (theme toggle, stat cards, coverage caption, settings toggles, API key buttons).
* Scan history: **Engine detection** header matches other column headers.
* Settings / teacher-access toggles: label leakage and alignment fixes.

### Overview behaviour

* VirusTotal availability radar **paused** when no API key is saved.

### Tests / tooling

* Behat suite (**18** scenarios), PHPUnit generator, live VT opt-in tests and scripts under `tests/` and `scripts/`.

### Documentation

* Public `/docs` consolidated to **ARCHITECTURE.md**, **FEATURES.md**, and **ROADMAP.md**; release/QA evidence retained in this file and **SECURITY.md**.

---

## 1.0.0 (build 2026092801) — 2026-09-28

Initial stable release: native antivirus gate, async VirusTotal analysis, enforcement, product UI, archives, privacy, operation ceilings (**2026092801** schema).

---

## Release verification (build 2026101100)

Evidence types are described in [`docs/ROADMAP.md`](docs/ROADMAP.md). Internal logs may be kept in a local `qa-logs/` directory (not shipped in the production ZIP).

| Check | Status | Notes |
| ----- | ------ | ----- |
| PHPUnit **556** × branches **405, 500, 501, 502** | Documented **0 failures**, **6 skips** | Historical runs 2026-10-10/11; re-run after code changes |
| Post–UI-fix PHPUnit subset (502) | **PASS** (15 tests) | `scan_ui_test` + radar motion |
| `qa-all-moodles.bat` lint/PHPCS/validate | **PASS** (2026-10-11) | PHPUnit skipped in that script by default |
| Behat **18/18** per branch | Documented separate runs | Functional regression; not full product coverage |
| Behat aggregate all-branch runner | **Exit 1** (environment) | ChromeDriver timeouts in hooks—not Verdict assertion batch failure |
| Live VT Workflow B | **Executed 2026-10-10** | `VERDICT_LVT_OPT_IN=1`; 4 tests, 3 HTTP calls; opt-in only |
| Release ZIP + validator | **PASS** (2026-10-11 audit) | `antivirus_verdict_moodle52_1.0.0_2026101100.zip`; SHA-256 below |

**Validated artifact (2026-10-11 audit build):**

* Size: **752885** bytes  
* SHA-256: `64227B0830AB018A7218E19DA26AA93B117F2BCA146BCDDC98363549D0B76666`  
* Entries: **284** · root **`verdict/`** · component **`antivirus_verdict`**

Rebuild from the exact git commit you release; recompute checksum after rebuild.

### Running tests (maintainers)

From a Moodle dirroot with the plugin installed and PHPUnit initialised:

```text
php vendor/bin/phpunit --configuration phpunit.xml --testsuite antivirus_verdict_testsuite
```

Always use the **antivirus_verdict_testsuite** name; bare `--filter` can pull unrelated core tests.

Optional live VT (never commit keys):

```text
set VERDICT_LVT_OPT_IN=1
php vendor/bin/phpunit --configuration phpunit.xml --group live_vt
```

Packaging uses local `build-release-zip.ps1` (gitignored) and `scripts/create-release-zip.php` + `scripts/validate-release-zip.php`. Production ZIP **excludes** `docs/`, `scripts/`, and QA wrappers by policy.

---

## Moodle plugins directory checklist (maintainer)

Use when uploading build **2026101100**:

| Item | Value |
| ---- | ----- |
| Plugin name | Verdict for Moodle |
| Component | `antivirus_verdict` |
| Type | Antivirus |
| Folder | `verdict` |
| Requires | `2024100700` (Moodle 4.5+) |
| Supported | 405–502 |
| Maturity | Stable |
| Licence | GPL v3 or later |
| ZIP name | `antivirus_verdict_moodle52_1.0.0_2026101100.zip` |

**You must still provide:** public source repository URL, support contact, screenshots, and directory changelog text (summarise from this file). Upload and approval are manual steps on [Moodle plugins](https://moodle.org/plugins/).
