# Verdict for Moodle — QA

## Strategy

PHPUnit is the automated gate. Mocks and fakes only (no live malware samples). Optional live VirusTotal certification uses `VERDICT_LVT_API_KEY` and `scripts/run-live-vt-cert.ps1` (operator-only, rate-limited).

Moodle plugin CI (`qa.bat`) runs PHP lint, PHPCS (Moodle standard), PHPDoc, plugin validation, upgrade savepoints, Mustache lint, and PHPUnit when tests exist.

Only one `antivirus_verdict_testsuite` run at a time **per Moodle tree** (PHPUnit global lock).

Always pass `--testsuite antivirus_verdict_testsuite`. `--filter` alone also loads core quiz CSV walkthrough tests, which error on empty data providers (Moodle core).

## Commands (Moodle 5.2 / PHP 8.4)

From `D:\CODE\moodle-dev`:

```text
php vendor\bin\phpunit --configuration phpunit.xml --testsuite antivirus_verdict_testsuite --display-notices
```

PHPCS:

```text
php D:\CODE\moodle-plugin-ci\vendor\squizlabs\php_codesniffer\bin\phpcs --standard="<plugin>\phpcs.xml.dist" -p -s --report-full --report-width=132 "<plugin>"
```

JavaScript: `node --check javascript/ui.js` and `node --check javascript/theme-boot.js`.

Packaging: `.\build-release-zip.ps1` from the plugin root. Archive root must be `verdict/version.php`. Fixture `.zip` files under `tests/fixtures/` are included. Do not use `Compress-Archive` for Linux installs.

After a long-lived site upgrade, purge Moodle caches (`admin/cli/purge_caches.php`) so new task classes enter the component classmap, then scheduled tasks from `db/tasks.php` can register.

## Test architecture

| Area | Primary tests |
| ---- | ------------- |
| Gate / scanner | `scanner_test`, `hardening_test` |
| Client / 429 / circuit | `client_test`, `provider_health_test`, `retry_policy_test` |
| Async / enforcement | `process_scan_task_test`, `malicious_enforcer_test` |
| Assignment | `assignment_scanner_test`, `assignment_submission_linker_test` |
| Archive | `archive_*_test` |
| Privacy / retention | `privacy_provider_test`, `scan_retention_test` |
| UI / overview | `scan_ui_test`, `overview_service_test`, `settings_ui_test`, `plugin_test` |
| Access | `scan_access_test` |
| QA suites | `qa_phases_test`, `qa_edge_case_test` |
| Live VT (optional) | `live_vt_certification_test` (skipped without key) |

## Release checklist

* [x] Package zip root is `verdict/` (205 entries, logos + archive fixtures)
* [x] PHPUnit testsuite on Moodle 5.2
* [x] PHPCS / PHP lint / JS syntax / plugin-ci validate / savepoints / phpdoc
* [x] Site DB upgrade 2026091100 → 2026092501 (schema + API key + scan rows retained)
* [ ] Live HTTP UI (requires a running web server; `http://localhost` was not listening)
* [ ] Live VirusTotal (`VERDICT_LVT_API_KEY` unset)
* [ ] PHPUnit executed on Moodle 4.5 / 5.0 / 5.1 trees this pass

## Known external limitations

* PHPUnit 11 `@covers` deprecations, not suppressed
* One Moodle PHPUnit notice: `DEBUG_DEVELOPER` `debugging()` when the notification hook throws inside `scan_service::complete()` (`process_scan_task_test::test_completed_poll_persists_malicious`). Not treated as a failure. Not suppressed.
* Quiz CSV walkthrough tests if `--filter` is used without the Verdict testsuite
* Direct File API writes that never call `antivirus\manager` are not scanned (Moodle core)
* Live VT and live browser/device matrix are operator/environment, not default CI

## PHPUnit deprecations / notices (Moodle 5.2, 2026-09-23)

**45 PHPUnit deprecations:** PHPUnit 11 `@covers` on test classes. Moodle/PHPUnit metadata, not Verdict runtime.

**Notices after test hygiene fixes:** **1** remaining (`notification hook failed` debugging during malicious completion in `process_scan_task_test`). Previously 8: two were PHP 8.4 “only variables should be passed by reference” in `assignment_submission_linker_test` (fixed); six were unasserted `debugging()` on expected developer paths (consumed with `assertDebuggingCalled()` where it is deterministic).

## Latest certification results

Recorded **2026-09-30** (Phase 9 marketplace audit pass on Moodle 5.2.2+ / PHP 8.4.25).

Previous recorded run: **2026-09-23**.

### PHPUnit — Moodle 5.2.2+ / PHP 8.4.25 / MariaDB 12.3.3 / PHPUnit 11.5.55

```text
cd D:\CODE\moodle-dev
php vendor\bin\phpunit --configuration phpunit.xml --testsuite antivirus_verdict_testsuite --display-notices
```

* Tests: **545**
* Assertions: **3082**
* Failures: **0**
* Errors: **0**
* Skipped: **6** (live VT without key; archive platform skips)
* PHPUnit deprecations: **54**
* Time: **42:45**
* Exit: **0**

Moodle 4.5 / 5.0 / 5.1 trees exist and junction the same plugin source. This certification pass did **not** complete PHPUnit on those trees: Moodle 4.5 PHPUnit on PHP 8.4 stopped with core bootstrap deprecations and “PHPUnit environment was initialised for different version” (Moodle/PHPUnit tooling, not a Verdict assertion failure).

### PHPCS

155 files, **0** errors, **0** warnings (`phpcs.xml.dist`).

### Other

* `php -l` 155 plugin PHP files: **0** failures
* `node --check` `javascript/ui.js` and `javascript/theme-boot.js`: **0**
* moodle-plugin-ci `validate`: PASS
* moodle-plugin-ci `savepoints`: PASS (7 blocks)
* moodle-plugin-ci `phpdoc --max-warnings 0`: PASS
* Behat: N/A
* Grunt via moodle-plugin-ci: not a Verdict correctness gate on this Windows layout

### Package

`dist/antivirus_verdict_moodle52_1.0.0_2026092501.zip` — VALIDATION PASS, root `verdict`, 205 entries, `verdict/version.php`, both logos, `tests/fixtures/archives/*.zip`. `docs/` excluded by pack policy. README included.

### Site upgrade (moodle-dev `mdl_` prefix)

From config version **2026091100** to **2026092501**: attribution/archive/enforcement fields and indexes present; API key still configured; 5 existing scan rows retained; `verdict` remains in `$CFG->antiviruses`. After `purge_caches.php`, `purge_scan_history` and `scan_private_files` scheduled tasks registered. Fresh-install XMLDB includes the `submissionid` index (aligned with the 2026092500 upgrade step).

### Live VirusTotal

**NOT EXECUTED — ENVIRONMENT LIMITATION** (`VERDICT_LVT_API_KEY` unset).

### Live UI / responsive / accessibility

**NOT EXECUTED — ENVIRONMENT LIMITATION** (no HTTP listener on `localhost`; Moodle `wwwroot` is `http://localhost`).
