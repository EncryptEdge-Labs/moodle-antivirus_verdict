# Verdict for Moodle

**Verdict for Moodle** connects Moodle’s native antivirus upload gate to VirusTotal analysis, asynchronous scanning, and an administrator console for scan history, enforcement, and configuration.

**Component:** `antivirus_verdict` · **Install folder:** `verdict` · **Release:** 1.0.0 (build `2026101100`) · **Moodle:** 4.5–5.2 · **Licence:** [GPL-3.0-or-later](LICENSE)

Maintained by **EncryptEdge Labs Limited**.

## What Verdict does

When Verdict is enabled in Moodle’s antivirus list and configured with a site-owned VirusTotal API key, uploads that pass through Moodle’s antivirus manager receive a **synchronous hash lookup**. Unknown files can continue uploading while analysis runs in the background. Completed malicious results can trigger **late enforcement** on the live file in Moodle’s file pool. Administrators (and optionally teachers) use Verdict’s pages for history, manual scan, coverage, and quarantine correlation.

Verdict is a **Moodle integration product**, not workstation antivirus and not a VirusTotal dashboard embedded in Moodle.

## Key features

* Native `\core\antivirus\scanner` integration and configurable upload policies  
* VirusTotal hash lookup, submit, and poll (API v3)  
* Async workers, retries, rate-limit handling, availability circuit  
* Optional ZIP/MBZ member scanning  
* Manual and bulk scan, scan history and detail  
* Overview dashboard, file coverage, quarantine inventory  
* Privacy API, retention purge, administrator notifications  
* Optional teacher-facing pages (administrator-controlled)  

Details: [`docs/FEATURES.md`](docs/FEATURES.md)

## Requirements and compatibility

| | |
| - | - |
| **Moodle** | 4.5, 5.0, 5.1, or 5.2 |
| **PHP** | As required by your Moodle version (use Moodle’s documented PHP for each branch) |
| **Database** | Supported Moodle databases (see ARCHITECTURE for SQL Server ceiling note) |
| **VirusTotal** | Site-owned API v3 key and outbound HTTPS |
| **Optional** | PHP `ZipArchive` if archive scanning is enabled |

## Installation

1. Copy the plugin into the Moodle **`verdict`** folder:
   * Moodle **4.5 / 5.0:** `{moodleroot}/lib/antivirus/verdict/`
   * Moodle **5.1 / 5.2:** `{moodleroot}/public/lib/antivirus/verdict/`
2. Visit **Site administration → Notifications** to install or upgrade the database.
3. Continue with [Configuration](#configuration) below.

The folder name must be **`verdict`** (component `antivirus_verdict`).

## Configuration

1. **API key:** Site administration → Plugins → Antivirus plugins → **Verdict for Moodle** — save your VirusTotal API key (or use in-app **Settings** after install).
2. **Enable scanning:** Site administration → Plugins → Antivirus plugins → **Manage antivirus plugins** — enable **Verdict**.
3. **Policies:** Set unknown, suspicious, provider-error, and late-malicious policies on the Verdict admin settings page.
4. **Optional:** Archive scanning, activity backfill toggles, retention, notifications, teacher access — see [`docs/FEATURES.md`](docs/FEATURES.md).

After upgrades that change tasks or templates, run **Purge all caches** (`Site administration → Development → Purge caches`).

## VirusTotal — important limitations

* Each site must supply its **own** API key and comply with [VirusTotal’s terms](https://www.virustotal.com/) and plan limits.
* Verdict does **not** provide quota, guaranteed detection, or removal of data already sent to VirusTotal.
* Provider outages, rate limits (HTTP 429), and circuit-open states may leave scans **pending**—that is not the same as **clean**.
* Usage may incur charges according to your VirusTotal account; EncryptEdge Labs does not set VirusTotal pricing.

## Testing and quality

The repository includes a large PHPUnit suite (`antivirus_verdict_testsuite`) and Behat scenarios tagged `@antivirus_verdict`. Normal CI uses mocks; live VirusTotal tests require explicit operator opt-in.

Summary of verified release evidence (build **2026101100**): [`CHANGES.md`](CHANGES.md). Implementation boundaries: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Security and support

* **Vulnerability reports:** see [`SECURITY.md`](SECURITY.md) — private report to EncryptEdge Labs; do not post API keys, customer files, or live malware in public issues.
* **Commercial support:** contact EncryptEdge Labs through your support agreement or the channel named in your contract. This repository is GPL source, not a hosted service.

## Licence

Copyright 2026 M. Afzal Riaz, powered by EncryptEdge Labs Limited.  
Released under the **GNU General Public License v3.0 or later** — see [LICENSE](LICENSE).

## Documentation

| Document | Purpose |
| -------- | ------- |
| [`docs/FEATURES.md`](docs/FEATURES.md) | Feature behaviour, settings, limitations |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Implementation, data model, tasks, security boundaries |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Release status, known limits, planned work |
