# Verdict for Moodle — Roadmap

## Current release

**1.0.0** (`2026092801`, `MATURITY_STABLE`). Official Moodle support **4.5–5.2**. VirusTotal is the implemented provider.

Completed for this release:

* Native Moodle antivirus scanner and VirusTotal API v3 client
* Synchronous hash-lookup gate with unknown / suspicious / provider-error / late-malicious policies
* HTTP 429 and circuit-open treated as queued pending (not malware, not clean)
* Async `process_scan` with retries, Retry-After cap, stale recovery
* Availability circuit (5 / 120s / half-open probe)
* Late File API identity enforcement
* Optional assignment and other activity backfill
* Manual scan, bulk scan, history, detail, overview
* Archive ZIP/MBZ member scanning (optional)
* Privacy API and retention purge
* Coverage and quarantine inventories
* Light/Dark theme, responsive product chrome, CSS radars bound to operational/circuit state
* Administrator-controlled teacher access to selected Verdict pages
* Professional administrator scan notifications (HTML + plain text)

## Known limitations (not defects)

* Direct File API writes that never call `antivirus\manager` are not scanned. That is Moodle core behaviour.
* VirusTotal cannot retract data after a hash or file is submitted.
* Verdict is not endpoint antivirus.
* Archive scanning is ZIP/MBZ only; other containers are uninspectable, not clean.
* Official CI in this tree is Moodle 5.2 / PHP 8.4. Moodle 4.5–5.1 share the same plugin source via junctions. Running this PHP 8.4 CLI against Moodle 4.5 bootstrap emits core `E_STRICT` deprecations and does not constitute a Verdict test failure. Re-run 4.5/5.0/5.1 PHPUnit on matching PHP versions.

## Intentionally deferred

* Additional analysis providers beyond VirusTotal
* Scanning every File API write independently of Moodle’s antivirus manager
* In-browser live VirusTotal certification as a default CI job
* A plugin-owned master enable switch (native Moodle enablement remains authoritative)

## Future (post-1.0)

* Additional Moodle versions only after they exist and are tested
* Optional extra archive formats only with bounded extractors and explicit uninspectable handling
* Operator UX refinements that do not change the security model
