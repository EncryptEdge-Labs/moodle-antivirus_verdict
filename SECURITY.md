# Security policy

## Supported versions

EncryptEdge Labs supports the current stable release of Verdict for Moodle (`1.0.0`, Moodle 4.5–5.2). Older unpublished builds are not a security-support surface.

## Report a vulnerability

Do **not** open a public GitHub issue for:

* VirusTotal API keys or Moodle session cookies
* Customer filenames, SHA-256 values, or file contents
* Live malware samples or EICAR uploads from production
* Privilege-escalation or scanning-bypass reports

Send a private report to EncryptEdge Labs (commercial security contact or the address given on your support agreement). Include Moodle version, plugin version (`version.php`), and steps that do not require a real production key.

## Scope

Verdict participates in Moodle’s antivirus manager. Direct `file_storage` writes that never call `\core\antivirus\manager` are **not** scanned; that is Moodle core behaviour, not a Verdict secret.

Unknown, pending, and provider-error outcomes must never be treated as clean. Reports that a ZIP was “clean on VirusTotal” while Verdict showed Error should include whether archive scanning was enabled and whether member scans existed — outer-hash lookup is not the same as member inspection.

## API keys

Site administrators own VirusTotal credentials. EncryptEdge Labs does not need your production key to triage a source-code defect. Rotate any key that was pasted into git, chat, or a public ticket.
