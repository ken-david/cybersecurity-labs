# TryHackMe — Email Analysis: Greenholt PLC (Analyst Report)

**Author:** Ken David

**Date:** 2026-01-16

**Role:** L1 SOC / Incident Triage

**Scope:** Analyze an unexpected email received by a Sales Executive at Greenholt PLC and determine whether the message and attachment are malicious.

---

## TL;DR

A suspicious email with an unexpected `.CAB` attachment was reported by a Sales Executive. Manual header analysis, SPF/DMARC checks, IP WHOIS, and a SHA256 hash lookup on VirusTotal confirm the attachment is malicious. This report documents methodical triage steps, key findings (IOCs), impact assessment, and recommended remediation and hunting actions.

---

## Purpose & Constraints

* Produce a professional, analyst-style report suitable for GitHub and employer review (process-focused, not a Q&A dump).
* **Do not** execute or open the attachment.
* This writeup intentionally excludes any challenge flags or step-by-step answers per TryHackMe rules and ethical disclosure practices.

---

## Timeline & Actions Taken

1. Notification: Sales Executive forwarded suspicious email to SOC.
2. Visual inspection: Opened email in Thunderbird — noted unprofessional language, unsolicited `.CAB` attachment, odd reference number, and mismatched sender behavior.
3. Header analysis: Viewed full message source for Received headers and origin IP.
4. WHOIS/IP lookup: Resolved originating IP to Hostwinds LLC.
5. Return-Path/SPF/DMARC: Retrieved and inspected DNS records for authentication results.
6. Artifact handling: Computed SHA256 hash of attachment (offline, read-only).
7. Threat intel lookup: Queried VirusTotal and reputation sources using the SHA256 and other IOCs.
8. Conclusion & recommendations: Declared attachment malicious and provided containment/hunting steps.

---

## Evidence & Findings

### 1) Initial Indicators (Observable from Mail Client)

* Unsolicited message with inconsistent greeting compared to sender’s usual style.
* Unexpected attachment: `SWT_#09674321___PDF__.CAB` (double extension and `.CAB` is unusual for PDFs).
* Poor grammar and suspicious wording.

### 2) Message Source / Mail Headers

* Extracted full message source and located earliest `Received:` header showing originating IP: `192.119.71.157` (example).
* Extracted Return-Path domain from `Return-Path:` header.

> **Note:** When presenting headers in a public repo, sanitize user-identifying email addresses and any internal hostnames.

### 3) Sender Authentication (Return-Path Domain)

* SPF: Domain published an SPF record restricting sending to Microsoft Outlook infrastructure (`-all`).
* DMARC: Domain has a `p=quarantine` DMARC policy.
* Interpretation: The domain has legitimate anti-spoofing controls in place; however, SPF/DKIM alignment and the actual sending MTA may still differ (evidence of third-party relay or compromised host). If authentication fails against the Return-Path, treat as high-risk.

### 4) IP and Hosting Information

* WHOIS for originating IP resolves to: Hostwinds LLC (hosting provider).
* Interpretation: Hosting providers often used by attackers to send spam/phishing; a legitimate corporate sender would more likely originate from their corporate mail MXs.

### 5) Artifact Analysis (Attachment)

* Without opening the file, computed SHA256 (command used):

```bash
sha256sum "SWT_#09674321___PDF__.CAB"
```

* SHA256 was queried against VirusTotal and returned a malicious verdict from multiple engines.

---

## Indicators of Compromise (IOCs)

> *Sanitize any IOCs before publishing publicly if they include private or trial flags.*

| Type                 | Value                       | Notes                                                                                                                              |
| -------------------- | --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| Attachment file name | `SWT_#09674321___PDF__.CAB` | suspicious double-extension                                                                                                        |
| SHA256               | `REDACTED_FOR_PUBLICATION`  | use full hash in internal repo; public repo can show truncated hash (first 8 chars) or a pointer to IOCs file with access controls |
| Originating IP       | `192.119.71.157`            | WHOIS: Hostwinds LLC                                                                                                               |
| Return-Path domain   | `example-return.com`        | SPF: `v=spf1 include:spf.protection.outlook.com -all`  (observed)                                                                  |

**Severity:** Medium–High (malicious attachment, targeted impersonation characteristics).
**Confidence:** High (VirusTotal and header anomalies corroborate).

---

## Impact Assessment

* If the attachment had been executed, potential outcomes include malware infection, data exfiltration, credential theft, or lateral movement depending on payload.
* As the file was not executed, there is no confirmed host compromise at this time.

---

## Containment & Remediation Steps (Immediate)

1. Block the originating IP and any infrastructure observed on network perimeter devices (firewall, IDS/IPS) and email gateway blocklists.
2. Quarantine the affected mailbox and reset the user’s mailbox access if credential compromise is suspected.
3. Mark the message as phishing in the mail system and remove similar messages from user inboxes via search + quarantine.
4. Add file hash to EDR/XDR blocklist and signature sets for prevention.
5. Notify other potentially affected departments and run targeted email searches for the Return-Path and attachment filename.

---

## Hunting & Follow-Up

* Search SIEM for events containing the SHA256, attachment filename, Return-Path domain, and originating IP over the previous 30–90 days.
* Look for suspicious authentications or logins for the user in question around the email receipt time.
* Monitor for newly observed domains or IPs associated with the same actor.

---

## Tools & Commands Used (examples)

* Mail client: Thunderbird — view → message source
* Header parsing: manual review (this lab restricted automated header tools)
* WHOIS: `whois 192.119.71.157`
* DNS/SPF/DMARC lookup: `dig TXT example-return.com` or online SPF/DMARC checkers
* Hashing: `sha256sum suspicious.cab`
* VirusTotal: web UI or API lookup using SHA256

---

## Recommendations (Policy & Engineering)

* Enforce and tune email gateway sandboxing for archive file types and double-extensions.
* Educate employees to report unusual emails and not to open attachments from unexpected senders.
* Implement automated header analysis and blocking when `Received` headers resolve to known hosting provider ranges for corporate senders.
* Add IOC feed integration to SIEM/EDR for faster automated blocking.

---

## What to Include on GitHub (and what to avoid)

**Include:**

* A clean, professional Markdown analyst report (this file).
* A sanitized `iocs.md` or `iocs.csv` file for internal use (or gated repo if IOCs are sensitive).
* `assets/` folder with sanitized screenshots (redact PII).
* `tools.md` listing commands and tools used.

**Avoid publishing:**

* Raw user email addresses or internal hostnames.
* Any TryHackMe flags or challenge answers that violate the platform rules.
* Full unreleased IOCs that may target live environments unless the repo is private or access-controlled.

---

## Appendix A — Suggested File & Repo Structure

```
email-triage-greenholt/
├─ README.md                     # short TL;DR + link to full report
├─ reports/
│  └─ 2026-01-18-email-triage.md  # this analyst report
├─ iocs/
│  └─ iocs-2026-01-18.csv         # internal (hashed/sanitized for public)
├─ assets/
│  └─ screenshots/                # redacted screenshots
├─ tools.md
└─ LICENSE
```

---

## Appendix B — Suggested Commit Message & PR Description

**Commit message:** `docs(reports): add email triage report for Greenholt PLC (2026-01-18)`
**PR description (short):** `Adds an L1 SOC analyst report for an email triage exercise (Greenholt PLC). Focuses on methodology, evidence, and recommended containment/hunting steps. IOCs are sanitized for public posting.`

---

## Final Notes

This report was written to showcase analyst thinking: evidence collection, triage steps, corroborating telemetry, and actionable recommendations. If you want, I can also:

* Produce a shorter executive summary suitable for a README.
* Generate a private `iocs.csv` and a public `iocs-truncated.md` for GitHub.
* Sanitize your screenshots (redact PII) and prepare the repo-ready ZIP with proper README, LICENSE, and commit history.

---

*End of report.*

