# Greenholt Phish — Email Triage & Analysis

**Challenge:** Greenholt Phish (TryHackMe)  
**Role:** L1 SOC Analyst (Triage & initial investigation)  
**Date:** 1-16-2026

---

## TL;DR
A suspicious email with an unexpected `.CAB` attachment was reported by a Sales Executive. Manual header inspection, WHOIS lookup, SPF/DMARC checks, file hashing, and VirusTotal analysis confirmed the attachment was malicious. No execution of the file was performed. IOCs (IP, filename, SHA256 hash, sending domain) are included below.

---

## Scope & Objective
- Confirm legitimacy of the suspicious email.
- Extract key indicators (IP, domains, hashes, filenames).
- Provide remediation and next steps for containment and escalation.
- Keep analysis non-destructive: **do not execute** any suspicious files.

---

## Tools & Environment
- Thunderbird (email client) — initial triage view  
- CLI tools: `sha256sum`, `whois`, `dig` / `nslookup`  
- Online intelligence: VirusTotal (file + URL), SPF/DMARC lookup tools  
- (Optional) MXToolbox / other header analyzers (not allowed in this room — manual header parsing used)

---

## Timeline & Actions Taken
1. **Initial triage (client view)** — observed language, unexpected attachment `.CAB`, odd salutations.
2. **Full headers & message source** — extracted origin IP and delivery headers.
3. **WHOIS on originating IP** — identified hosting provider (Hostwinds LLC).
4. **Return-Path / envelope domain** — checked SPF and DMARC records (found SPF `-all` and DMARC `quarantine`).
5. **File hash generation** — `sha256sum` on the attachment.
6. **VirusTotal lookup** — file flagged as malicious by multiple vendors.
7. **Documented IOCs and recommended containment**.

---

## Evidence (high-level)
> Screenshots referenced below are included in the `screenshots/` folder. (See *Where to put screenshots* section.)

- Thunderbird message view — shows suspicious wording and `.CAB` attachment.  
  `![01 - Thunderbird view](screenshots/01_thunderbird_view.png)`

- Full headers / message source — shows `Received:` headers and originating IP.  
  `![02 - Full headers](screenshots/02_full_headers.png)`

- WHOIS lookup for IP `192.119.71.157`.  
  `![03 - WHOIS output](screenshots/03_whois.png)`

- SPF/DKIM/DMARC checks for return-path domain.  
  `![04 - SPF record](screenshots/04_spf.png)`  
  `![05 - DMARC record](screenshots/05_dmarc.png)`

- Hash generation and VirusTotal result showing detection.  
  `![06 - SHA256 & VirusTotal](screenshots/06_vt_and_hash.png)`

---

## Technical analysis

### 1) Message source & originating IP
- Extracted originating IP from headers: `192.119.71.157` (example — confirm exact value from your headers).
- Performed `whois` lookup: ownership points to Hostwinds LLC (commercial hosting provider) — often used by threat actors to host malicious infrastructure.

**Commands (examples):**
```bash
# show origin IP in the saved headers file
grep -i "Received:" message_source.txt | tail -n 10

# whois lookup
whois 192.119.71.157

### 2) Envelope / Return-Path checks (SPF/DMARC)
- Located the return-path domain from headers.
- Checked SPF record (TXT) and DMARC policy via DNS:

dig +short TXT example-return-path.com
dig +short TXT _dmarc.example-return-path.com


Observations: SPF restricted to Microsoft infrastructure with -all (hard fail). DMARC policy quarantine. This indicates the legitimate domain has authentication, but the email observed still came from an IP not listed for the domain — a strong spoofing indicator.

### 3) Attachment analysis (non-execution)

Attachment filename: SWT_#09674321___PDF__.CAB

DO NOT execute. Extract metadata where possible in a safe environment (sandbox or isolated VM).

Generated file hash:

sha256sum "SWT_#09674321___PDF__.CAB"
# Example output:
# <SHA256_HASH>  SWT_#09674321___PDF__.CAB


Queried VirusTotal with the SHA256 and file — returned multiple detections indicating malicious content.

4) Conclusion

Multiple indicators (suspicious wording, originating IP from a generic hosting provider, return-path and envelope mismatch, malicious detection on VirusTotal) confirm a phishing/malicious email. Recommend containment and escalation to Level 2/3 for full forensic and sandbox analysis.


