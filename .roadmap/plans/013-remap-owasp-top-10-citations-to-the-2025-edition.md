---
id: 13
title: Remap OWASP Top 10 citations to the 2025 edition
type: bug
version: 3.4.0
status: done
created: 2026-08-21
---

# 🐛 Plan 13: Remap OWASP Top 10 citations to the 2025 edition

> Type: bug · Target: v3.4.0

## 🔍 Symptom & Reproduction

- **Observed:** The plugin cites OWASP Top 10 **2021** category numbers throughout. The 2025
  edition renumbered nearly every category, so several citations now point at a *different
  vulnerability class* than the text describes.
- **Expected:** Every OWASP web Top 10 reference matches the current 2025 numbering and naming.
- **Repro steps:** `grep -rn "A0[0-9]\|A10" skills/ SOURCES.md` and compare each against
  <https://owasp.org/Top10/2025/>.

Two citations are actively wrong, not merely dated:

- `web-vulns` says it covers "**A01/A03/A10**". Under 2025, **A10 is *Mishandling of Exceptional
  Conditions***, which the skill does not cover at all. SSRF was folded *into* A01.
- `logging-monitoring` cites **A03** for command/code injection. Under 2025, **A03 is *Software
  Supply Chain Failures***. Injection is A05.

Verified mapping (fetched from owasp.org 2026-08-21):

| 2021 | 2025 | Note |
|---|---|---|
| A01 Broken Access Control | **A01** Broken Access Control | absorbs SSRF |
| A02 Cryptographic Failures | **A04** Cryptographic Failures | |
| A03 Injection | **A05** Injection | |
| A04 Insecure Design | **A06** Insecure Design | |
| A05 Security Misconfiguration | **A02** Security Misconfiguration | |
| A06 Vulnerable Components | **A03** Software Supply Chain Failures | broadened |
| A07 Identification & Auth Failures | **A07** Authentication Failures | renamed |
| A08 Software/Data Integrity Failures | **A08** Software or Data Integrity Failures | |
| A09 Logging & Monitoring Failures | **A09** Security Logging and **Alerting** Failures | renamed |
| A10 SSRF | — | merged into A01 |
| — | **A10** Mishandling of Exceptional Conditions | new |

## 🩺 Root Cause

- **Culprit:** `skills/audit/SKILL.md` (:146-155 mapping table, :349 source),
  `skills/cryptography/SKILL.md` (:3, :7, :130), `skills/logging-monitoring/SKILL.md`
  (:3, :7, :70, :89, :112, :140-142), `skills/web-vulns/SKILL.md` (:3, :142),
  `skills/privilege-escalation/SKILL.md` (:160), `SOURCES.md` (:63, :133, :140, :142, :154).
- **Why:** The plugin was written against the 2021 edition, which stood for four years. The 2025
  edition (RC Nov 2025, final Jan 2026) reordered by prevalence, so stable-looking identifiers
  silently changed meaning.

## ✅ Acceptance

- **Passes when:** no `A0N_2021` URL remains, and every category number in prose matches the
  2025 edition.
- **Passes when:** references are written so a future renumbering is visible — cite the edition
  year alongside the number (e.g. "A05:2025") rather than a bare "A03".
- **Fails if:** an **OWASP API Security Top 10** citation is renumbered by mistake. That is a
  separate list; `A05 (BFLA)` in `privilege-escalation` and `SOURCES.md` is API-A05 and must not
  change. Likewise the **OWASP LLM Top 10** (plan 14) and **Mobile Top 10** are separate lists.

## 🛠️ Checklist

- [x] Step 1: Remap the mapping table and source link in `skills/audit/SKILL.md`, adding the new
  A10 row and folding SSRF into A01 -> target: `skills/audit/SKILL.md`
- [x] Step 2: Remap `cryptography` (A02 -> A04:2025) in the description, heading, and source
  -> target: `skills/cryptography/SKILL.md`
- [x] Step 3: Remap `logging-monitoring` (A09/A08/A03 -> A09/A08/**A05**:2025), including the
  renamed A09 "Alerting" and the section headings -> target: `skills/logging-monitoring/SKILL.md`
- [x] Step 4: Remap `web-vulns` (A01/A03/A10 -> **A01/A05**:2025, SSRF now inside A01)
  -> target: `skills/web-vulns/SKILL.md`
- [x] Step 5: Update the web-Top-10 URLs in `privilege-escalation` and `SOURCES.md` to the 2025
  slugs, leaving every API-Security-Top-10 URL untouched -> target: `SOURCES.md`,
  `skills/privilege-escalation/SKILL.md`
- [x] Step 6: Verify — no `_2021` URL remains, every rewritten `owasp.org/Top10/2025/...` URL
  returns HTTP 200, and API/LLM/Mobile Top 10 citations are unchanged -> target: manual
  verification
