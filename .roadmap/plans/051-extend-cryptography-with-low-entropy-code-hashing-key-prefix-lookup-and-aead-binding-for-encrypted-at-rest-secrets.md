---
id: 51
title: Extend cryptography with low-entropy code hashing, key-prefix lookup and AEAD binding for encrypted-at-rest secrets
type: feature
version: 3.10.0
status: planned
created: 2026-10-16
---

# Plan 51: Extend cryptography with low-entropy code hashing, key-prefix lookup and AEAD binding for encrypted-at-rest secrets
> Type: feature · Target: v3.10.0

## 🎯 Target Scope & Boundaries
- **Core objective:** new `cryptography` section(s): the entropy rule for hashing secrets — high-entropy random API keys/session tokens are safely stored as a fast hash (SHA-256) with a public lookup prefix, while low-entropy secrets (join/invite codes, short PINs) under a deterministic unkeyed hash are brute-forceable offline from a DB leak, so use HMAC-SHA256 with a server-held pepper (or argon2id when no lookup is needed) plus rate limiting; API-key prefix lookup + constant-time compare, key format (prefix, checksum for secret-scanning), rotation and last-used tracking; encrypted-at-rest secrets such as stored webhook URLs: AES-256-GCM with a unique nonce per encryption, AAD binding ciphertext to its row/tenant id so ciphertexts cannot be swapped between tenants, key ids for rotation, keys kept out of the DB and backups, decrypt only at use.
- **Out of scope:** password hashing parameters (already in section 1); JWT (section 4).

## 🏗️ Architectural Blueprint
- **Files to create:** none
- **Files to modify:** `skills/cryptography/SKILL.md`, `skills/audit/SKILL.md` (tier + OWASP map), `README.md`, `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, `SOURCES.md`
- **Schema/interface changes:** none (Markdown skill content only).
- **Downstream impact:** the `audit` orchestrator dispatches to it for projects using the covered technology.

## ✅ Acceptance
- **Passes when:** an auditor can classify every stored secret in an app by entropy and pick the right storage scheme from this section, with OWASP/NIST guidance quoted exactly.
- **Passes when:** `python3 scripts/check-freshness.py` is all-current.
- **Fails if:** an API name, default, version, advisory ID or provider capability is asserted that the vendor docs, RFC or OSV do not confirm; or the freshness check reports drift; or content duplicates a sibling skill instead of cross-referencing it.

## 🚶 Step-by-Step Checklist
- [ ] Step 1: Research primary sources and write the new section(s); every API name, parameter, default and advisory ID verified live -> target: `skills/cryptography/SKILL.md`
- [ ] Step 2: Update the skill description/frontmatter, audit dispatch notes, README and plugin.json keywords; cross-references from sibling skills -> target: `skills/audit/SKILL.md`, `README.md`, `.claude-plugin/plugin.json`
- [ ] Step 3: Add cited sources and confirm `python3 scripts/check-freshness.py` is all-current -> target: `SOURCES.md`
