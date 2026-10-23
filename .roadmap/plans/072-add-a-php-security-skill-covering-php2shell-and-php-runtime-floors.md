---
id: 72
title: Add a php-security skill covering PHP2Shell and PHP runtime floors
type: feature
version: 3.14.0
status: done
created: 2026-10-23
---

# Plan 72: Add a php-security skill covering PHP2Shell and PHP runtime floors
> Type: feature · Target: v3.14.0

## 🎯 Target Scope & Boundaries
- **Core objective:** a new `skills/php-security/SKILL.md` that audits PHP apps the way python-web-security audits Python ones. Leads with the PHP runtime itself: PHP2Shell (CVE-2026-109618 / CVE-2026-109619, CVSS 4.0 9.2 each, unauthenticated RCE in PHP core, exploited in the wild, patched 2026-10-21) — floors 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35; 8.1 and older are EOL and unpatched by the PHP project (upgrade, or rely on a distro/vendor backport and say so). Mod_php / php-cgi / php-fpm exposure, how to read the running version (`php -v`, `composer.json` `require.php`, `config.platform.php`, Docker `php:` base tags, `X-Powered-By`), and endoflife.date `php` for EOL lines. Then the common app-level checks AI assistants miss in PHP: `unserialize()` on input, `include`/`require` with user paths (RFI/LFI), `eval`/`assert`/`preg_replace /e`, `system`/`exec`/`shell_exec`/backticks, PDO without bound params, `display_errors`/`expose_php` in prod, `.env`/`vendor/` exposure, Laravel `APP_DEBUG`/`APP_KEY`, WordPress plugin supply chain (link the supply-chain skill).
- **Also:** a PHP2Shell entry in `framework-versions` pointing to php-security, and the audit orchestrator routes PHP projects (composer.json / *.php) to the new skill.
- **Sources:** php.net/archive/2026.php (vendor), CSA AL-2026-151, SANS ISC diary 33450; pwn.watch only as a tracker link.
- **Out of scope:** per-CMS deep dives (WordPress/Drupal/Magento/Joomla plugin CVE lists), Composer lockfile parsing in monitor-deps.py (plan 75 may consume it).

## 🏗️ Architectural Blueprint
- **Files to create:** skills/php-security/SKILL.md
- **Files to modify:** skills/audit/SKILL.md (routing), skills/framework-versions/SKILL.md (PHP2Shell floor + source), README.md (skill list), SOURCES.md, .claude-plugin/plugin.json and .codex-plugin/plugin.json keywords if they enumerate stacks
- **Downstream impact:** check-freshness.py must stay green (OSV does not index the PHP runtime — floors cite the vendor URL, same treatment as the Node.js runtime note)

## ✅ Acceptance
- **Passes when:** the skill exists with frontmatter matching sibling skills; audit routes PHP projects to it; framework-versions names the four fixed versions and the EOL caveat with php.net as source; `python3 scripts/check-freshness.py` reports all current and `--self-check` passes; README/SOURCES list it.
- **Fails if:** a floor is stated without a vendor source, or pwn.watch is cited as the authority.

## 🚶 Step-by-Step Checklist
- [x] Step 1: Write skills/php-security/SKILL.md (runtime floors + PHP2Shell, app-level checks, sources) -> target: skills/php-security/SKILL.md
  > evidence: freshness --self-check: OK; --only manifests: All current; php-security snippets/greps run in php:8.4-cli (8.4.27) + BSD grep; verifier: PARTIAL, 12 findings, 12 acted on; scoped re-review verifier: CONFIRMED, 0 blocking (lows noted) (2026-10-23)
- [x] Step 2: Wire it in: audit routing, framework-versions entry, README, SOURCES, manifests; freshness green -> target: skills/audit/SKILL.md, skills/framework-versions/SKILL.md, README.md, SOURCES.md
  > evidence: audit item 34 + OWASP rows, framework-versions PHP entry, README (39 domain skills = 40 dirs), SOURCES, 3 manifests in sync; full freshness run: 10 drifted both with and without this change (pre-existing, none PHP); spec scout: all MET except 'all current' = pre-existing drift (2026-10-23)
