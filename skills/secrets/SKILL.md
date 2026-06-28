---
name: secrets
description: Finds hardcoded API keys, tokens, and credentials, and secrets exposed through client-side env var prefixes (NEXT_PUBLIC_, VITE_, EXPO_PUBLIC_, REACT_APP_). Checks .gitignore hygiene and common AI-generated default credentials. Use when handling API keys, secrets, environment variables, or .env files, when wiring up a third-party service, or when auditing for leaked credentials — even if the user doesn't say "secrets".
license: MIT
---

# Secrets & Environment Variables

## When to Use

- Adding or reviewing API keys, tokens, or credentials.
- Wiring up a third-party service (Stripe, Supabase, OpenAI, etc.) that has client and server keys.
- Auditing `.env` handling, `.gitignore`, or env var prefixes.
- Checking seed data / auth code for default credentials.

## Hardcoded Credentials

Never hardcode API keys, tokens, passwords, or credentials in source code. This includes:
- Strings that look like API keys in source files
- Connection strings with embedded passwords
- Private keys or certificates in the repo

If a secret was ever committed to Git history, consider it compromised — deleting the file doesn't
remove it from history. The key must be rotated immediately. Run `gitleaks detect` to scan for
leaked secrets.

## Client-Side Environment Variable Prefixes

These prefixes cause env vars to be inlined into the client bundle at build time. Everything in
the bundle is visible to anyone:

| Framework | Client Prefix | Danger |
|-----------|--------------|--------|
| Next.js | `NEXT_PUBLIC_` | Inlined into browser JS at build time |
| Vite | `VITE_` | Inlined into browser JS at build time |
| Expo / React Native | `EXPO_PUBLIC_` | Baked into the app bundle |
| Create React App | `REACT_APP_` | Inlined into browser JS at build time |

**What belongs client-side:**
- Stripe publishable key (`pk_live_*`, `pk_test_*`)
- Supabase anon / publishable key (RLS still governs access)
- Firebase client config (apiKey, authDomain, projectId)
- Public analytics IDs

**What must NEVER be client-side:**
- Supabase `service_role` / secret key (bypasses all RLS)
- Stripe secret key (`sk_live_*`, `sk_test_*`)
- Any database connection string
- Any third-party API secret key
- JWT signing secrets
- OAuth client secrets

## .gitignore

Ensure `.env`, `.env.local`, `.env.*.local`, and any file containing secrets is in `.gitignore`
**before the first commit**. Check that `.env.example` or `.env.sample` files contain only
placeholder values, not real keys.

## Detection Tips

When auditing, search for:
- Files named `.env` that are tracked by git (`git ls-files | grep .env`)
- Strings matching common key patterns: `sk_live_`, `sk_test_`, `AKIA`, `ghp_`, `glpat-`, `xoxb-`, `Bearer `
- `process.env.NEXT_PUBLIC_` or `import.meta.env.VITE_` referencing anything with "secret", "private", "service", or "key" in the name
- Hardcoded URLs containing credentials (e.g., `postgresql://user:password@host`)

## Common AI-Generated Default Credentials

AI code generation tools consistently produce applications with hardcoded default credentials.
These are functional in production and enable trivial account takeover.

Search for these patterns in your codebase:
```bash
grep -rn "password123\|admin123\|@example\.com\|@test\.com\|@admin\.com\|changeme\|supersecret\|keyboard.cat\|your-secret-key" --include="*.ts" --include="*.js" --include="*.tsx" --include="*.sql" --include="*.env*"
```

Common offenders:
- `user@example.com` / `password123` — login and seed data
- `admin@admin.com` / `admin` — admin panels
- JWT secrets: `"secret"`, `"jwt-secret"`, `"your-secret-key"`, `"supersecret"`, `"changeme"`

If any of these are present in production code or seed data that runs in production, flag as
**High** severity. See also `secaudit:supply-chain` for the full default-credentials list.

## Supabase New Key Model (2025+)

Supabase is replacing the legacy JWT `anon` / `service_role` keys with two new formats:

- **Publishable key** (`sb_publishable_...`) — low-privilege, **safe to expose** in the client.
  Maps to the Postgres `anon`/`authenticated` role, so access is **still governed by RLS**.
- **Secret key** (`sb_secret_...`) — backend-only, elevated. Maps to `service_role`, which carries
  `BYPASSRLS` (RLS does not apply). Individually revocable/rotatable; multiple can coexist.

Timeline: legacy keys keep working with no action required until **Nov 1, 2025**; new projects
after that date no longer get `anon`/`service_role`; legacy keys deprecated by end of 2026.
Supabase now rejects secret keys sent from a browser User-Agent and auto-revokes secret keys found
in public GitHub repos — but neither stops an attacker using a leaked key via curl. Same rule
stands: publishable keys go client-side, secret keys stay server-side only. See
`secaudit:database`.

## Sources

- https://nextjs.org/docs/app/guides/environment-variables -- NEXT_PUBLIC_ inlined into the client bundle
- https://vite.dev/guide/env-and-mode -- VITE_ vars bundled at build time
- https://docs.expo.dev/guides/environment-variables/ -- EXPO_PUBLIC_ embedded in plain text
- https://supabase.com/docs/guides/api/api-keys -- Supabase publishable vs secret key model
