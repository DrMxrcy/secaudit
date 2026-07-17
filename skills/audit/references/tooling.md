# Automated Security Tooling

After a manual audit, recommend these tools based on the project's stack. Prioritize by what the developer can run immediately with no setup.

## Universal (Every Project)

| Tool | What it does | How to run |
|------|-------------|------------|
| `gitleaks` | Scans git history for leaked secrets | `npx gitleaks detect` or `brew install gitleaks && gitleaks detect` |
| `npm audit` | Checks dependencies for known CVEs (live data) | `npm audit` (built into npm) |
| `osv-scanner` | Scans the lockfile against the live OSV.dev advisory DB (npm, PyPI, crates.io, Go); catches CVEs disclosed after any static list | `brew install osv-scanner` then `osv-scanner scan source --lockfile <lockfile>` |
| `git ls-files \| grep -i env` | Checks if .env files are tracked by git | Run from project root |

## Supabase Projects

| Tool | What it does | How to access |
|------|-------------|--------------|
| Security Advisor | Scans for RLS misconfigurations, weak policies | Supabase Dashboard → Security Advisor |
| Supabase MCP | Run security advisor from Claude Code | Via Supabase MCP connector (read-only where possible) |
| SupaExplorer | Free RLS audit via OAuth | supaexplorer.com |
| `supabase db lint` | Lint database for common issues | Supabase CLI |

## Convex Projects

| Tool | What it does | How to run |
|------|-------------|------------|
| `@convex-dev/eslint-plugin` | Flags missing argument validators and unindexed `.filter()` table scans | Enable `require-argument-validators` and `no-filter-in-query` rules |
| Manual function audit | Confirm every public `query`/`mutation`/`action`/`httpAction` has auth + validators | `grep -rn "mutation(\|query(\|action(\|httpAction(" convex/` |

## Next.js Projects

| Tool | What it does | How to run |
|------|-------------|------------|
| `/security-review` | Built-in Claude Code security audit | Run in Claude Code from project root |
| `npx next info` | Shows Next.js version and environment | Check version against known CVEs |
| Security headers check | Verify CSP, HSTS, X-Frame-Options | securityheaders.com or `curl -I your-site.com` |

## Expo / React Native Projects

| Check | What to verify | How |
|-------|---------------|-----|
| Bundle secret scan | No secrets in the JS bundle | Search source/`.env` for `EXPO_PUBLIC_*(KEY\|SECRET\|TOKEN)`, `sk_live`, `sk-` |
| Secure storage | Tokens in Keychain/Keystore, not AsyncStorage | `grep -rn "AsyncStorage.setItem" --include="*.ts*"` |
| OTA code signing | Updates are signed | `updates` block in app config includes `codeSigningCertificate` |

## Vercel-Deployed Projects

| Check | What to verify | How |
|-------|---------------|-----|
| Environment variables | Preview deploys don't use production keys | Vercel Dashboard → Settings → Environment Variables |
| Preview protection | Preview URLs require auth | Vercel Dashboard → Settings → Deployment Protection |
| Source maps | Not exposed in production | Check browser DevTools → Sources for `.map` files |

## CI/CD Integration

For ongoing protection, add these to your CI pipeline:

```yaml
# GitHub Actions example
- name: Security checks
  run: |
    npm audit --audit-level=high
    npx gitleaks detect --source=. --no-git
```

## When to Use Which

- **Before every deploy:** `npm audit`, `gitleaks detect`, check framework version
- **After adding AI-generated code:** Verify all new packages in `package.json` exist and are legitimate
- **Weekly:** Run Supabase Security Advisor, check security headers
- **After any auth changes:** Manual review of Server Actions + RLS policies
