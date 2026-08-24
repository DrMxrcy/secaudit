---
name: python-web-security
description: Audits Python web backends for framework-shaped security gaps — FastAPI routes leaking full ORM rows because no response_model is declared, per-route auth dependencies silently missing on one endpoint, identity taken from a path/body parameter instead of the session, Django production settings (DEBUG, ALLOWED_HOSTS, SECRET_KEY) including the ALLOWED_HOSTS=['*'] case that `manage.py check --deploy` does NOT catch, and requests calls with verify=False disabling TLS verification. Use whenever the project has pyproject.toml, requirements.txt, manage.py, or a FastAPI/Django/Flask app, or when reviewing Python route handlers, settings modules, or outbound HTTP calls.
license: MIT
---

# Python Web Security

Python web frameworks fail differently from the JS/TS stacks the rest of this plugin covers. The
bugs here are not language-level sinks — they are **shape** bugs: a serializer that ships every
column because you never told it what to ship, a guard bolted onto each route so one route can miss
it, a settings module that is safe in dev and catastrophic in prod. Each section below was verified
by running it (Python 3.12, FastAPI, SQLAlchemy 2.0, Pydantic 2, Django 6.1, requests).

> **Scope.** Language-level Python sinks live in sibling skills: `pickle`/`yaml.load`,
> `eval`/`exec`, `subprocess(shell=True)` → `secaudit:logging-monitoring`; SQLAlchemy `text()` and
> Pydantic mass assignment → `secaudit:data-access`; PyPI pinning, hallucinated packages, and
> `setup.py` install hooks → `secaudit:supply-chain`. This skill covers what the *framework* gets
> wrong.

## When to Use

- The repo has `pyproject.toml`, `requirements.txt`, `manage.py`, or a `main.py` containing
  `FastAPI(`.
- Writing or reviewing FastAPI/Flask route handlers, dependencies, or response models.
- Reviewing a Django `settings.py` (or any `settings/*.py`) before it reaches production.
- Auditing outbound HTTP calls made with `requests`, `httpx`, or `urllib3`.

## 1. FastAPI Responses Leaking ORM Fields (no `response_model`)

FastAPI serializes **whatever you return**. Return a SQLAlchemy ORM object from a route with no
`response_model` and no return annotation, and every mapped column goes out over the wire —
password hashes, billing IDs, internal flags, soft-delete markers. The route looks correct, the
tests pass, and the leak is invisible until someone reads the JSON.

```python
# BAD — returns the ORM row; every column is serialized
@app.get("/users/{user_id}")
async def get_user(user_id: int, db: Session = Depends(get_db)):
    return db.get(User, user_id)

# Verified actual response body:
# {"hashed_password":"$argon2id$...","email":"a@x.com","id":1,"stripe_customer_id":"cus_123"}
```

```python
# GOOD — an explicit output schema is an allowlist
class UserOut(BaseModel):
    id: int
    email: EmailStr
    model_config = ConfigDict(from_attributes=True)

@app.get("/users/{user_id}", response_model=UserOut)
async def get_user(user_id: int, db: Session = Depends(get_db)):
    return db.get(User, user_id)

# Verified actual response body: {"id":1,"email":"a@x.com"}
```

Annotating the return type (`async def get_user(...) -> UserOut:`) has the same effect — FastAPI
reads the annotation. Use the documented **separate-models** pattern: `UserIn` (accepts a plaintext
password), `UserOut` (never has one), `UserInDB` (has `hashed_password`, never leaves the server).
Three models is not ceremony; it is the only version where the leak is structurally impossible.

**`response_model_exclude` is a denylist and fails open.** Excluding `{"hashed_password"}`
protects exactly the fields you remembered — add a column next quarter and it ships. Worse, the
OpenAPI schema still advertises the full model, so `/docs` documents the fields you meant to hide.
Always prefer an explicit output model over subtractive filtering.

```bash
# Route decorators with neither response_model nor a return annotation
grep -rnE '@(app|router)\.(get|post|put|patch|delete)\(' --include='*.py' . \
  | grep -v 'response_model'
# ...then check each match's `def` line for a `-> Model:` annotation.

# Pydantic models built straight off ORM rows (candidates for over-broad output)
grep -rnE 'from_attributes\s*=\s*True|orm_mode\s*=\s*True' --include='*.py' .
```

## 2. Per-Route Auth Dependency, Silently Missing on One Route

The classic partial-coverage failure. When the guard is applied per-decorator, coverage is a human
habit rather than a property of the code — one forgotten route is fully public and **nothing errors,
nothing warns, no test fails**. This is `A01:2025` (Broken Access Control) in its purest form.

```python
# BAD — the GET is guarded, the DELETE was forgotten
@router.get("/admin/users", dependencies=[Depends(require_admin)])
async def list_users(): ...

@router.delete("/admin/users/{user_id}")           # <-- no guard
async def delete_user(user_id: int): ...
# Verified: DELETE /admin/users/1 with no credentials returned 200.
```

```python
# GOOD — the guard is a property of the router, not of each decorator
router = APIRouter(prefix="/admin", dependencies=[Depends(require_admin)])

@router.get("/users")
async def list_users(): ...

@router.delete("/users/{user_id}")                  # inherits the guard; cannot be forgotten
async def delete_user(user_id: int): ...
# Verified: the same unauthenticated DELETE now returns 403.
```

`FastAPI(dependencies=[Depends(...)])` applies app-wide, covering every route including those in
included sub-routers — use it for a baseline (authenticated-by-default) and open specific routes
explicitly. `Security(...)` is `Depends(...)` plus OAuth2 scopes, so scoped checks compose the same
way at router level.

This is the plugin's recurring thesis, restated in Python: **put the check where it cannot be
omitted.** Same failure as an unguarded Convex mutation (`secaudit:convex-security`) or trusting a
Next.js middleware pass (`secaudit:auth`, `secaudit:framework-versions`) — a guard that must be
remembered per call site will eventually not be.

```bash
# Count route decorators vs. route decorators carrying a dependency, then diff the sets
grep -rnE '@(app|router)\.(get|post|put|patch|delete)\(' --include='*.py' . | wc -l
grep -rnE '@(app|router)\.(get|post|put|patch|delete)\(.*dependencies=\[' --include='*.py' . | wc -l
# And find routers/apps declaring a baseline guard at construction:
grep -rnE '(APIRouter|FastAPI)\(.*dependencies=\[' --include='*.py' .
```

## 3. Identity From a Path or Body Parameter Instead of the Session

Distinct from section 2: here **authentication is present and authorization is absent.** The caller
is a real logged-in user; they just pass someone else's ID. Any parameter is attacker-controlled, so
`user_id` in a path, query string, or JSON body is a request, never an identity.

```python
# BAD — authenticated, but the record returned is whichever one you ask for
@app.get("/users/{user_id}")
async def read_user(user_id: int, _=Depends(require_login), db=Depends(get_db)):
    return db.get(User, user_id)
# Verified: user 1 requested /users/2 and received user 2's record with 200.
```

```python
# GOOD — identity comes from the dependency; the parameter is only a claim to check
@app.get("/users/{user_id}", response_model=UserOut)
async def read_user(user_id: int, me: int = Depends(current_user_id), db=Depends(get_db)):
    if user_id != me:
        raise HTTPException(status_code=403, detail="Forbidden")
    return db.get(User, user_id)
# Verified: the same cross-user request now returns 403.
```

Better still, drop the parameter — `GET /users/me`, resolving entirely from
`Depends(current_user_id)`, has no ID to tamper with. Where the resource is not the user (a
document, an invoice), scope the query itself:
`select(Doc).where(Doc.id == doc_id, Doc.owner_id == me)` so a miss is a 404 rather than a leak.
This is IDOR — see `secaudit:web-vulns` for the general pattern and
`secaudit:privilege-escalation` for the role-bearing variant.

```bash
# Handlers taking an identity-shaped parameter
grep -rnE 'def .*\((.*\b(user_id|owner_id|account_id|org_id|customer_id)\b)' --include='*.py' .
# For each hit, confirm an ownership comparison exists against the dependency-derived identity
grep -rnE 'current_user|get_current_user|current_user_id' --include='*.py' .
```

## 4. Django Production Settings

Three settings decide whether a Django deployment is a web app or a disclosure incident: `DEBUG`,
`ALLOWED_HOSTS`, and `SECRET_KEY`. `DEBUG=True` renders a traceback page containing settings,
environment, and SQL for any unhandled error. A committed `SECRET_KEY` lets anyone forge session
cookies, password-reset tokens, and signed data. `ALLOWED_HOSTS=['*']` accepts any `Host` header,
enabling host-header poisoning — password-reset emails whose links point at the attacker's domain,
and poisoned cache keys. This is `A02:2025` (Security Misconfiguration).

```python
# BAD — settings.py as committed
DEBUG = True
ALLOWED_HOSTS = ['*']
SECRET_KEY = 'django-insecure-8f3k...'         # in git, therefore already compromised
```

```python
# GOOD — every value from the environment, missing secret fails closed
import os

DEBUG = os.environ.get("DJANGO_DEBUG", "") == "1"
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]   # KeyError at boot beats a weak default
ALLOWED_HOSTS = os.environ["DJANGO_ALLOWED_HOSTS"].split(",")   # "example.com,www.example.com"

CSRF_TRUSTED_ORIGINS = ["https://example.com", "https://www.example.com"]
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
```

Use `os.environ["KEY"]`, not `os.environ.get("KEY", "fallback")`. A default turns a missing-secret
misconfiguration into a *silent* one: the app boots with a known key and keeps serving.

**Django's own checker does not cover this — verified.** `python manage.py check --deploy` on Django
6.1 does flag `DEBUG=True` (`security.W018`) and the auto-generated key (`security.W009` — it
detects the `django-insecure-` prefix). It does **not** flag `ALLOWED_HOSTS=['*']`. Run with
`DEBUG=False`, a strong key, full security middleware, and `ALLOWED_HOSTS=['*']`, the output was:

```
System check identified no issues (0 silenced).
```

So host-header poisoning passes Django's deployment checker in total silence. `check --deploy` is a
useful first pass, never a sign-off — **the grep is mandatory**.

```bash
python manage.py check --deploy          # necessary, not sufficient — misses ALLOWED_HOSTS=['*']

grep -rnE "^\s*DEBUG\s*=\s*True" --include='*.py' .
grep -rnE "ALLOWED_HOSTS\s*=.*['\"]\*['\"]" --include='*.py' .
grep -rnE "SECRET_KEY\s*=\s*['\"]" --include='*.py' .   # a literal, not os.environ[...]
```

A `SECRET_KEY` found in git history is compromised even after the commit that removes it — rotate
it, and read the redaction rule in `secaudit:secrets` before quoting anything you find. For headers,
HSTS, and environment separation across deploy targets, see `secaudit:deployment`.

## 5. `requests` With `verify=False`

`verify=False` disables certificate verification for that call. Every request it guards can be
intercepted and modified by anyone on the network path — including the ones carrying your API keys,
OAuth tokens, and webhook payloads. It is usually added to silence a TLS error during local
development and then committed.

```python
# BAD — no certificate validation; full MITM exposure
r = requests.get("https://internal.example.com/api", verify=False,
                 headers={"Authorization": f"Bearer {token}"})
# Verified: against a host with an EXPIRED certificate this returned HTTP 200,
# emitting only an InsecureRequestWarning — which most apps never surface.
# With `verify` left at its default, the same host raised SSLError.
```

```python
# GOOD — default verification, explicit timeout
r = requests.get("https://api.example.com/v1/thing",
                 headers={"Authorization": f"Bearer {token}"}, timeout=10)

# GOOD — internal CA: trust it explicitly instead of trusting nothing
r = requests.get("https://internal.example.com/api",
                 verify="/etc/ssl/certs/internal-ca.pem", timeout=10)
```

Two related tells. `urllib3.disable_warnings(...)` means someone silenced the symptom rather than
fixing the cause — wherever you find it, `verify=False` is nearby. And at the stdlib level,
`ssl._create_unverified_context()` or `ctx.check_hostname = False` / `ctx.verify_mode = CERT_NONE`
disable the same protection for `urllib`, `smtplib`, and anything else built on `ssl`.

Always pass a `timeout=` — `requests` has **no default timeout**, so a hung upstream pins a worker
indefinitely (a DoS you inflict on yourself). For TLS configuration and certificate handling
generally, see `secaudit:cryptography`; if the URL being fetched is user-supplied, that is SSRF —
see `secaudit:web-vulns`.

```bash
grep -rnE 'verify\s*=\s*False' --include='*.py' .
grep -rnE 'disable_warnings|InsecureRequestWarning' --include='*.py' .
grep -rnE '_create_unverified_context|check_hostname\s*=\s*False|CERT_NONE' --include='*.py' .
grep -rnE 'requests\.(get|post|put|patch|delete)\(' --include='*.py' . | grep -v 'timeout'
```

## Detection Quick Pass

Stack markers that should trigger this skill: `pyproject.toml`, `requirements.txt`, `manage.py`,
`settings.py`, or a `main.py` containing `FastAPI(`.

```bash
# --- Django settings (section 4) — check --deploy misses ALLOWED_HOSTS=['*'] ---
grep -rnE "^\s*DEBUG\s*=\s*True|ALLOWED_HOSTS\s*=.*['\"]\*['\"]|SECRET_KEY\s*=\s*['\"]" \
  --include='*.py' .

# --- Routes with no output schema (section 1) ---
grep -rnE '@(app|router)\.(get|post|put|patch|delete)\(' --include='*.py' . | grep -v response_model

# --- Auth coverage: every route vs. routes/routers carrying a guard (sections 2-3) ---
grep -rncE '@(app|router)\.(get|post|put|patch|delete)\(' --include='*.py' .
grep -rnE '(APIRouter|FastAPI)\(.*dependencies=\[|dependencies=\[Depends\(|Security\(' \
  --include='*.py' .
grep -rnE 'def .*\b(user_id|owner_id|account_id|org_id)\b' --include='*.py' .

# --- TLS verification disabled (section 5) ---
grep -rnE 'verify\s*=\s*False|disable_warnings|_create_unverified_context|CERT_NONE' \
  --include='*.py' .

# --- Cross-referenced sinks (covered in sibling skills, still worth surfacing here) ---
grep -rnE '\b(pickle|yaml)\.(load|loads)\(|\beval\(|\bexec\(|shell\s*=\s*True' --include='*.py' .
```

Findings from that last block route to `secaudit:logging-monitoring` (deserialization, code and
command injection) and `secaudit:data-access` (SQLAlchemy `text()`, Pydantic mass assignment).
Dependency hygiene for `requirements.txt` / `pyproject.toml` — pinning, lock files, hallucinated
packages, `pip-audit` — belongs to `secaudit:supply-chain`.

## Sources

- https://fastapi.tiangolo.com/tutorial/response-model/ -- response_model as an output allowlist
- https://fastapi.tiangolo.com/tutorial/extra-models/ -- UserIn / UserOut / UserInDB separate models
- https://fastapi.tiangolo.com/tutorial/bigger-applications/ -- router-level and app-level dependencies
- https://fastapi.tiangolo.com/reference/dependencies/ -- Depends and Security reference
- https://docs.djangoproject.com/en/6.0/howto/deployment/checklist/ -- DEBUG, ALLOWED_HOSTS, SECRET_KEY, cookies
- https://docs.djangoproject.com/en/6.0/ref/checks/ -- what `check --deploy` does (and does not) cover
- https://requests.readthedocs.io/en/latest/user/advanced/ -- SSL verification, custom CA bundles
- https://cheatsheetseries.owasp.org/cheatsheets/Django_Security_Cheat_Sheet.html -- Django hardening checklist
- https://owasp.org/Top10/2025/ -- A01:2025 Broken Access Control, A02:2025 Security Misconfiguration
