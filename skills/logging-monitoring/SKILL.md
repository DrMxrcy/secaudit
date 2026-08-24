---
name: logging-monitoring
description: Audits logging, monitoring, and integrity failures (OWASP A09/A08/A05:2025) - error responses leaking stack traces and internals, secrets or PII written to logs and crash reporters, missing audit logging and alerting for security events, insecure deserialization of untrusted data, and command/code injection via shell-exec or dynamic-eval. Covers both JS/TS and Python (pickle, PyYAML, jsonpickle, shell=True, eval/exec). Use when writing error handlers, logging, deserializing untrusted data, or running subprocesses, or when auditing observability and incident readiness.
license: MIT
---

# Logging, Monitoring & Integrity (OWASP A09 / A08 / A05, 2025 edition)

## When to Use

- Writing error handlers or returning error responses to clients.
- Adding logging, or configuring crash/APM reporters (Sentry, Datadog).
- Auditing whether security events are logged and alerted on.
- Deserializing untrusted data, or running subprocesses / dynamic code from input.

## 1. Error Responses Leaking Internals

**What to look for:** returning `err.stack`/`err.message`/the raw error to clients, no centralized error
handler, framework debug mode on in production (`NODE_ENV` not `production`), raw DB driver errors or
file paths in API responses.

**Why it's exploitable:** stack traces, SQL errors, versions, and file paths are reconnaissance gold -
they reveal the stack, schema, and internals, helping attackers craft targeted attacks. SQL error text
often directly confirms an injection point.

```ts
// src/middleware/error.ts — BEFORE: leaks stack + internals to the client
app.use((err, req, res, next) => res.status(500).json({ error: err.message, stack: err.stack }));

// AFTER: generic message to client, full detail logged server-side with a correlation id
app.use((err, req, res, next) => {
  const id = crypto.randomUUID();
  logger.error({ id, message: err.message, stack: err.stack, path: req.path });
  res.status(500).json({ error: "Internal error", reference: id });
});
// + set NODE_ENV=production so the framework disables verbose error pages
```

## 2. Secrets / PII in Logs and Crash Reporters

**What to look for:** logging full request/response objects, `Authorization` headers, cookies, JWTs,
passwords, card numbers, or connection strings; crash/APM reporters capturing request bodies without
scrubbing.

**Why it's exploitable:** logs are widely accessible (aggregators, support staff, third-party SaaS,
backups) and long-lived. A token or password in logs is a credential leak; card numbers/PII is a
PCI/GDPR violation. Crash reporters silently ship this off-site.

Never log: passwords, session/access tokens, secrets/keys, card and bank numbers, connection strings,
or non-consented PII. Redact via deletion/masking; hash session IDs if you must correlate.

```ts
// src/logger.ts — AFTER: pino with redaction
import pino from "pino";
export const logger = pino({
  redact: { paths: ["req.headers.authorization", "req.headers.cookie", "*.password", "*.token",
                    "*.cardNumber", "*.ssn"], censor: "[REDACTED]" },
});
// Also configure the crash reporter's scrubbing to strip body + auth headers.
```

See `secaudit:secrets` and `secaudit:react-native-security` (mobile log/crash leaks).

## 3. Missing Audit Logging + Alerting

**What to look for:** no logs around login success/failure, logout, password/email/MFA changes; no
logging of access-control denials, role/permission changes, admin actions, or payments; no alerting on
bursts of failed logins or 403s.

**Why it's exploitable:** A09 (Security Logging and Alerting Failures) is about blindness - without these logs you can't detect credential
stuffing, privilege escalation, or fraud, and breaches go undetected for months. No alerting means even
logged attacks are never seen.

Must-log events (OWASP): auth successes and failures; authorization failures; input-validation
failures; account/privilege changes; access to sensitive data; crypto key use; and high-value business
actions (payments). Add tamper-evidence (append-only / read-only store), synchronized timestamps, and
alerting.

```ts
// src/auth/login.ts — AFTER: structured security event + signal for alerting
if (!ok) {
  logger.warn({ event: "auth.login.failure", userId: user?.id ?? null, ip: req.ip, ts: Date.now() });
  metrics.increment("auth.login.failure");   // dashboards alert on spikes (e.g. > N/min/IP)
  return res.status(401).send("Invalid credentials");
}
logger.info({ event: "auth.login.success", userId: user.id, ip: req.ip });
```

## 4. Insecure Deserialization (A08:2025)

**What to look for:** libraries that reconstruct functions/objects from untrusted input
(`node-serialize`'s `unserialize`, `funcster`), eval-based "parsing", deserializing
cookies/JWT payloads/query params into live objects, or legacy `js-yaml.load` on untrusted YAML.

**Why it's exploitable:** `node-serialize`'s `unserialize()` executes an embedded function tagged
`_$$ND_FUNC$$_`, so attacker-controlled serialized data yields remote code execution (CVE-2017-5941).
Any deserializer that can instantiate code/types from untrusted bytes is an RCE primitive. JSON has no
such semantics.

```ts
// src/session.ts — BEFORE: RCE via a code-reconstructing deserializer
import { unserialize } from "node-serialize";
const session = unserialize(req.cookies.session);   // attacker payload runs code

// AFTER: plain JSON, integrity-checked, schema-validated
const raw = verifyHmac(req.cookies.session, process.env.COOKIE_KEY!); // reject if tampered
const session = SessionSchema.parse(JSON.parse(raw));                 // no code execution
```

Prefer pure-data formats (JSON); only deserialize signed/HMAC'd payloads; validate against a schema.

### Python: `pickle`, `PyYAML`, `jsonpickle`

Same threat model, different names — and Python's are worse, because `pickle` is the *idiomatic*
serializer for caches, queues, and `.pkl` model files, so untrusted bytes reach it easily.

```python
# BAD — every one of these executes attacker-supplied code
session = pickle.loads(request.cookies["session"])      # __reduce__ runs os.system
config  = yaml.load(body, Loader=yaml.UnsafeLoader)     # !!python/object/apply:os.system
obj     = jsonpickle.decode(body)                       # py/reduce runs os.system

# GOOD — pure data, integrity-checked, schema-validated
raw     = verify_hmac(request.cookies["session"], SESSION_KEY)
session = SessionModel.model_validate_json(raw)         # Pydantic; no code execution
config  = yaml.safe_load(body)                          # ConstructorError on py/object tags
```

Three details that change what you grep for, each verified by execution:

- **`yaml.safe_load` and `Loader=yaml.FullLoader` both block** the `!!python/object/apply`
  payload (`ConstructorError`). Only `Loader=yaml.Loader` and `Loader=yaml.UnsafeLoader` execute
  it — so "`yaml.load` is dangerous" is too blunt a rule to grep on.
- **Bare `yaml.load(data)` is a `TypeError` in PyYAML ≥ 6** — `Loader` is a required positional
  argument. The classic advice is stale; the live danger is an explicit unsafe `Loader=`.
- **`jsonpickle.decode(..., safe=True)` does NOT make jsonpickle safe.** A `py/reduce` payload
  executes under `safe=False`, `safe=True`, *and* the default. The flag's name actively misleads.

Detection: `grep -rn "pickle.load\|pickle.loads\|jsonpickle.decode\|yaml.unsafe_load\|Loader=yaml\.\(Unsafe\)\?Loader\|shelve.open\|dill.load" --include="*.py"`

## 5. Command / Code Injection (A05:2025)

**What to look for:** building a shell command string from user input and running it through a shell;
dynamic code execution (`eval`, `new Function`, `vm.runInNewContext`, string `setTimeout`) on input;
constructing ffmpeg/imagemagick/git command strings from request data.

**Why it's exploitable:** shell-exec runs the string through `/bin/sh`, so metacharacters
(`; | & $()`) let an attacker append commands and reach RCE. Dynamic-eval runs arbitrary attacker JS
in-process. The fix is to separate the command from its arguments so the shell never parses user data.

```ts
// src/convert.ts — BEFORE: shell injection ("a.jpg; rm -rf /" -> RCE)
import { exec } from "node:child_process";
exec(`convert ${req.query.file} out.png`);

// AFTER: pass args as an array, no shell, with an allowlist
import { execFile } from "node:child_process";
if (!/^[\w.-]+$/.test(String(req.query.file))) throw new Error("bad filename");
execFile("convert", [String(req.query.file), "out.png"], { shell: false }, cb);
```

For dynamic logic, never eval user input - use a lookup map or a sandboxed expression library with an
allowlist. Run with least privilege. See `secaudit:data-access` for SQL/ORM injection.

### Python: `shell=True`, `eval`, `exec`

The single most common Python sink an AI assistant generates for "run the user's formula" or
"convert this file". Verified by execution: `shell=True` ran the appended command, while the argv
form passed `report.txt; echo PWNED` through as one literal argument.

```python
# BAD
subprocess.run(f"ffmpeg -i {filename} out.mp4", shell=True)   # "a.mp4; curl evil|sh"
result = eval(request.json["expression"])                      # __import__('os').system(...)

# GOOD — argv list, no shell; literal_eval for data
subprocess.run(["ffmpeg", "-i", filename, "out.mp4"], shell=False, check=True)
result = ast.literal_eval(request.json["expression"])          # ValueError on __import__
```

`subprocess.run` already defaults to `shell=False`, so **`shell=True` is always a deliberate,
greppable choice** — which makes this one of the highest-signal greps in a Python codebase.

Detection: `grep -rn "shell=True\|os.system(\|os.popen(\|\beval(\|\bexec(" --include="*.py"`

## Sources

- https://docs.python.org/3/library/pickle.html -- stdlib warning: not secure against maliciously constructed data
- https://pyyaml.org/wiki/PyYAMLDocumentation -- loader classes and safe_load
- https://github.com/jsonpickle/jsonpickle/issues/178 -- safe=True does not prevent py/reduce execution
- https://docs.python.org/3/library/subprocess.html -- shell=True security considerations
- https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html -- Python deserialization
- https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html -- what to log, what to exclude
- https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html -- safe error responses
- https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/ -- OWASP A09:2025 overview
- https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html -- insecure deserialization
- https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/ -- OWASP A08:2025 overview
- https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html -- command injection defense
- https://nodejs.org/api/child_process.html -- execFile/spawn (args as array, no shell)
