---
name: php-security
description: Audits PHP apps — the PHP runtime first (PHP2Shell, CVE-2026-109618 / CVE-2026-109619, unauthenticated RCE in PHP core, fixed 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35, nothing for EOL 8.1 and older; how to read the version that actually serves requests from php -v, composer.json, Docker php:<tag>, distro packages and X-Powered-By), then the PHP sinks AI assistants leave in — unserialize() on input, include/require with user paths, eval/assert/preg_replace /e, shell exec without escapeshellarg, PDO with interpolated SQL, display_errors/expose_php in production, .env/vendor/composer.json and uploaded .php files under the web root, Laravel APP_DEBUG/APP_KEY/Ignition/unguarded models, WordPress plugin supply chain, and Composer hygiene. Use whenever the project has composer.json, *.php files, a php:<tag> Docker base, wp-config.php or artisan, or when reviewing PHP code or a PHP server's configuration.
license: MIT
---

# PHP Security

PHP apps fail at two layers. The **runtime** itself can be the vulnerability: PHP2Shell gets code
execution before a single line of application code runs, so no review of the app catches it.
Below that, PHP keeps the sinks other stacks removed or hid — native object deserialization,
`include` of a runtime path, `eval`, a shell one call away — and AI-generated PHP reaches for them
because the training data is full of them. Each behavior marked *verified* below was run on PHP
8.4.27 in the official `php:8.4-cli` and `php:8.4-apache` images.

> **Scope.** This skill covers what is PHP-specific. General patterns live in siblings:
> SQL injection and mass assignment in depth → `secaudit:data-access`; deserialization and command
> injection across languages → `secaudit:logging-monitoring`; upload validation, path traversal and
> SSRF → `secaudit:web-vulns`; dependency trust, lock files and compromised packages →
> `secaudit:supply-chain`; headers and `.git` exposure → `secaudit:deployment`; `APP_KEY` and
> `.env` handling and redaction → `secaudit:secrets`; base images → `secaudit:docker-security`.
> The cross-stack version floor list is `secaudit:framework-versions`.

## When to Use

- The repo has `composer.json`, `*.php` files, `artisan` (Laravel), `wp-config.php` / `wp-content/`
  (WordPress), or a Dockerfile `FROM php:<tag>`.
- Any server, container or appliance in scope runs PHP, even if the main app does not.
- Reviewing PHP controllers, templates, upload handlers, `php.ini` / FPM pool / Apache config.

## 1. The Runtime: PHP2Shell (CVE-2026-109618, CVE-2026-109619)

Two unauthenticated remote code execution bugs in PHP core, published by the PHP project on
2026-10-21 and scored CVSS 4.0 9.2 each (CSA AL-2026-151). `CVE-2026-109618` is out-of-memory
handling that leaves request data half-initialized; `CVE-2026-109619` is request state that
survives after its memory is freed and is reused by the next request on the same worker (php.net).

- **Who is exposed:** php.net's news post names every PHP installation serving web requests —
  PHP-FPM, Apache `mod_php`, php-cgi, FrankenPHP and LiteSpeed — and rates `mod_php` highest. The
  two GitHub advisories are more precise about what was actually shown. RCE is **confirmed on
  `mod_php`**, where the OOM bug fires **before any application code runs**, so app code and
  framework middleware are not in the path. For the OOM bug, FPM is susceptible by source analysis
  but no complete FPM exploit was demonstrated, and FrankenPHP and LSAPI are likely susceptible but
  not validated (GHSA-w8hw-w9fx-j79w). The stale-state bug's session-upload-progress path was
  validated against both `mod_php` and FPM (GHSA-6wmf-4rv5-p3rp). Patch every SAPI. SANS rates the
  workarounds and WAF rules as not fully effective.
- **Exploitation:** CSA reports widespread exploitation attempts and multiple proof-of-concept
  exploits. SANS ISC (2026-10-23): details leaked early ahead of the coordinated release, many
  partial exploits circulate (some parasitic — they attack whoever runs them), and the handler
  expects reliable public exploits soon. Not on CISA KEV as of the 2026-10-23 catalog
  (<https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>); re-check.
- **Floors:** PHP 8.5.12, 8.4.27, 8.3.36, 8.2.35 (php.net, 2026-10-21). Anything below on a
  supported branch is vulnerable — report it Critical, internet-facing first.
- **Known crash in 8.4.27 and 8.5.12 — not a reason to stay below the floor.** php-src issue
  #24488 reports a regression in those two releases: the garbage collector double-frees a
  `SimpleXMLElement`'s properties table, and the process dies with `zend_mm_heap corrupted`. It
  needs a `SimpleXMLElement` whose properties were read (`get_object_vars()`, an `(array)` cast,
  `json_encode()`) and that sits in a reference cycle the GC collects. Reporters hit it in test
  suites. The fix is commit `f963484`, which no release ships yet: php.net's archive lists none
  after 8.4.27 / 8.5.12 as of 2026-10-23. Reporters worked around it by pinning 8.4.26 or setting
  `zend.enable_gc=0`. **Do not pin 8.4.26**: it is PHP2Shell-vulnerable. Stay on the floor release,
  use the `zend.enable_gc=0` workaround only where the crash actually occurs, and track the next
  bugfix release. The issue is a bug tracker entry, not a security advisory.
- **EOL branches (8.1 and older):** no release from the PHP project. php.net published minimal
  source backports for 7.4, 8.0 and 8.1 for people who build from source; otherwise the answer is
  an upgrade to a supported branch, or a distro / LTS vendor backport that you **confirm in that
  vendor's tracker** — never assume one exists.
- **Appliances and bundled PHP:** NAS boxes, firewalls, admin consoles and control panels ship
  their own PHP and patch on their own schedule. SANS calls them a major concern. Tracker-reported
  only, not confirmed at the vendor: the pwn.watch tracker listed QNAP as still preparing fixes on
  2026-10-23. Check each vendor's own advisory and isolate the device until it is patched.

**If you cannot update today** (php.net — these reduce exposure, they do not make an install safe):

- `memory_limit=-1` set where the app cannot override it (`php_admin_value` in the FPM pool or
  Apache config), a low `post_max_size` (`8M` without uploads, `32M` with), and request-size,
  field-count and part-count limits at the proxy; a container/cgroup memory limit as the backstop.
  Do **not** substitute `RLIMIT_AS` or `RLIMIT_DATA` (`ulimit -v` / `ulimit -d`, systemd
  `LimitAS=` / `LimitDATA=`): php.net says these can cause the vulnerable allocation failure.
- `session.upload_progress.enabled=0` in `php.ini` or the pool config, then restart every worker.
  `ini_set()` and `.user.ini` apply too late and do not count.
- On 8.5, `fatal_error_backtraces=0`. Hiding errors (`display_errors`, `@`) does not help.

**Keep `session.upload_progress.enabled=0` after patching.** On 2026-10-23 php.net advised leaving
it off until the next regular bugfix release because of `CVE-2026-115560`, an RCE vector that is
**not yet fixed**. It needs an unusual setup — `session.serialize_handler` set to `php_binary` or
`php_serialize` in config, switched to `php` with `ini_set()` before `session_start()` — but upload
progress is on by default (verified), so check for it:

```bash
grep -rnE "ini_set\(\s*['\"]session\.serialize_handler" --include='*.php' .
grep -rnE 'session\.(upload_progress\.enabled|serialize_handler)' --include='*.ini' --include='*.conf' .
```

### Finding the version that actually serves requests

Every source below can disagree with the others. Report the one closest to the running process.

```bash
php -v                                   # the CLI binary — the web SAPI may be a different one
php-fpm -v 2>/dev/null; ls /usr/sbin/php-fpm* 2>/dev/null   # the FPM binary(ies) on the host
curl -sI https://target.example.com/ | grep -i x-powered-by   # PHP/8.4.27 when expose_php is on
grep -nE '"php"\s*:' composer.json        # require.php AND config.platform.php — intent, not runtime
grep -nE '^FROM\s+php:' Dockerfile* */Dockerfile* 2>/dev/null
dpkg -l 'php*' 2>/dev/null | grep -E '^ii'; rpm -qa 'php*' 2>/dev/null
```

- **`composer.json`:** `require.php` is the range the app accepts; `config.platform.php` *fakes*
  the platform for dependency resolution, so it says nothing about what is installed (Composer
  docs). Use both to learn the targeted branch, then check the server.
- **Docker `php:<tag>`:** the official floating tags (`8.4-apache`, `8.3-fpm`, …) now point at the
  fixed releases, but an image only picks that up when it is rebuilt with a fresh pull. A
  patch-pinned tag or digest built before 2026-10-21 is vulnerable. `-apache` variants run
  `mod_php` (verified: `php_module` loaded), the highest-risk configuration.
- **Distro packages keep the old version number.** Ubuntu 24.04 ships the PHP2Shell patch as
  `php8.3` `8.3.6-0ubuntu0.24.04.13` and Ubuntu 22.04 as `php8.1` `8.1.2-1ubuntu2.28`, so `php -v`
  prints `8.3.6` or `8.1.2` on a patched host. Compare the **package** version to the distro
  tracker (Debian, Ubuntu links below), never the `php -v` string to the php.net floors.
- **`X-Powered-By`:** `expose_php` defaults to `1`, and the bundled `php.ini-production` leaves it
  on (verified: `X-Powered-By: PHP/8.4.27` from a stock `php:8.4-apache`). Useful for inventory,
  then turn it off (section 7).

**EOL lines.** Query endoflife.date instead of trusting a table:

```bash
curl -s https://endoflife.date/api/php.json | python3 -c 'import json,sys
for c in json.load(sys.stdin)[:8]: print(c["cycle"], "eol", c["eol"], "latest", c["latest"])'
```

As of 2026-10-23 it lists 8.1 EOL on 2025-12-31 and 8.2 reaching EOL on 2026-12-31 — re-derive,
do not trust this line. An EOL branch outranks any single CVE: it gets no fixes at all.

> **These floors are not machine-policed.** OSV indexes packages, not the PHP runtime (none of the
> PHP2Shell CVEs resolve on OSV), so `scripts/check-freshness.py` cannot tell when 8.4.27 stops
> being enough. The authority is <https://www.php.net/archive/2026.php>; read it at audit time.
> Same treatment as the Node.js runtime note in `secaudit:framework-versions`.

## 2. `unserialize()` on Anything a User Can Touch

`unserialize()` instantiates objects, and their magic methods (`__wakeup`, `__destruct`,
`__toString`) run on attacker-chosen property values. Any class in the autoloader — including
every Composer package — is gadget material. Cookies, hidden fields, cache entries and queue
payloads all count as input.

```php
// BAD — a cookie becomes objects
$prefs = unserialize($_COOKIE['prefs']);
// Verified: a payload naming a class whose __destruct writes $this->data to $this->file
// wrote a PHP web shell to disk the moment the result went out of scope.
```

```php
// GOOD — data, not objects
$prefs = json_decode($_COOKIE['prefs'] ?? '{}', true, 8, JSON_THROW_ON_ERROR);
```

`['allowed_classes' => false]` blocked the verified gadget (the object came back as
`__PHP_Incomplete_Class`), but php.net says **do not pass untrusted input to `unserialize()`
regardless of `allowed_classes`**. Treat it as defense in depth for data you stored yourself, and
sign that data with `hash_hmac()` if it round-trips through the client.

```bash
grep -rnE '\bunserialize\s*\(' --include='*.php' . | grep -v 'allowed_classes'
grep -rnE 'unserialize\s*\(\s*(\$_(GET|POST|COOKIE|REQUEST)|base64_decode|file_get_contents)' --include='*.php' .
```

## 3. `include` / `require` With a User-Influenced Path

`include` executes whatever it loads. A request parameter in the path is local file inclusion at
best and code execution at worst.

```php
// BAD — ?page=../../../../etc/passwd, or a stream wrapper
include __DIR__ . '/pages/' . $_GET['page'] . '.php';
include $_GET['page'];
// Verified with allow_url_include=0 (the default): include of http://… failed, but
// include 'php://filter/convert.base64-encode/resource=/tmp/secret.php' returned the
// source of the file, secrets included. The default does not stop local wrappers.
```

```php
// GOOD — the request picks a key; the code owns the path
$pages = ['home' => 'home.php', 'about' => 'about.php'];
$page  = is_string($_GET['page'] ?? null) ? $_GET['page'] : 'home';   // ?page[]=x is an array
$file  = $pages[$page] ?? 'home.php';
require __DIR__ . '/pages/' . $file;
// Verified: without the is_string() guard, ?page[]=x threw an uncaught TypeError.
```

Keep `allow_url_include=0` (default `"0"`, deprecated since 7.4 — php.net). Combined with an
upload that lets an attacker place a file, LFI becomes RCE, so fix both (section 8).

```bash
grep -rnE '\b(include|require)(_once)?\b[^;]*\$' --include='*.php' .
grep -rniE 'allow_url_include\s*=\s*(1|On)' --include='*.ini' --include='*.conf' --include='.htaccess' .
```

## 4. `eval`, `assert`, `create_function`, `preg_replace` `/e`

`eval()` runs a string as PHP; php.net calls it very dangerous and discourages it. Three older
spellings of the same thing survive in legacy code and in answers copied from it: `assert()` with a
string argument (evaluated as code before PHP 8, removed in 8.0), `create_function()` (removed in
PHP 8) and `preg_replace()` with the `/e` modifier (removed in PHP 7). On a current runtime they
fail loudly; on an EOL one they still execute.

```php
// BAD
eval('$total = ' . $_POST['formula'] . ';');
$out = preg_replace('/\{(\w+)\}/e', '$vars["$1"]', $tpl);   // PHP 5 only, still in old code
```

```php
// GOOD — parse, don't execute; callbacks instead of code strings
$out = preg_replace_callback('/\{(\w+)\}/', fn($m) => htmlspecialchars($vars[$m[1]] ?? ''), $tpl);
```

```bash
grep -rnE '\b(eval|assert|create_function)\s*\(' --include='*.php' .
grep -rnE "preg_replace\s*\(\s*['\"]/.*/[a-zA-Z]*e[a-zA-Z]*['\"]" --include='*.php' .   # /-delimited only
```

## 5. Shell Execution: `system`, `exec`, `shell_exec`, `passthru`, `popen`, backticks

```php
// BAD — ?host=8.8.8.8;id
echo shell_exec("ping -c1 " . $_GET['host']);
// Verified: the unescaped value ran `id` and printed uid=0(root).
```

```php
// GOOD — validate, escape, and end option parsing
$host = filter_var($_GET['host'] ?? '', FILTER_VALIDATE_IP) ?: throw new InvalidArgumentException();
echo shell_exec('ping -c1 -- ' . escapeshellarg($host));
```

`escapeshellarg()` quotes one argument so the shell treats it as a single word. It does **not**
stop the program from reading that word as an option: `ls '--version'` still printed the `ls`
version (verified); `ls -- '--version'` treated it as a filename. Put `--` before user arguments
where the program supports it, validate against an allowlist, and prefer a PHP API over a shell
command when one exists. Backticks are `shell_exec()` — grep for them too.

```bash
grep -rnE '\b(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(' --include='*.php' .
grep -rnE '`[^`]*\$[^`]*`' --include='*.php' .
```

## 6. PDO / mysqli With Interpolated SQL

Prepared statements only help when the value goes in as a parameter. AI-generated PHP often calls
`prepare()` on a string that already contains the variable.

```php
// BAD — interpolation, with or without prepare()
$rows = $pdo->query("SELECT id FROM users WHERE email = '$email'")->fetchAll();
$stmt = $pdo->prepare("SELECT id FROM users WHERE email = '$email'"); $stmt->execute();
// Verified: email = "nobody' OR '1'='1" returned every row.
```

```php
// GOOD — bound parameter
$stmt = $pdo->prepare('SELECT id FROM users WHERE email = ?');
$stmt->execute([$email]);
// Verified: the same input returned 0 rows.
```

Identifiers (table, column, `ORDER BY` direction) cannot be bound — map them from an allowlist.
Laravel's `DB::select()` / `DB::statement()` / `DB::unprepared()` with an interpolated string,
`DB::raw()`, `whereRaw()`, `orderByRaw()`, procedural `mysqli_query($conn, "… $id")` and WordPress
`$wpdb->query()` without `$wpdb->prepare()` are the same sink. Depth: `secaudit:data-access`.

```bash
# interpolated "…$x…" or a concatenated '…'. / "…". literal, as the first argument or after a
# connection argument (procedural mysqli_query($conn, …)); covers PDO, mysqli, $wpdb and Laravel DB::
grep -rnE "(->(query|exec|prepare|get_results|get_row|get_var|get_col)|\bmysqli_(query|real_query|multi_query|prepare)|DB::(select|selectOne|insert|update|delete|statement|unprepared))\s*\(([^,()]*,\s*)?(\"[^\"]*\\$|\"[^\"]*\"\s*\.|'[^']*'\s*\.)" --include='*.php' .
grep -rnE '\b(DB::raw|whereRaw|orderByRaw|havingRaw|selectRaw)\s*\([^)]*\$' --include='*.php' .
```

## 7. Production `php.ini`: Errors, Version Banner, Logging

With no `php.ini` — the default in the official Docker images until you copy one in —
`display_errors` is `1`: a stock `php:8.4-apache` sent warnings, the fatal error and its stack
trace, with absolute file paths, to the browser (verified). php.net: `display_errors` should never
be used on production systems.

```ini
; GOOD — production
display_errors = Off
display_startup_errors = Off
log_errors = On
error_log = /proc/self/fd/2        ; or a file outside the web root
expose_php = Off                   ; php.ini-production leaves this On (verified)
allow_url_include = Off
session.upload_progress.enabled = 0   ; section 1
```

In Docker, start from the shipped production file — `RUN mv "$PHP_INI_DIR/php.ini-production"
"$PHP_INI_DIR/php.ini"` — then set `expose_php = Off`, which that file does not do.

```bash
# php.ini / conf.d, FPM pool php_(admin_)value[...] / php_(admin_)flag[...], Apache php_flag / php_value
grep -rniE '^\s*(php_(admin_)?(flag|value)(\[|\s+))?(display_errors|display_startup_errors|expose_php)\]?(\s*=\s*|\s+)"?(1|on|true|yes|stdout|stderr)\b' --include='*.ini' --include='*.conf' --include='.htaccess' .
grep -rniE "ini_set\(\s*['\"](display_errors|display_startup_errors)['\"]\s*,\s*['\"]?(1|on|true|yes|stdout|stderr)\b" --include='*.php' .
grep -niE '(display_errors|display_startup_errors|expose_php)\s*=\s*"?(1|on|true|yes|stdout|stderr)\b' Dockerfile* */Dockerfile* 2>/dev/null   # RUN echo … >> conf.d/*.ini
grep -rnE 'error_reporting\(\s*E_ALL\s*\)' --include='*.php' .   # fine in dev; check it is not paired with display on
```

## 8. Files the Web Server Should Never Serve or Execute

When the project root is the document root, everything in it is a URL. Verified on a stock
`php:8.4-apache` with the repo mounted at `/var/www/html`: `/.env` returned `200` with the
`APP_KEY` and database password, `/composer.json` returned `200`, and `/uploads/avatar.php`
**executed** (`200 executed:42`). Apache's default denies `.ht*` files, not `.env`.

- Point the document root at `public/` (Laravel, Symfony) and keep `.env`, `vendor/`,
  `composer.json`/`composer.lock`, `storage/`, `.git/` and backups (`*.sql`, `*.zip`, `*.bak`,
  `wp-config.php~`) outside it. Probe the live host: `curl -s -o /dev/null -w '%{http_code}'
  https://target.example.com/.env` should be `404`.
- **Uploads:** `$_FILES[...]['type']` comes from the client and PHP does not check it (php.net).
  Allowlist the extension, check content (`finfo_file()`, re-encode images), generate the stored
  filename yourself, size-limit, and store **outside the web root**, serving through a controller
  that sets `Content-Type` and `Content-Disposition`. If uploads must sit under the document root,
  disable PHP execution for that directory in the server config. Depth: `secaudit:web-vulns`.

```bash
ls -a public/ 2>/dev/null | grep -E '^\.env|composer\.(json|lock)|vendor'   # should be empty
grep -rnE 'move_uploaded_file\s*\(' --include='*.php' .
grep -rnE "\\\$_FILES\[[^]]+\]\[['\"](name|type)['\"]\]" --include='*.php' .   # client-controlled
```

## 9. Laravel

- **`APP_DEBUG=true` in production.** Laravel's docs: always `false` in production, or you risk
  exposing sensitive configuration to end users. The debug page is Ignition; with debug mode on,
  `facade/ignition` allowed unauthenticated RCE (`CVE-2021-3129`, on CISA KEV since 2023-09-18),
  fixed 2.5.2 / 2.4.2 / 1.16.14 / 1.6.15. Keep `spatie/laravel-ignition` (or `facade/ignition`) in
  `require-dev` and deploy with `composer install --no-dev`.
- **`APP_KEY`.** Laravel encrypts every cookie, session cookies included, with it (Laravel docs), so
  a leaked key lets anyone decrypt and forge them. A key in git, a public `.env` (section 8), a
  debug page or a log is compromised: generate a new one with `php artisan key:generate`. Plan
  for what rotation breaks (Laravel docs): every user is logged out, and data encrypted with the
  old key — `encrypted` model casts, `Crypt::encryptString()` values — can no longer
  be decrypted. Re-encrypt that data with a one-off migration or command that decrypts each value
  with an `Illuminate\Encryption\Encrypter` built from the old key and saves it again under the
  new one, then discard the old key. Do not park the leaked key in `APP_PREVIOUS_KEYS` to skip
  that step — Laravel still tries every previous key when decrypting (Laravel docs), so values
  forged with it keep working. Redaction rules: `secaudit:secrets`.
- **Mass assignment.** `protected $guarded = [];` or the `#[Unguarded]` attribute makes every column
  fillable; with `User::create($request->all())` a request can set `is_admin` or `role`. Laravel's
  docs: if you unguard, always hand-craft the arrays passed to `fill`, `create` and `update`. Use
  `$fillable` / `#[Fillable]` and `$request->validated()`.

```bash
grep -nE '^APP_DEBUG\s*=\s*true' .env* 2>/dev/null
grep -nE '^APP_KEY\s*=\s*\S+' .env.example .env.*.example 2>/dev/null   # a real key in a template
git log --all -p -- .env | grep -cE '^\+APP_KEY=.+'                  # ever committed? count only, never print it
grep -nE '"(spatie/laravel-ignition|facade/ignition)"' composer.json     # must be under require-dev
grep -rnE 'guarded\s*=\s*\[\s*\]|#\[Unguarded\]' --include='*.php' app/
grep -rnE '::(create|forceCreate|update)\(\s*\$request->all\(\)|->fill\(\s*\$request->all\(\)' --include='*.php' app/
```

## 10. WordPress Plugins and Themes

A WordPress site's attack surface is its plugin list, and plugins are a supply chain: code from a
vendor download or update channel runs with full access to the database and filesystem. Two
October 2026 incidents show that a clean code review of *your* repo does not cover this:

- **Rank Math SEO PRO 3.0.123** was backdoored at the vendor's own download source; Patchstack
  lists 3.0.124 as the patched version and its remedy is to update. The entry does not say what
  the backdoor did while it was installed, so updating is the minimum: a site that ran 3.0.123
  still needs a compromise check (unknown users, plugins and files) before it is called clean.
- **UpdraftCentral:** attackers holding stolen UpdraftCentral dashboard keys used the legitimate
  remote-management channel to install backdoor plugins on connected sites. No plugin bug was
  needed, and no plugin update stops it. Patchstack's remediation (2026-10-19,
  <https://patchstack.com/articles/updraftcentral-key-compromise-wordpress-backdoors/>):
  - Delete **every** UpdraftCentral key on the site (`wp option delete updraft_central_localkeys`).
    Removing the site from the UpdraftCentral dashboard is not enough — the key that matters lives
    on the site. Do not reconnect until the vendor explains the cause.
  - The backdoor creates an account that shows as an **Editor** but holds `manage_options` and
    `install_plugins`, so a review of the administrator list misses it. The account stays after
    the plugin is removed. Find it by capability, not by role name.
  - If the backdoor plugin is present, delete the keys first, then deactivate it and **move it out
    of the web root** rather than deleting it through wp-admin — its uninstall routine erases its
    own traces.
  - If the account exists or the trigger parameter appears in the access logs, treat the site as
    fully compromised: restore from a pre-attack backup, compare files against a clean install,
    rotate passwords and end all sessions.

Inventory every plugin and theme with its version (`wp plugin list`, `wp theme list`, or the
`Version:` header), check each against a vendor or vulnerability-database advisory, and remove
anything inactive. The pwn.watch PHP feed (<https://pwn.watch/t/php.json>) is a useful live list
of incidents to check against — it is a tracker, so confirm each item at the vendor or database
before reporting it. Dependency-trust method: `secaudit:supply-chain`.

```bash
grep -HE '^\s*\*?\s*Version:' wp-content/plugins/*/*.php 2>/dev/null | head -50   # keeps the file name
grep -rnE "define\(\s*'(DISALLOW_FILE_EDIT|WP_DEBUG|WP_DEBUG_DISPLAY)'" wp-config.php
grep -rnE '\$wpdb->(query|get_results|get_row|get_var)\(\s*"[^"]*\$' --include='*.php' wp-content/
```

## 11. Composer Hygiene

- **Commit `composer.lock`** (Composer docs) and deploy with `composer install --no-dev`, never
  `composer update` on the server.
- **Run `composer audit`** in CI — it reports packages with security advisories, abandoned
  packages and, per the current docs, malware matches; `--locked` audits the lock file without a
  `vendor/` directory. Exit code `0` means no issues; `1` means findings **or** a failure (Composer
  docs). Keep stderr visible: empty output after an error is not a clean result.
- **No branch or `*` constraints** in production `require` — `dev-master` / `dev-main`, aliases
  such as `dev-main as 1.0`, `1.x-dev`, a `@dev` stability flag, or `*`. They track a moving
  branch, so the code you reviewed is not the code you deploy.
- Review custom `repositories` entries (VCS URLs, `path`, private mirrors) as part of the trust
  boundary. Code that runs during `composer install`: the root package's `scripts` hooks
  (`post-install-cmd`, `post-update-cmd`, …; dependencies' scripts do not run) and Composer
  plugins, which `config.allow-plugins` gates since Composer 2.2. An `allow-plugins: true` or a
  long allowlist is a code-execution grant (Composer docs).

```bash
test -f composer.lock || echo "no composer.lock"
composer audit --locked; echo "composer audit exit=$?"   # 0 = clean; 1 = findings or failure
grep -nE ':\s*"(dev-[^"]*|[^"]*(-dev|@dev)( [^"]*)?|\*)"' composer.json   # then check it is under require, not require-dev
grep -nE '"(repositories|allow-plugins|post-install-cmd|post-update-cmd|post-autoload-dump)"' composer.json
```

## Detection Quick Pass

Stack markers: `composer.json`, `*.php`, `artisan`, `wp-config.php`, `FROM php:` in a Dockerfile,
or `X-Powered-By: PHP/…` on a live host.

```bash
# --- Runtime (section 1) — compare against php.net, not memory ---
php -v; grep -nE '"php"\s*:' composer.json; grep -nE '^FROM\s+php:' Dockerfile* 2>/dev/null
grep -rnE 'session\.(upload_progress\.enabled|serialize_handler)' --include='*.ini' --include='*.conf' --include='*.php' .

# --- Code and config sinks (sections 2-7) ---
grep -rnE '\b(unserialize|eval|assert|create_function|system|exec|shell_exec|passthru|popen|proc_open)\s*\(' --include='*.php' .
grep -rnE '\b(include|require)(_once)?\b[^;]*\$_(GET|POST|REQUEST|COOKIE)' --include='*.php' .
grep -rnE "(->(query|exec|prepare|get_results|get_row|get_var|get_col)|\bmysqli_(query|real_query|multi_query|prepare)|DB::(select|selectOne|insert|update|delete|statement|unprepared))\s*\(([^,()]*,\s*)?(\"[^\"]*\\$|\"[^\"]*\"\s*\.|'[^']*'\s*\.)" --include='*.php' .
grep -rniE '^\s*(php_(admin_)?(flag|value)(\[|\s+))?(display_errors|display_startup_errors|expose_php|allow_url_include)\]?(\s*=\s*|\s+)"?(1|on|true|yes|stdout|stderr)\b' --include='*.ini' --include='*.conf' --include='.htaccess' .

# --- Exposure, Laravel, Composer (sections 8-11) ---
ls -a public/ 2>/dev/null | grep -E '^\.env|composer\.|vendor'
grep -nE '^APP_DEBUG\s*=\s*true' .env* 2>/dev/null
grep -rnE 'guarded\s*=\s*\[\s*\]|#\[Unguarded\]' --include='*.php' app/ 2>/dev/null
test -f composer.lock && composer audit --locked
```

Findings that are deserialization or command injection also map to `secaudit:logging-monitoring`;
SQL to `secaudit:data-access`; uploads and traversal to `secaudit:web-vulns`. A PHP2Shell-vulnerable
runtime is Critical on its own and goes at the top of the report.

## Sources

- https://www.php.net/archive/2026.php -- PHP2Shell advisory (2026-10-21): fixed 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35, affected SAPIs, mod_php highest, interim mitigations, 7.4-8.1 source backports; 2026-10-23 note on session.upload_progress and CVE-2026-115560
- https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w -- CVE-2026-109618 (OOM): RCE validated on mod_php; FPM susceptible by source analysis, no complete exploit; FrankenPHP and LSAPI likely but unvalidated; do not use RLIMIT_AS / RLIMIT_DATA
- https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp -- CVE-2026-109619 (stale state): session upload progress RCE validated on mod_php and FPM
- https://github.com/php/php-src/issues/24488 -- bug tracker, not an advisory: 8.4.27 / 8.5.12 SimpleXML GC double-free crash, fixed in commit f963484, no release yet as of 2026-10-23
- https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json -- CISA KEV feed: PHP2Shell CVEs absent from catalog 2026.10.23; CVE-2021-3129 present
- https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2026-151/ -- CSA Singapore: CVSS 4.0 9.2 each, widespread exploitation attempts, multiple PoCs
- https://isc.sans.edu/diary/33450 -- SANS ISC wrap-up: early leak, partial and parasitic exploits, appliances as the major concern
- https://pwn.watch/i/php2shell-cve-2026-109618-109619 -- tracker only (not an authority): downstream vendor timeline incl. QNAP and other appliances
- https://pwn.watch/t/php.json -- tracker only: live PHP incident feed
- https://security-tracker.debian.org/tracker/CVE-2026-109618 -- Debian fixed package versions
- https://ubuntu.com/security/CVE-2026-109618 -- Ubuntu fixed package versions (backports keep old upstream numbers)
- https://endoflife.date/php -- PHP branch EOL dates (API: https://endoflife.date/api/php.json)
- https://github.com/docker-library/docs/blob/master/php/README.md -- official image tags, -apache = mod_php, php.ini-production
- https://getcomposer.org/doc/06-config.md -- config.platform fakes the platform; allow-plugins
- https://getcomposer.org/doc/articles/scripts.md -- only root-package scripts run; install/update events
- https://getcomposer.org/doc/03-cli.md -- composer audit, --locked, exit codes (0 clean, 1 findings or failure)
- https://getcomposer.org/doc/01-basic-usage.md -- commit composer.lock
- https://www.php.net/manual/en/function.unserialize.php -- never pass untrusted input, regardless of allowed_classes
- https://www.php.net/manual/en/filesystem.configuration.php -- allow_url_include default and deprecation
- https://www.php.net/manual/en/function.eval.php -- eval is very dangerous
- https://www.php.net/manual/en/function.assert.php -- string assertions removed in PHP 8
- https://www.php.net/manual/en/migration80.incompatible.php -- create_function() removed
- https://github.com/php/php-src/blob/PHP-7.0/UPGRADING -- /e (PREG_REPLACE_EVAL) removed
- https://www.php.net/manual/en/function.escapeshellarg.php -- quoting a single shell argument
- https://www.php.net/manual/en/pdo.prepared-statements.php -- prepared statements and SQL injection
- https://www.php.net/manual/en/errorfunc.configuration.php -- display_errors never on production
- https://www.php.net/manual/en/ini.core.php -- expose_php and X-Powered-By
- https://www.php.net/manual/en/features.file-upload.post-method.php -- $_FILES type is client-controlled
- https://laravel.com/framework/docs/13.x/configuration -- APP_DEBUG must be false in production
- https://laravel.com/framework/docs/13.x/encryption -- APP_KEY encrypts every cookie; rotation logs users out and orphans old-key data; APP_PREVIOUS_KEYS
- https://laravel.com/framework/docs/13.x/eloquent -- unguarded models and mass assignment
- https://github.com/advisories/GHSA-4qwp-7c67-jmcc -- CVE-2021-3129 Ignition debug-mode RCE
- https://patchstack.com/database/wordpress/plugin/seo-by-rank-math-pro/vulnerability/wordpress-rank-math-seo-pro-plugin-3-0-123-unauthenticated-embedded-malicious-code-vulnerability -- Rank Math SEO PRO 3.0.123 backdoor, patched 3.0.124
- https://patchstack.com/articles/updraftcentral-key-compromise-wordpress-backdoors/ -- stolen UpdraftCentral keys used to backdoor sites; remediation (delete updraft_central_localkeys, no reconnect, disguised Editor account, move plugin out of web root, full-compromise criteria)
- https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html -- php.ini hardening
- https://cheatsheetseries.owasp.org/cheatsheets/Laravel_Cheat_Sheet.html -- Laravel hardening
