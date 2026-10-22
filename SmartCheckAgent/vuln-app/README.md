# CVE-2026-109618 / CVE-2026-109619 detection test target

A deliberately-vulnerable, **local-only** PHP host for exercising SmartCheck's
in-house detection of the "php2shell" PHP core RCEs.

## What these CVEs actually are

CVE-2026-109618 and CVE-2026-109619 (disclosed 2026-10-21, CVSS 9.2) are
remote-code-execution bugs in the **PHP interpreter itself** — `longjmp()`
out-of-memory / fatal-error handling leaves request or global memory
uninitialized or pointing at freed regions. They are not flaws in any
particular PHP script.

- **Affected:** all PHP 5.4 through 8.5.11
- **Patched in:** 8.5.12, 8.4.27, 8.3.36, 8.2.35 (8.1 and earlier are EOL, no fix)

## Why this target is version-based, not an exploit

Because the vulnerability lives in the engine's memory handling, you cannot
reproduce it with vulnerable application code, and actually triggering the OOM
condition would just crash the PHP worker — useless for testing a scanner. So
this target reproduces the **observable fingerprint** that remote,
non-destructive detection keys on: a vulnerable PHP version advertised through
response headers and endpoints.

This image pins **PHP 8.3.0** (< the patched 8.3.36), so any version-based
check should flag it.

What it exposes:

- `X-Powered-By: PHP/8.3.0` response header (`expose_php = On`)
- `Server:` header with full tokens
- `GET /version.php` — JSON with `php_version`, `php_version_id`, affected CVEs
- `GET /info.php` — full `phpinfo()`

## Run it

```bash
docker compose -f vuln-app/docker-compose.yml up --build -d
```

Then:

```bash
curl -i http://127.0.0.1:8089/
curl -s http://127.0.0.1:8089/version.php
```

## Point SmartCheck at it

```bash
# full-URL target for httpx/nuclei capabilities
http://127.0.0.1:8089/
```

Expected: the version/tech fingerprint (httpx) and any version-matching
signature (nuclei) resolve PHP 8.3.0 and raise CVE-2026-109618 / -109619 as a
POSSIBLE finding for the reasoning engine to confirm against the banner.

## Tear down

```bash
docker compose -f vuln-app/docker-compose.yml down
```

## Safety

- Bound to `127.0.0.1:8089` only. Never expose it to a network or the internet
  — it is an intentionally vulnerable PHP build.
- Contains no working exploit payload; it only advertises a vulnerable version.
