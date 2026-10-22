# SmartCheckAgent

A local, AI-assisted penetration-testing agent for Kali Linux — **for explicitly
authorized targets only**. An LLM drives the reasoning loop (Discover →
Understand → Hypothesize → Test → Observe → Adapt → Validate → Chain →
Report), while existing Kali tools (`nmap`, `curl`, `feroxbuster`, `httpx`,
`nuclei`, `searchsploit`, ...) do the actual testing. Python validates scope,
selects a plugin, executes the tool safely, parses its output, and remembers
everything in SQLite.

> ⚠️ **Authorized use only.** Every action is gated by `scope.yaml`
> (deny-by-default). There is no unrestricted shell. Run it only against
> systems you own or have **written** permission to test.

## Core principle

```
AI model reasons → capability registry selects → Kali tool executes
  → Python parses → SQLite remembers → model adapts → findings validated → HTML report
```

The model never runs commands directly — and never gets a shell. It requests a
named **capability** (e.g. `network_discovery`); Python enforces the pipeline —
scope check, plugin selection, safe execution, output parsing — and hands back
normalized observations. PTES frames the overall methodology; OWASP WSTG, the
Web Top 10 and API Top 10 classify what's being tested; CWE maps weaknesses;
CVSS scores severity; MITRE ATT&CK optionally tags attack-path steps. These are
**guidance, not checklists** — the model reasons from what it observes and
decides what to investigate next, rather than running a fixed script. A
traditional scanner runs the same ports, payloads, and signatures every time
regardless of what it finds; this agent loops — run a capability, look at the
result, form a hypothesis, decide the next test, repeat.

## Quick start (Docker, the fast path)

If you only read one section, read this one.

```bash
# 1. Log in to the image registry (ask the repo owner for a read:packages PAT)
echo "$GITHUB_PAT" | docker login ghcr.io -u YOUR_GITHUB_USERNAME --password-stdin

# 2. Pull and tag the image
docker pull ghcr.io/y3llowduck/smartcheckagent:latest
docker tag ghcr.io/y3llowduck/smartcheckagent:latest smartcheckagent:latest

# 3. Set up a working directory for this engagement
mkdir ~/engagements/client-x && cd ~/engagements/client-x
cp /path/to/scope.example.yaml scope.yaml      # then edit with AUTHORIZED targets
mkdir -p data

# 4. Fix data/ ownership (one-time per directory — see "Why this step" below)
docker run --rm -v "$PWD/data:/data" --user root --entrypoint sh smartcheckagent:latest -c "chown -R 999:999 /data"

# 5. Add the `sca` shortcut to your shell
cat >> ~/.zshrc <<'EOF'
sca() { docker run --rm -it --cap-drop=ALL --cap-add=NET_RAW --cap-add=NET_BIND_SERVICE --security-opt no-new-privileges -v "$PWD/scope.yaml":/app/scope.yaml:ro -v "$PWD/data":/app/data -e ANTHROPIC_API_KEY smartcheckagent:latest "$@"; }
EOF
source ~/.zshrc

# 6. Initialize, verify scope, and go
export ANTHROPIC_API_KEY=sk-ant-...
sca init
sca scope show
sca assess 192.168.1.50 --model <model-id> --objective "Find and validate web vulnerabilities"
```

That's the whole path from zero to a running assessment. Everything below
explains *why* each step exists, plus the from-source alternative, the full
command reference, and troubleshooting.

## Two ways to run it

| | Docker (recommended) | From source |
|---|---|---|
| Kali tools bundled | ✅ nmap, httpx, searchsploit, curl in the image | ❌ you install them |
| Isolation | ✅ runs as a non-root user in a container | ❌ runs on your host |
| Best for | quick, reproducible runs | development / modifying the code |

### Option A — Docker, step by step

**1. Get the image.** The published image is **private** — log in to GitHub
Container Registry first with a Personal Access Token that has
`read:packages` (ask the repo owner to grant you read access to the
package — package page:
https://github.com/users/Y3llowDuck/packages/container/package/smartcheckagent):

```bash
echo "$GITHUB_PAT" | docker login ghcr.io -u YOUR_GITHUB_USERNAME --password-stdin
docker pull ghcr.io/y3llowduck/smartcheckagent:latest
docker tag ghcr.io/y3llowduck/smartcheckagent:latest smartcheckagent:latest
```

...or build it yourself from the `Dockerfile` in this repo:

```bash
docker build -t smartcheckagent:latest .
```

The build is multi-stage: it compiles `agent.py` into a single-file binary
with PyInstaller, then assembles a slim Kali runtime containing `nmap`,
`httpx-toolkit`, `exploitdb`/`searchsploit`, `curl`, and `ca-certificates`.
`nmap` is granted raw-socket capability via `setcap`; the agent runs as the
unprivileged `scagent` user (UID 999); `scope.yaml` and `data/` are the only
things that cross the container boundary, and only at run time.

**2. Set up a working directory for the engagement:**

```bash
mkdir ~/engagements/client-x && cd ~/engagements/client-x
cp /path/to/scope.example.yaml scope.yaml   # then edit with AUTHORIZED targets
mkdir -p data
```

**3. Fix `data/` ownership** (one-time per directory):

```bash
docker run --rm -v "$PWD/data:/data" --user root --entrypoint sh smartcheckagent:latest -c "chown -R 999:999 /data"
```

<details>
<summary>Why this step exists</summary>

The container runs as `scagent` (UID 999). Docker creates bind-mounted
directories owned by `root` by default, so without this step the first write
to SQLite fails with
`sqlite3.OperationalError: attempt to write a readonly database`. Running
the `chown` through a throwaway container (as above) avoids needing `sudo`
on the host.
</details>

**4. Add the `sca` shell function**, so you don't retype the security flags
and mount paths on every command:

```bash
cat >> ~/.zshrc <<'EOF'
sca() { docker run --rm -it --cap-drop=ALL --cap-add=NET_RAW --cap-add=NET_BIND_SERVICE --security-opt no-new-privileges -v "$PWD/scope.yaml":/app/scope.yaml:ro -v "$PWD/data":/app/data -e ANTHROPIC_API_KEY smartcheckagent:latest "$@"; }
EOF
source ~/.zshrc
```

<details>
<summary>What each flag is doing</summary>

`--cap-drop=ALL` then re-adding only `NET_RAW`/`NET_BIND_SERVICE` is the CIS
Docker Benchmark pattern — least privilege instead of a fully capable
container. `NET_RAW` here works together with the `setcap` grant baked into
the image: the file capability on the `nmap` binary only takes effect when
`NET_RAW` is also in the container's bounding set, otherwise nmap silently
falls back to a connect scan. `--security-opt no-new-privileges` blocks
privilege escalation. The image already sets default internal paths for
`scope.yaml`/`data`/generated plugins, so no extra `SMARTCHECK_*` env vars
are needed here — only pass them if you're overriding the defaults.
</details>

**5. Initialize and run:**

```bash
export ANTHROPIC_API_KEY=sk-ant-...
sca init                     # once per data/ directory — creates the SQLite schema
sca scope show
sca assess 192.168.1.50 --model <model-id> --objective "Find and validate web vulnerabilities" --max-steps 40
```

The command reference below uses `sca` as shorthand (same as `smartcheck`
would be for a self-built image tagged differently).

<details>
<summary>Optional extra hardening for a locked-down host</summary>

```bash
docker run --rm -it --read-only --tmpfs /tmp --memory=2g --cpus=2 --pids-limit=512 --cap-drop=ALL --cap-add=NET_RAW --cap-add=NET_BIND_SERVICE --security-opt no-new-privileges -v "$PWD/scope.yaml:/app/scope.yaml:ro" -v "$PWD/data:/app/data" -e ANTHROPIC_API_KEY smartcheckagent:latest "$@"
```

Test `--read-only` against the capabilities you actually use first — some
tools write temp files outside `/tmp` under certain modes, and `--tmpfs /tmp`
only covers `/tmp`.
</details>

The container needs to reach your in-scope targets. The default bridge
network is usually fine; for lab targets on the host or an isolated segment
you may want `--network host` (Linux) — use it deliberately and only for
scopes you control. Scanning third-party targets from a cloud instance (e.g.
AWS EC2) can trip abuse detection — review the provider's penetration-testing
policy before any external engagement from there.

### Option B — From source

```bash
python3 -m venv .venv
source .venv/bin/activate              # or: .venv/bin/python agent.py ...
pip install -r requirements.txt        # PyYAML (anthropic for `assess`)

python agent.py init                   # create data dir, DB, seed plugins
cp scope.example.yaml scope.yaml       # then edit with AUTHORIZED targets
```

Install the external Kali tools you intend to use (`nmap`, `curl`,
`feroxbuster`, `httpx-toolkit`, `nuclei`, `exploitdb`). A plugin whose binary
is missing is simply not offered — no code change needed. Later sessions just
need `source .venv/bin/activate` first; `.venv/` is gitignored.

## Configuring `scope.yaml`

Deny-by-default: anything not listed is refused.

| Field | Purpose |
|---|---|
| `authorization.authorized_by` | Who signed off on the engagement. **Must be entered by hand** — never inferred or auto-filled by the agent. |
| `authorization.engagement` | Engagement name / rules-of-engagement reference. Also hand-entered only. |
| `authorization.expires` | Engagement expiry date, recorded in reports. |
| `targets.ips` / `cidrs` / `domains` / `urls` | Authorized hosts, networks, hostnames, and full URLs. A URL's explicit port is auto-added to allowed ports. |
| `ports.allowed` | Only these ports may be touched (empty list = all ports, still host-scoped). |
| `options.allow_subdomains` | Whether a subdomain of a listed domain is in scope. |
| `limits` | Requests/sec, per-request timeout, max concurrency. |

The HTML report **refuses to generate** while `authorized_by` or `engagement`
is blank or still the placeholder text from `scope.example.yaml` — replace
both with your real sign-off before running `report`.

## First run

1. **Define scope** (see above), then verify it before touching anything:

   ```bash
   sca scope show
   sca scope check 192.168.56.10 --port 8080
   ```

2. **Run capabilities** (the only way to touch a target):

   ```bash
   sca capability list
   sca capability run network_discovery 192.168.56.10 -p ports=22,80,443
   sca capability run http_request http://192.168.56.10:8080/
   ```

3. **Or let the model drive it** (needs `ANTHROPIC_API_KEY` and `--model`):

   ```bash
   sca assess 192.168.56.10 --model <model-id> --objective "Find and validate web vulns" --max-steps 40
   ```

   The target is optional: if `scope.yaml` has exactly one concrete host (no
   CIDRs, ignoring localhost), it's auto-selected. The model discovers →
   hypothesizes → requests capabilities → validates → records findings, then
   the text summary prints automatically. To resume a prior run instead of
   starting over: `sca assess --run 4` — the model is re-seeded with a
   summary of prior ports, tech, paths, hypotheses, and findings.

4. **Watch progress, then report:**

   ```bash
   sca status      # live progress bar + counts
   sca summary     # consolidated text findings
   sca report --out /app/data/report.html   # -> lands at ./data/report.html on the host
   ```

### Choosing a model

There's no hardcoded default — a model release can behave very differently
from the last on authorized security-testing tasks, so it's pinned
explicitly rather than drifting silently. Resolved in this order, first one
set wins: the `--model` flag, then the `$SMARTCHECK_MODEL` environment
variable. If neither is set, `assess` / `plugin add` fail with a clear error
instead of guessing.

```bash
sca assess 192.168.56.10 --model <model-id>
# or, once per shell session:
export SMARTCHECK_MODEL=<model-id>
sca assess 192.168.56.10
```

## What a run looks like

A completed `assess` run — the model reasoning turn by turn, then a plain
summary once it concludes:

![A terminal showing the tail end of an assess run: steps requesting capabilities, a progress bar at 100%, and a concluding summary](docs/screenshots/assess-run.png)

The resulting HTML report's findings table and detail cards, each mapped to
CWE/OWASP/CVSS with reproduction evidence:

![The HTML report's Findings Summary table and a detailed finding card with description, reproduction & evidence, and remediation](docs/screenshots/report-findings.png)

Raw tool output is retained separately in a collapsible evidence appendix,
for verification independent of the normalized findings:

![The HTML report's Evidence Appendix, listing raw tool-output records by ID, capability, target, and return code](docs/screenshots/report-evidence.png)

## Command reference

```bash
# Scope
sca scope show
sca scope check <target> [--port N]

# Runs
sca run new --name "clientX engagement"
sca run list

# Onboard a new Kali tool as a plugin (the model drafts a declarative
# adapter, never executable code — you approve it before it's used)
sca plugin add ffuf --model <model-id>      # inspect → draft → approve
sca plugin add ffuf --model <model-id> --test-target http://192.168.56.10/ --yes
sca plugin remove ffuf                           # remove an onboarded plugin

# Capabilities (deterministic scope gate + safety ceiling)
sca capability list
sca capability run <capability> <target> [-p key=value ...] [--dry-run]

# AI-driven assessment — needs ANTHROPIC_API_KEY and --model/$SMARTCHECK_MODEL
sca assess [target] --model <id> --objective "..." --max-steps 40 --max-safety active

# Progress & results
sca status
sca summary
sca report [--run N] [--out /path/report.html]

# Safety — kill switch
sca kill engage     # halt all execution immediately
sca kill release
```

`-p key=value` params are JSON-parsed (`-p ports=22,80`, `-p depth=2`,
`-p headers='["X-Test: 1"]'`). `--max-safety` sets the auto-run intrusiveness
ceiling (default `active`; shells / `dangerous` are never auto-run).

## Capabilities → plugins

| Capability | Plugin | Safety | Binary (Kali) |
|---|---|---|---|
| `network_discovery` / `service_detection` | nmap | active | nmap |
| `http_request` | curl | passive | curl |
| `web_content_discovery` | feroxbuster | active | feroxbuster |
| `http_probe` / `tech_fingerprint` | httpx | active | **httpx-toolkit** ¹ |
| `vuln_signature_scan` | nuclei | active | nuclei ² |
| `exploit_mapping` | searchsploit | passive | searchsploit ³ |

¹ ProjectDiscovery httpx is `httpx-toolkit` on Kali (`/usr/bin/httpx` is the
unrelated Python CLI — the plugin detects and refuses it). Install:
`apt install httpx-toolkit`.
² Install nuclei from ProjectDiscovery. Its matches are **signatures →
POSSIBLE findings only**, never auto-confirmed.
³ Offline (no target traffic). `target` names the in-scope asset; the
product/version goes in `params.query`, e.g.
`capability run exploit_mapping 192.168.56.10 -p query="vsftpd 2.3.4"`.

A plugin whose binary is absent shows `missing` in `plugin list` and is not
offered to the reasoning engine until installed — no code change needed.
Additional tools (`ffuf`, `gobuster`, Penelope for reverse shells, etc.)
onboard the same way via `plugin add`, without touching the reasoning engine:
the agent inspects the tool's own `--help`/`--version` output, has the model
draft a declarative adapter spec (plain JSON describing flags and output
format — never executable code), validates it, optionally test-runs it
against an in-scope target, and requires your approval before it's used in a
real assessment.

## Validation discipline

Every finding follows **Hypothesis → Test → Observation → Reproduce →
Validate → Finding**, and is recorded as either **POSSIBLE** or **CONFIRMED**.
A vulnerability is never marked confirmed on a scanner signature or an
unusual response alone — it must cite reproduction evidence. Validated
findings are correlated into **attack paths** only when evidence supports
every step in the chain, optionally tagged with MITRE ATT&CK techniques.
Coverage is tracked as endpoints tested vs. discovered: discovery tools
(feroxbuster/httpx) record endpoints as untested; an actual request against
one (curl, a nuclei match) marks it tested.

## Safety model

- **Scope gate** runs before anything else; out-of-scope requests are refused
  and recorded (audit trail), never executed.
- **Safe executor** is the only process-spawning code: `shell=False`, argv
  only, per-request timeout, global rate limit, concurrency cap, and a
  file-based **kill switch** (`sca kill engage`).
- **Safety levels** (`passive < active < intrusive < dangerous`) cap what may
  run automatically.
- No DoS, persistence, malware deployment, data destruction, or destructive
  testing.
- Raw tool output is kept under `data/evidence/` for every execution,
  separate from the normalized observations the model sees.

## Report

`sca report` generates a standalone, offline HTML pentest report: cover page,
severity dashboard, executive summary, scope & methodology, attack surface,
findings summary, detailed findings with CVSS/CWE/OWASP mappings, evidence
and reproduction steps, attack paths, remediation guidance, and testing
statistics. Everything inline (no external resources), print-friendly CSS,
HTML-escaped. It never exposes the model's reasoning, prompts, credentials,
API keys, or session tokens.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Capability run refused / "out of scope" | Target IP, domain, or port isn't listed in `scope.yaml` | Add it under `targets`/`ports.allowed`, re-check with `scope check` |
| `report` refuses to generate | `authorization.authorized_by` or `engagement` is blank or placeholder text | Fill in both by hand in `scope.yaml` |
| Plugin shows `missing` in `plugin list` | The underlying Kali binary isn't installed | Install it (e.g. `apt install httpx-toolkit`; nuclei from ProjectDiscovery) |
| httpx plugin refuses to run | `/usr/bin/httpx` resolved to the unrelated Python CLI | Install `httpx-toolkit`; the plugin detects and rejects the wrong binary |
| `assess`/`plugin add` fail with "No model specified" | Neither `--model` nor `$SMARTCHECK_MODEL` is set | Pass `--model <id>` or `export SMARTCHECK_MODEL=<id>` |
| `assess` fails immediately / no model output | Missing or invalid `ANTHROPIC_API_KEY` | `export ANTHROPIC_API_KEY=sk-ant-...` |
| Scan seems stuck or runaway | Rate limit/timeout/concurrency misconfigured, or a tool hanging | `sca kill engage` to halt immediately, then adjust `limits` in `scope.yaml` |
| Resuming a run redoes recon | Ran a fresh `assess` instead of resuming | Pass `--run N` for the existing run to resume |
| `sqlite3.OperationalError: attempt to write a readonly database` (Docker) | `data/` is owned by root, not UID 999 (`scagent`) | Run the one-time `chown -R 999:999` step from the Docker setup above |
| `Scope file not found: /tmp/_MEIxxxxxx/scope.yaml` (self-built compiled image) | A custom Dockerfile without the baked-in `SMARTCHECK_SCOPE` default — the PyInstaller binary resolves paths relative to its own unpack temp dir | Add `ENV SMARTCHECK_SCOPE=/app/scope.yaml` (and `SMARTCHECK_DATA_DIR`/`SMARTCHECK_PLUGINS_DIR`) to the image, or pass them as `-e` flags at run time |
| TLS/certificate errors calling the model API from inside the container | `ca-certificates` missing from a custom runtime stage | The published image already includes this; if building your own, add `ca-certificates` and run `update-ca-certificates` |

## What never gets committed or baked in

`scope.yaml`, `data/` (DB, evidence, reports), and any API keys stay local.
They're excluded by `.gitignore` / `.dockerignore` and mounted at run time —
by design.

## Layout

```
agent.py                     entry point
scope.example.yaml           scope template
docs/screenshots/            README images
smartcheck/
  config.py  scope.py  db.py  models.py  progress.py  executor.py  capabilities.py  normalize.py
  plugins/   base.py  interactive.py  registry.py  {nmap,curl,feroxbuster,httpx,nuclei,searchsploit}_plugin.py
  reasoning/ engine.py  prompts.py  tools.py
tests/       test_scope.py  test_normalize.py  test_progress.py  test_reasoning.py  test_onboarding.py  test_report.py
data/        smartcheck.db, evidence/, reports/   (gitignored)
```

## Tests

```bash
python tests/test_scope.py        # deterministic scope gate (deny-by-default)
python tests/test_normalize.py    # observation -> knowledge-table normalization
python tests/test_progress.py     # progress accounting (coverage + step blend)
python tests/test_reasoning.py    # reasoning tool-use loop + validation discipline
python tests/test_onboarding.py   # plugin auto-onboarding
python tests/test_report.py       # HTML report generation
```

## Not yet built

An interactive reverse-shell driver (`reverse_shell_handler` / Penelope) and
authenticated scans.
