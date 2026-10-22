"""Command-line interface and dispatch.

Foundation commands:
    init                       set up data dir, DB, and scope.example.yaml
    scope check <target>       test deterministic scope validation
    scope show                 print the loaded scope summary
    run new [--name]           create an assessment run
    run list                   list runs
    capability list            show capabilities -> plugins
    capability run <cap> <target> [-p k=v ...] [--plugin X] [--run ID] [--dry-run]
    plugin list                show registered plugins
    status [--run ID]          show live progress
    kill (engage|release|status)
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Optional

# No hardcoded fallback: pin a model explicitly via --model / $SMARTCHECK_MODEL
# rather than drifting onto a baked-in default as new releases ship.
_DEFAULT_MODEL = os.environ.get("SMARTCHECK_MODEL")

from . import __version__, config, progress, summary
from .capabilities import CapabilityRouter
from .db import Database
from .executor import SafeExecutor
from .models import CapabilityRequest, SafetyLevel
from .plugins.registry import Registry
from .scope import Scope, ScopeError

# ---- small output helpers ------------------------------------------------

def _c(text: str, code: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"


def ok(msg: str) -> None:
    print(f"{_c('[+]', '32')} {msg}")


def info(msg: str) -> None:
    print(f"{_c('[*]', '36')} {msg}")


def warn(msg: str) -> None:
    print(f"{_c('[!]', '33')} {msg}")


def err(msg: str) -> None:
    print(f"{_c('[x]', '31')} {msg}", file=sys.stderr)


def _parse_params(items: Optional[list[str]]) -> dict:
    """Parse -p key=value pairs. Values are JSON-decoded when possible."""
    params: dict = {}
    for item in items or []:
        if "=" not in item:
            raise ValueError(f"Bad param {item!r}; expected key=value.")
        key, _, value = item.partition("=")
        try:
            params[key] = json.loads(value)
        except json.JSONDecodeError:
            params[key] = value
    return params


# ---- commands ------------------------------------------------------------

def cmd_init(args) -> int:
    config.ensure_dirs()
    db = Database()
    db.init_schema()
    # Seed the plugins table from built-ins.
    reg = Registry.with_builtins()
    for p in reg.all():
        db.upsert_plugin(
            name=p.name, capabilities=p.capabilities,
            execution_type=p.execution_type.value, safety_level=p.safety_level.value,
            binary_path=shutil.which(p.binary) or "", source="builtin",
            status="active" if reg.is_available(p) else "disabled",
        )
    db.close()
    ok(f"Initialized data dir: {config.DATA_DIR}")
    ok(f"Database ready:       {config.DB_PATH}")
    if not config.SCOPE_PATH.exists():
        if config.SCOPE_EXAMPLE_PATH.exists():
            warn(f"No scope.yaml yet. Copy the template and edit it:")
            print(f"      cp {config.SCOPE_EXAMPLE_PATH} {config.SCOPE_PATH}")
        else:
            warn("No scope.yaml and no template found.")
    else:
        ok(f"Scope file present:   {config.SCOPE_PATH}")
    return 0


def _load_scope_or_exit() -> Scope:
    try:
        return Scope.load()
    except ScopeError as e:
        err(str(e))
        sys.exit(2)


def cmd_scope_check(args) -> int:
    scope = _load_scope_or_exit()
    decision = scope.check(args.target, args.port)
    status = _c("ALLOWED", "32") if decision.allowed else _c("DENIED", "31")
    print(f"{status}  target={args.target}"
          + (f" port={args.port}" if args.port else ""))
    print(f"  reason: {decision.reason}")
    if decision.matched_rule:
        print(f"  matched: {decision.matched_rule}")
    return 0 if decision.allowed else 1


def cmd_scope_show(args) -> int:
    scope = _load_scope_or_exit()
    info(f"Scope loaded from {scope.source_path}")
    if scope.authorization:
        print("  authorization:")
        for k, v in scope.authorization.items():
            print(f"    {k}: {v}")
    print(f"  ips:       {sorted(scope.ips) or '-'}")
    print(f"  cidrs:     {[str(n) for n in scope.networks] or '-'}")
    print(f"  domains:   {sorted(scope.domains) or '-'}")
    print(f"  url_hosts: {sorted(scope.url_hosts) or '-'}")
    print(f"  ports:     {sorted(scope.allowed_ports) or 'ALL'}")
    print(f"  subdomains allowed: {scope.allow_subdomains}")
    lim = scope.limits
    print(f"  limits: {lim.requests_per_second} rps, "
          f"{lim.request_timeout_seconds}s timeout, "
          f"{lim.max_concurrency} concurrent")
    return 0


def cmd_run_new(args) -> int:
    scope = _load_scope_or_exit()
    db = Database()
    rid = db.create_run(args.name or "assessment", str(scope.source_path))
    db.close()
    ok(f"Created run #{rid} ('{args.name or 'assessment'}')")
    info("Use --run {0} on capability/status commands.".format(rid))
    return 0


def cmd_run_list(args) -> int:
    db = Database()
    runs = db.list_runs()
    if not runs:
        info("No runs yet. Create one with: agent.py run new")
    for r in runs:
        print(f"  #{r['id']:<3} {r['name']:<20} phase={r['phase']:<14} "
              f"status={r['status']:<10} {r['created_at']}")
    db.close()
    return 0


def cmd_capability_list(args) -> int:
    reg = Registry.with_builtins()
    info("Capabilities -> plugins:")
    for cap, names in sorted(reg.capabilities().items()):
        avail = []
        for n in names:
            p = reg.get(n)
            mark = "" if reg.is_available(p) else " (missing)"
            avail.append(f"{n}{mark}")
        print(f"  {cap:<24} -> {', '.join(avail)}")
    return 0


def _resolve_run_id(db: Database, requested: Optional[int]) -> Optional[int]:
    if requested is not None:
        return requested
    latest = db.latest_run()
    return latest["id"] if latest else None


def cmd_capability_run(args) -> int:
    scope = _load_scope_or_exit()
    try:
        params = _parse_params(args.param)
    except ValueError as e:
        err(str(e))
        return 2
    db = Database()
    run_id = _resolve_run_id(db, args.run)
    if run_id is None:
        warn("No run found; creating one.")
        run_id = db.create_run("assessment", str(scope.source_path))

    reg = Registry.with_builtins()
    executor = SafeExecutor.from_limits(scope.limits)
    max_safety = SafetyLevel(args.max_safety)
    router = CapabilityRouter(scope, reg, executor, db, max_safety=max_safety)

    request = CapabilityRequest(
        capability=args.capability, target=args.target, params=params,
        run_id=run_id, reason=args.reason or "cli",
    )

    # Dry run: show scope decision + the argv that would run, execute nothing.
    if args.dry_run:
        decision = scope.check(request.target, params.get("port"))
        print(f"scope: {'ALLOWED' if decision.allowed else 'DENIED'} "
              f"- {decision.reason}")
        if not decision.allowed:
            db.close()
            return 1
        plugin = reg.select(args.capability, prefer=args.plugin)
        if not plugin:
            err(f"No plugin for capability {args.capability!r}.")
            db.close()
            return 1
        validation = plugin.validate(request)
        if not validation.ok:
            err(f"validation failed: {validation.reason}")
            db.close()
            return 1
        print(f"plugin: {plugin.name} (safety={plugin.safety_level.value})")
        print("argv:  ", " ".join(validation.argv or plugin.build_argv(request)))
        db.close()
        return 0

    info(f"[run #{run_id}] capability={args.capability} target={args.target}")
    outcome = router.run(request, prefer_plugin=args.plugin)

    if outcome.blocked_by_scope:
        err(outcome.reason)
        db.close()
        return 1
    if not outcome.ok and outcome.result is None:
        err(outcome.reason)
        db.close()
        return 1

    res = outcome.result
    print(f"plugin: {res.plugin}   rc={res.return_code}   "
          f"{res.duration_seconds:.2f}s")
    if res.evidence_path:
        print(f"evidence: {res.evidence_path}")
    if res.error:
        warn(f"note: {res.error}")
    print(f"observations ({len(res.observations)}):")
    for o in res.observations:
        print(f"  - [{o.kind}] {o.summary}")

    # Refresh progress after work is recorded.
    snap = progress.compute(db, run_id)
    print()
    info(f"progress: {snap.percent:.0f}%  phase={snap.phase}  tests={snap.tests_count}")
    db.close()
    return 0 if outcome.ok else 1


def cmd_plugin_list(args) -> int:
    db = Database()
    rows = db.list_plugins()
    if not rows:
        warn("No plugins recorded. Run: agent.py init")
    reg = Registry.with_builtins()
    for r in rows:
        caps = ", ".join(json.loads(r["capabilities"] or "[]"))
        live = reg.get(r["name"])
        avail = reg.is_available(live) if live else False
        mark = _c("ok", "32") if avail else _c("missing", "31")
        print(f"  {r['name']:<14} [{mark}] {r['execution_type']:<11} "
              f"safety={r['safety_level']:<9} src={r['source']:<9} caps=[{caps}]")
    db.close()
    return 0


def cmd_plugin_add(args) -> int:
    from . import onboarding

    binary = args.tool
    bin_path = shutil.which(binary)
    if not bin_path:
        err(f"'{binary}' is not on PATH. Install it first.")
        return 1
    info(f"Onboarding '{binary}' ({bin_path})")

    scope = None
    try:
        scope = Scope.load()
    except ScopeError:
        pass
    executor = SafeExecutor(10, 10, 1)

    info("Inspecting tool help/version…")
    help_text, version_text = onboarding.gather_tool_info(binary, executor)
    if not help_text:
        warn("No help text captured; generation may be unreliable.")

    reg = Registry.with_builtins()
    known_caps = sorted(reg.capabilities().keys())
    info(f"Asking the model to draft an adapter (model {args.model})…")
    result = onboarding.generate_spec(binary, help_text, version_text,
                                      known_caps, args.model)
    if result.spec is None:
        err("Could not generate an adapter:")
        for e in result.errors:
            print(f"      - {e}")
        return 2

    print()
    info("Proposed adapter spec:")
    print(json.dumps(result.spec, indent=2))
    print()
    if result.errors:
        err("Spec has validation errors:")
        for e in result.errors:
            print(f"      - {e}")
        warn("Fix the tool/help or re-run; not saving.")
        return 1
    caps = ", ".join(result.spec.get("capabilities", []))
    ok(f"Valid. name={result.spec['name']}  safety={result.spec['safety_level']}  "
       f"caps=[{caps}]")

    # Optional live test against an in-scope target.
    if args.test_target:
        if scope is None:
            warn("No scope.yaml; skipping test.")
        else:
            _plugin_test(result.spec, args.test_target, scope)

    # Approval gate.
    if not args.yes:
        if not sys.stdin.isatty():
            warn("Non-interactive and --yes not given; not activating. "
                 "Re-run with --yes to save.")
            return 0
        try:
            answer = input("Activate this plugin? [y/N] ").strip().lower()
        except EOFError:
            answer = "n"
        if answer not in ("y", "yes"):
            info("Not activated.")
            return 0

    db = Database()
    path = onboarding.save_spec(result.spec, db)
    db.close()
    ok(f"Activated. Spec saved: {path}")
    info("It is now available to capabilities and the reasoning engine.")
    return 0


def _plugin_test(spec: dict, target: str, scope: Scope) -> None:
    from .capabilities import CapabilityRouter
    from .onboarding import build_plugin

    decision = scope.check(target)
    if not decision.allowed:
        warn(f"Test target out of scope ({decision.reason}); skipping test.")
        return
    try:
        plugin = build_plugin(spec)
    except Exception as e:  # noqa: BLE001
        warn(f"Could not build plugin for test: {e}")
        return
    reg = Registry()
    reg.register(plugin)
    executor = SafeExecutor.from_limits(scope.limits)
    db = Database()
    router = CapabilityRouter(scope, reg, executor, db,
                              max_safety=SafetyLevel(spec["safety_level"]))
    cap = spec["capabilities"][0]
    info(f"Test run: capability={cap} target={target}")
    from .models import CapabilityRequest
    outcome = router.run(CapabilityRequest(capability=cap, target=target,
                                           reason="plugin add test"))
    db.close()
    if outcome.result is None:
        warn(f"Test did not run: {outcome.reason}")
        return
    res = outcome.result
    print(f"      rc={res.return_code}  observations={len(res.observations)}")
    for o in res.observations[:5]:
        print(f"        - [{o.kind}] {o.summary}")


def cmd_plugin_remove(args) -> int:
    path = config.GENERATED_PLUGINS_DIR / f"{args.name}.json"
    if not path.exists():
        err(f"No generated plugin named '{args.name}'. "
            "(Built-in plugins cannot be removed.)")
        return 1
    path.unlink()
    db = Database()
    db.delete_plugin(args.name)   # drop the persisted record too
    db.close()
    ok(f"Removed generated plugin '{args.name}' ({path}).")
    return 0


def cmd_status(args) -> int:
    db = Database()
    run_id = _resolve_run_id(db, args.run)
    if run_id is None:
        warn("No runs yet.")
        db.close()
        return 1
    run = db.get_run(run_id)
    snap = progress.compute(db, run_id)
    print(f"Run #{run_id}  '{run['name']}'  (status={run['status']})\n")
    print(progress.render(snap))
    db.close()
    return 0


def cmd_assess(args) -> int:
    from .reasoning.engine import (DEFAULT_MODEL, AssessmentResult, EngineError,
                                   ReasoningEngine, StepEvent)

    scope = _load_scope_or_exit()

    # Resolve the target: use the CLI arg, else auto-pick from an unambiguous scope.
    target = args.target
    if not target:
        target, reason = scope.default_target()
        if not target:
            err(f"No target given and it can't be inferred: {reason}")
            info("Pass one explicitly, e.g.: agent.py assess <ip-or-url>")
            return 1
        info(f"No target given — using {target} ({reason})")

    # Pre-flight: the primary target must itself be in scope.
    decision = scope.check(target)
    if not decision.allowed:
        err(f"Primary target out of scope: {decision.reason}")
        return 1

    db = Database()
    run_id = _resolve_run_id(db, args.run) if args.run else None
    if run_id is None:
        run_id = db.create_run(args.name or f"assess {target}",
                               str(scope.source_path))
    prior_tests = db.count("tests", run_id)
    if prior_tests:
        ok(f"Run #{run_id}  target={target}  (RESUMING — {prior_tests} prior tests)")
    else:
        ok(f"Run #{run_id}  target={target}")
    db.set_run_status(run_id, "active")   # mark running (also re-activates a resume)
    info(f"Objective: {args.objective}")
    info(f"Model: {args.model}   max-steps: {args.max_steps}   "
         f"safety-ceiling: {args.max_safety}")
    print(f"{_c('[*]', '36')} Authorization: "
          f"{scope.authorization.get('authorized_by', 'UNSPECIFIED')} "
          f"(engagement: {scope.authorization.get('engagement', 'n/a')})")
    print()

    reg = Registry.with_builtins()
    executor = SafeExecutor.from_limits(scope.limits)
    if executor.kill_switch_engaged():
        err("Kill switch is engaged. Release it before assessing: agent.py kill release")
        db.close()
        return 1

    # Pin the progress bar as a bottom status line on a TTY: log lines scroll
    # above it, and the bar rewrites itself in place. Fall back to plain lines
    # when output is not a terminal (piped/redirected).
    live = sys.stdout.isatty()
    status = {"line": ""}  # the current pinned bar text (empty = none shown)

    def _status_text(d: dict) -> str:
        bar = progress.bar(d["percent"])
        cov = (f"  endpoints {d['endpoints_done']}/{d['endpoints_total']}"
               if d.get("endpoints_total") else "")
        plain = (f"  {bar} {d['percent']:.0f}%  {d['phase']}  "
                 f"steps {d['step']}/{d['max_steps']}  tests={d['tests']}  "
                 f"confirmed={d['confirmed']}{cov}")
        # On a TTY the bar is redrawn in place with a single-line clear (\r\033[K),
        # which only erases ONE physical row. If the text is wider than the
        # terminal it wraps, the clear can't erase the wrapped-off part, and stale
        # bars pile up in the scrollback. Keep it to one row so the clear works.
        if live:
            cols = max(20, shutil.get_terminal_size((80, 24)).columns)
            if len(plain) > cols - 1:
                plain = plain[:cols - 2] + "…"
        # Colorize only the bar (at the front, never near the truncation point).
        return plain.replace(bar, _c(bar, "36"), 1)

    def _log(line: str) -> None:
        """Print a scrolling line above the pinned status bar."""
        if live and status["line"]:
            sys.stdout.write("\r\033[K")        # clear the status line
        print(line)
        if live and status["line"]:
            sys.stdout.write(status["line"])     # re-pin the bar (no newline)
            sys.stdout.flush()

    def on_event(e: "StepEvent") -> None:
        if e.kind == "text":
            _log(f"  {_c(f'step {e.step}', '2')} {e.text}")
        elif e.kind == "tool":
            _log(f"  {_c(f'step {e.step}', '2')} {_c('⚙', '36')} {e.text}")
        elif e.kind == "progress":
            text = _status_text(e.detail)
            status["line"] = text
            if live:
                sys.stdout.write("\r\033[K" + text)
                sys.stdout.flush()
            else:
                print(text)
        elif e.kind == "conclude":
            _log(f"\n{_c('[+]', '32')} concluded: {e.text}")
        elif e.kind == "error":
            if live and status["line"]:
                sys.stdout.write("\r\033[K")
            err(e.text)
            if live and status["line"]:
                sys.stdout.write(status["line"]); sys.stdout.flush()

    def _finish_status() -> None:
        """Move off the pinned status line so later output starts cleanly."""
        if live and status["line"]:
            sys.stdout.write("\n")
            sys.stdout.flush()
            status["line"] = ""

    engine = ReasoningEngine(
        scope, reg, executor, db, run_id,
        max_safety=SafetyLevel(args.max_safety), model=args.model,
        max_steps=args.max_steps, on_event=on_event,
    )

    try:
        result: "AssessmentResult" = engine.run(target, args.objective)
    except EngineError as e:
        _finish_status()
        db.set_run_status(run_id, "aborted")
        err(str(e))
        db.close()
        return 2
    except KeyboardInterrupt:
        _finish_status()
        db.set_run_status(run_id, "aborted")
        warn(f"Assessment interrupted. Resume with: agent.py assess --run {run_id}")
        db.close()
        return 130

    _finish_status()
    # Engine marks 'completed' on conclude; otherwise it stopped early (budget,
    # refusal, end_turn) and is resumable, so mark it 'paused'.
    if not result.concluded:
        db.set_run_status(run_id, "paused")
    print()
    info(f"Loop finished: {result.steps} steps, "
         f"{result.capability_calls} capability calls, "
         f"{result.findings_recorded} findings recorded "
         f"(stop={result.stop_reason or 'n/a'})")
    print()
    # Always show the consolidated summary at the end.
    print(summary.build(db, run_id, color=sys.stdout.isatty()))
    db.close()
    return 0


def cmd_summary(args) -> int:
    db = Database()
    run_id = _resolve_run_id(db, args.run)
    if run_id is None:
        warn("No runs yet.")
        db.close()
        return 1
    print(summary.build(db, run_id, color=sys.stdout.isatty()))
    db.close()
    return 0


def cmd_report(args) -> int:
    from . import report as report_mod

    db = Database()
    run_id = _resolve_run_id(db, args.run)
    if run_id is None:
        warn("No runs yet.")
        db.close()
        return 1
    run = db.get_run(run_id)
    if args.out:
        out_path = Path(args.out)
    else:
        config.ensure_dirs()
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in run["name"])
        out_path = config.DATA_DIR / f"report-run{run_id}-{safe}.html"
    try:
        path = report_mod.generate(db, run_id, out_path)
    except report_mod.UnauthorizedReportError as e:
        err(str(e))
        db.close()
        return 2
    except Exception as e:  # noqa: BLE001
        err(f"Report generation failed: {e}")
        db.close()
        return 2
    ok(f"Report written: {path}")
    info(f"Open it: xdg-open {path}")
    db.close()
    return 0


def cmd_kill(args) -> int:
    executor = SafeExecutor(1, 1, 1)
    if args.action == "engage":
        executor.engage_kill_switch()
        warn(f"Kill switch ENGAGED. All executions refused until released.")
        print(f"      file: {executor.kill_switch_path}")
    elif args.action == "release":
        executor.release_kill_switch()
        ok("Kill switch released.")
    else:  # status
        state = "ENGAGED" if executor.kill_switch_engaged() else "clear"
        print(f"kill switch: {state}  ({executor.kill_switch_path})")
    return 0


# ---- parser --------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agent.py",
        description="SmartCheckAgent - AI-assisted pentest agent (authorized targets only).",
    )
    p.add_argument("--version", action="version", version=f"SmartCheckAgent {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="set up data dir, DB, and seed plugins").set_defaults(
        func=cmd_init)

    sp = sub.add_parser("scope", help="scope operations")
    sps = sp.add_subparsers(dest="sub", required=True)
    c = sps.add_parser("check", help="test scope validation for a target")
    c.add_argument("target")
    c.add_argument("--port", type=int, default=None)
    c.set_defaults(func=cmd_scope_check)
    sps.add_parser("show", help="print loaded scope").set_defaults(func=cmd_scope_show)

    rp = sub.add_parser("run", help="assessment runs")
    rps = rp.add_subparsers(dest="sub", required=True)
    rn = rps.add_parser("new", help="create a run")
    rn.add_argument("--name", default=None)
    rn.set_defaults(func=cmd_run_new)
    rps.add_parser("list", help="list runs").set_defaults(func=cmd_run_list)

    cp = sub.add_parser("capability", help="capability operations")
    cps = cp.add_subparsers(dest="sub", required=True)
    cps.add_parser("list", help="list capabilities -> plugins").set_defaults(
        func=cmd_capability_list)
    cr = cps.add_parser("run", help="run a capability against a target")
    cr.add_argument("capability")
    cr.add_argument("target")
    cr.add_argument("-p", "--param", action="append",
                    help="param as key=value (repeatable; value JSON-parsed)")
    cr.add_argument("--plugin", default=None, help="prefer a specific plugin")
    cr.add_argument("--run", type=int, default=None, help="run id (default: latest)")
    cr.add_argument("--reason", default="", help="why (recorded for audit)")
    cr.add_argument("--max-safety", default="active",
                    choices=[s.value for s in SafetyLevel],
                    help="ceiling on auto-run intrusiveness (default: active)")
    cr.add_argument("--dry-run", action="store_true",
                    help="show scope decision + argv, execute nothing")
    cr.set_defaults(func=cmd_capability_run)

    pp = sub.add_parser("plugin", help="plugin operations")
    pps = pp.add_subparsers(dest="sub", required=True)
    pps.add_parser("list", help="list plugins").set_defaults(func=cmd_plugin_list)
    pa = pps.add_parser("add", help="onboard a Kali tool as a plugin (uses the AI model)")
    pa.add_argument("tool", help="binary name on PATH, e.g. ffuf")
    pa.add_argument("--model", default=_DEFAULT_MODEL, help="model id")
    pa.add_argument("--test-target", default=None,
                    help="in-scope target to test the generated adapter against")
    pa.add_argument("--yes", action="store_true",
                    help="activate without the interactive approval prompt")
    pa.set_defaults(func=cmd_plugin_add)
    prm = pps.add_parser("remove", help="remove a generated (onboarded) plugin")
    prm.add_argument("name")
    prm.set_defaults(func=cmd_plugin_remove)

    st = sub.add_parser("status", help="show live progress")
    st.add_argument("--run", type=int, default=None)
    st.set_defaults(func=cmd_status)

    sm = sub.add_parser("summary", help="print a consolidated text summary of findings")
    sm.add_argument("--run", type=int, default=None)
    sm.set_defaults(func=cmd_summary)

    asp = sub.add_parser(
        "assess",
        help="run the AI reasoning loop against a target (needs anthropic + creds)",
    )
    asp.add_argument("target", nargs="?", default=None,
                     help="primary target (must be in scope). Optional: if omitted "
                          "and the scope has exactly one concrete host, it is used.")
    asp.add_argument("--objective", default="Perform an authorized security assessment "
                     "and identify, validate, and report vulnerabilities.",
                     help="what the assessment should achieve")
    asp.add_argument("--name", default=None, help="run name (for a new run)")
    asp.add_argument("--run", type=int, default=None,
                     help="continue an existing run id")
    asp.add_argument("--model", default=_DEFAULT_MODEL,
                     help="model id")
    asp.add_argument("--max-steps", type=int, default=40,
                     help="max reasoning/tool loop iterations")
    asp.add_argument("--max-safety", default="active",
                     choices=[s.value for s in SafetyLevel],
                     help="ceiling on auto-run intrusiveness (default: active)")
    asp.set_defaults(func=cmd_assess)

    rpt = sub.add_parser("report", help="generate a standalone HTML pentest report")
    rpt.add_argument("--run", type=int, default=None, help="run id (default: latest)")
    rpt.add_argument("--out", default=None, help="output path (default: data/report-*.html)")
    rpt.set_defaults(func=cmd_report)

    kp = sub.add_parser("kill", help="kill switch")
    kp.add_argument("action", choices=["engage", "release", "status"])
    kp.set_defaults(func=cmd_kill)

    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        err("interrupted")
        return 130
    except ScopeError as e:
        err(str(e))
        return 2


if __name__ == "__main__":
    sys.exit(main())
