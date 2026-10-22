Build a local AI-assisted penetration testing agent for Kali Linux, for explicitly authorized targets only. The concept is similar to Wiz Red Agent: Claude reasons and adapts, while existing Kali tools perform the actual testing.

Core loop:

Discover → Understand → Hypothesize → Test → Observe → Adapt → Validate → Chain → Report

REQUIREMENTS

• Use Python, SQLite, and a CLI.

• Use PTES for overall methodology; OWASP WSTG, Web Top 10 and API Top 10 for testing knowledge/classification; CWE for weakness mapping; CVSS for severity; MITRE ATT&CK optionally for attack paths.

• These frameworks are guidance, NOT checklists. Claude should reason from observations and decide what to investigate next.

• Reuse existing Kali tools instead of reinventing functionality. Initial tools: nmap, curl and feroxbuster. Support others such as ffuf, httpx, nuclei and Penelope through plugins.

• Claude must request capabilities rather than arbitrary commands. Example:

web_content_discovery → feroxbuster / ffuf
network_discovery → nmap
http_request → curl
reverse_shell_handler → Penelope

• Never give Claude unrestricted shell access. Python validates scope and parameters, selects the plugin, executes the tool safely, parses its output and returns normalized observations to Claude.

PLUGIN SYSTEM

Create a standard plugin interface containing:

name
capabilities
execution_type
safety_level
validate()
execute()
parse()

Support:

ONE_SHOT tools such as nmap, curl and feroxbuster.

INTERACTIVE tools such as Penelope with start(), status(), get_events(), send_input() and stop().

Implement automatic onboarding:

python agent.py plugin add <tool>

The agent should inspect the tool's help/version information, use Claude to generate an adapter/parser, classify its capabilities and safety level, test it, show it to me and require approval before activation.

Adding a new tool must not require changing the reasoning engine.

KNOWLEDGE

Store assets, services, endpoints, parameters, identities, tests, observations, hypotheses, findings, relationships, attack paths, plugins and progress in SQLite.

Normalize tool output before giving it to Claude while retaining raw output for evidence.

VALIDATION

Use:

Hypothesis → Test → Observation → Reproduce → Validate → Finding

Support POSSIBLE and CONFIRMED findings.

Do not report a vulnerability as confirmed based only on a scanner signature or unusual response.

Correlate validated findings into attack paths when evidence supports every step.

SAFETY

Require scope.yaml containing authorized IPs, CIDRs, domains, URLs and ports.

Every action must pass deterministic scope validation.

Implement rate limits, timeouts, concurrency limits and a kill switch.

No DoS, persistence, malware deployment, data destruction or destructive testing.

PROGRESS

Display live progress:

[████████████████░░░░░░░░░░░░] 57%

Current phase: Authorization Testing
Endpoints: 27/42
Tests: 118
Confirmed findings: 3

Calculate the percentage from actual completed assessment work and persist it for resume support.

REPORT

Generate a professional standalone offline HTML pentest report containing:

Executive summary
Scope and methodology
Attack surface
Findings summary
Detailed findings
Evidence and reproduction steps
CVSS/CWE/OWASP mappings
Attack paths
Remediation
Testing statistics

Include severity dashboards, tables, collapsible technical evidence and print-friendly CSS.

Never expose Claude's chain-of-thought, prompts, credentials, API keys or session tokens.

DEVELOPMENT

Build incrementally.

First establish:
1. Architecture
2. Scope enforcement
3. SQLite
4. CLI/progress
5. Plugin interface/registry
6. Safe executor
7. nmap, curl and feroxbuster plugins

Then add Claude reasoning, automatic plugin generation, additional testing capabilities, validation/attack paths and HTML reporting.

Before coding, briefly show me the proposed architecture and directory structure. Then implement only the initial foundation and test it.

Core principle:

Claude reasons → capability registry selects → Kali tool executes → Python parses → SQLite remembers → Claude adapts → findings are validated → HTML report is generated.
