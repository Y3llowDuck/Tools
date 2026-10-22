# Tools

Small tools I wrote while doing offensive security work, kept in one place. Each one solves a problem I hit often enough to stop solving it by hand: setting up access, checking what a network will let out, dropping a shell, generating payloads, reading code someone did not want read.

Each folder is self-contained and has its own README and its own license. Nothing here needs installing or building — they are single scripts and single files, in whatever language suited the job.

## What is here

| Tool | Does | Language |
|------|------|----------|
| [js-duckfuscator](js-duckfuscator/) | Deobfuscates and unpacks JavaScript, entirely in the browser | HTML / JS |
| [RDP-Automation](RDP-Automation/) | Enables RDP, creates a local admin, and opens the firewall rules in one go | PowerShell |
| [nic3r](nic3r/) | A nicer ASPX web shell | ASP.NET |
| [byteclipper](byteclipper/) | Builds an msfvenom C# payload one-liner and copies it to the clipboard | Bash |
| [port_check](port_check/) | Checks which outbound ports a host can actually reach | Bash |
| [port_check_PowerShell](port_check_PowerShell/) | The same outbound port check, for Windows hosts | PowerShell |
| [oscp_exam-ai-tips](oscp_exam-ai-tips/) | Scrapes OSCP success stories from Reddit and extracts the recurring strategies | Python |
| [SmartCheckAgent](SmartCheckAgent/) | AI-assisted pentest agent that drives Kali tools (nmap, nuclei, httpx, ...) against authorized targets and writes an HTML report | Python |

## About the relocation

Most of these lived in their own repositories until September 2026. Those repositories still exist and are now archived — read-only, with their stars, forks and URLs intact, and a note pointing here. Nothing was deleted, and no old link is broken.

## Licenses

They are not all the same, so each folder carries the license that applies to it.

| Tool | License |
|------|---------|
| js-duckfuscator | MIT |
| RDP-Automation | GPL-3.0 |
| nic3r | GPL-3.0 |
| byteclipper | GPL-3.0 |
| oscp_exam-ai-tips | GPL-3.0 |
| port_check | No license specified |
| port_check_PowerShell | No license specified |
| SmartCheckAgent | No license specified |

The MIT `LICENSE` at the root covers the repository itself — this README and the index page — not the tools inside it. Check the folder.

## Use responsibly

Several of these are offensive tools: a web shell, payload generation, remote access setup. They are here for authorized testing, lab work and study. Use them on systems you own or have written permission to test.

---

Y3llowDuck · [y3llowduck.github.io](https://y3llowduck.github.io)
