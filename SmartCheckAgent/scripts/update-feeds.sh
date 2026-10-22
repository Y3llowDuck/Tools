#!/usr/bin/env bash
# Refresh SmartCheckAgent's local scanner feeds so the nuclei and searchsploit
# capabilities detect recent vulnerabilities without hitting the internet at
# scan time. Intended to run on a schedule (cron / systemd timer).
#
#   nuclei templates -> ~/.local/nuclei-templates  (runs as the invoking user)
#   exploitdb        -> /usr/share/exploitdb        (apt-managed here; needs root)
#
# Exit status is non-zero only if a feed that could be updated failed; skipped
# feeds (missing tool / no privileges) are warnings, not failures.
set -uo pipefail

log() { printf '[%s] %s\n' "$(date +%Y-%m-%dT%H:%M:%S)" "$*"; }
rc=0

# --- nuclei templates -------------------------------------------------------
if command -v nuclei >/dev/null 2>&1; then
  log "Updating nuclei templates..."
  if nuclei -update-templates -disable-update-check >/tmp/nuclei-update.$$ 2>&1; then
    tail -n 3 /tmp/nuclei-update.$$ | sed 's/^/    /'
  else
    log "ERROR: nuclei template update failed:"; tail -n 5 /tmp/nuclei-update.$$ | sed 's/^/    /'; rc=1
  fi
  rm -f /tmp/nuclei-update.$$
else
  log "SKIP: nuclei not on PATH."
fi

# --- exploitdb (searchsploit) ----------------------------------------------
if command -v searchsploit >/dev/null 2>&1; then
  if [ "$(id -u)" -eq 0 ]; then
    log "Updating exploitdb (apt, as root)..."
    if apt-get update -qq && apt-get install -y -qq exploitdb; then :; else log "ERROR: exploitdb update failed."; rc=1; fi
  elif sudo -n true 2>/dev/null; then
    log "Updating exploitdb (apt, via passwordless sudo)..."
    if sudo apt-get update -qq && sudo apt-get install -y -qq exploitdb; then :; else log "ERROR: exploitdb update failed."; rc=1; fi
  else
    log "SKIP exploitdb: apt-managed, needs root. Run this script as root, enable passwordless sudo for apt, or run 'sudo searchsploit -u' manually."
  fi
else
  log "SKIP: searchsploit not on PATH."
fi

log "Feed refresh done (rc=$rc)."
exit "$rc"
