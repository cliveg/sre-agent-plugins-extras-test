#!/bin/bash
# =============================================================================
# install.sh — One-shot Cloud Shell bootstrap for SRE Agent plugin extras.
#
# Designed to be piped straight from GitHub — NO git clone required:
#
#   curl -fsSL https://raw.githubusercontent.com/cliveg/sre-agent-plugins-extras-test/main/tools/install.sh \
#     | bash -s -- --plugin sla-reporting --resource-group <rg>
#
#   # or target the agent directly by URL:
#   curl -fsSL https://raw.githubusercontent.com/cliveg/sre-agent-plugins-extras-test/main/tools/install.sh \
#     | bash -s -- --plugin sla-reporting --endpoint https://<agent>.<region>.azuresre.ai
#
# What it does:
#   1. Downloads deploy-extras.sh and ONLY the chosen plugin's extras
#      (knowledge-base, agents, scheduled-tasks) into a temp dir.
#   2. Runs deploy-extras.sh against your agent (extras-only by default —
#      the SKILL is expected to come from the Plugin Marketplace in the portal).
#
# Any flags after the plugin/repo options are passed through to deploy-extras.sh
# (e.g. --status, --dry-run, --with-skill, --agent-name).
#
# Prereqs in Cloud Shell: az (already logged in), curl, python3 (+pyyaml).
# Your account needs the "SRE Agent Administrator" role on the agent.
# =============================================================================
set -euo pipefail

REPO="cliveg/sre-agent-plugins-extras-test"
BRANCH="main"
PLUGIN="sla-reporting"
PASS=()   # passthrough args for deploy-extras.sh

while [ $# -gt 0 ]; do
  case "$1" in
    --plugin|-p) PLUGIN="$2"; shift 2 ;;
    --branch)    BRANCH="$2"; shift 2 ;;
    --repo)      REPO="$2"; shift 2 ;;
    *)           PASS+=("$1"); shift ;;
  esac
done

API="https://api.github.com/repos/${REPO}/contents"
RAW="https://raw.githubusercontent.com/${REPO}/${BRANCH}"

# Find a usable Python (Cloud Shell has python3; Git Bash on Windows may only
# have 'python' or a versioned path).
PYTHON=""
for c in python3 python /c/Python314/python; do
  if command -v "$c" >/dev/null 2>&1; then PYTHON="$c"; break; fi
done
if [ -z "$PYTHON" ]; then
  echo "ERROR: no python interpreter found (need python3 or python)." >&2; exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PDIR="$WORK/plugins/$PLUGIN"
mkdir -p "$PDIR/extras" "$WORK/tools"

echo "Bootstrapping '$PLUGIN' from ${REPO}@${BRANCH} (no clone)…"
echo "Downloading deploy-extras.sh…"
curl -fsSL "${RAW}/tools/deploy-extras.sh" -o "$WORK/tools/deploy-extras.sh"
chmod +x "$WORK/tools/deploy-extras.sh"

# Download every file in a repo directory (public repo → no auth needed).
fetch_dir() { # $1 = repo-relative dir   $2 = local dest dir
  local rel="$1" dest="$2" json
  json="$(curl -fsSL "${API}/${rel}?ref=${BRANCH}" 2>/dev/null || true)"
  echo "$json" | "$PYTHON" -c '
import sys, json
try:
    items = json.load(sys.stdin)
except Exception:
    sys.exit(0)
if not isinstance(items, list):
    sys.exit(0)
for it in items:
    if it.get("type") == "file" and it.get("download_url"):
        print(it["name"] + "\t" + it["download_url"])
' | tr -d '\r' | while IFS=$'\t' read -r name url; do
      [ -n "${name:-}" ] || continue
      mkdir -p "$dest"
      curl -fsSL "$url" -o "$dest/$name"
      echo "  • ${rel}/${name}"
    done
}

echo "Fetching extras…"
fetch_dir "plugins/$PLUGIN/extras/knowledge-base" "$PDIR/extras/knowledge-base"
fetch_dir "plugins/$PLUGIN/extras/agents"         "$PDIR/extras/agents"
fetch_dir "plugins/$PLUGIN/extras/scheduled-tasks" "$PDIR/extras/scheduled-tasks"

# Only fetch the skill if the caller explicitly wants it pushed from the repo.
if printf '%s\n' "${PASS[@]:-}" | grep -qE -- '--with-skill|--skills-only'; then
  echo "Fetching skill(s)…"
  curl -fsSL "${API}/plugins/$PLUGIN/skills?ref=${BRANCH}" 2>/dev/null | "$PYTHON" -c '
import sys, json
try:
    items = json.load(sys.stdin)
except Exception:
    sys.exit(0)
if not isinstance(items, list):
    sys.exit(0)
for it in items:
    if it.get("type") == "dir":
        print(it["name"])
' | tr -d '\r' | while read -r sk; do
      [ -n "${sk:-}" ] || continue
      fetch_dir "plugins/$PLUGIN/skills/$sk" "$PDIR/skills/$sk"
    done
fi

echo ""
if [ ${#PASS[@]} -gt 0 ]; then
  exec "$WORK/tools/deploy-extras.sh" --plugin "$PDIR" "${PASS[@]}"
else
  exec "$WORK/tools/deploy-extras.sh" --plugin "$PDIR"
fi
