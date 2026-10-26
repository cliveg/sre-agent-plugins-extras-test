#!/bin/bash
# =============================================================================
# deploy-extras.sh — Deploy a plugin's SRE Agent "extras" to a running agent
#
# The Plugin Marketplace installs the SKILL (and MCP connectors). This script
# deploys the pieces the marketplace does NOT carry: the subagent, the
# scheduled task(s), and the knowledge-base files. By DEFAULT it deploys ONLY
# those extras — the skill is expected to come from the marketplace.
#
# It is GENERIC and FILE-DRIVEN: point it at any plugin folder and it discovers
#   <plugin>/extras/knowledge-base/*.md            → /api/v1/AgentMemory/upload
#   <plugin>/extras/agents/*.yaml                  → /api/v2/extendedAgent/agents
#   <plugin>/extras/scheduled-tasks/*.yaml         → /api/v1/scheduledtasks
#   <plugin>/skills/*/SKILL.md   (only with --with-skill / --skills-only)
# Names/tools/cron are read straight from the files, so they stay the single
# source of truth. Re-run after any edit.
#
# Usage:
#   ./deploy-extras.sh --plugin plugins/sla-reporting --endpoint https://<agent>.<region>.azuresre.ai
#   ./deploy-extras.sh --plugin plugins/sla-reporting --resource-group <rg> [--agent-name <name>]
#   SRE_AGENT_ENDPOINT=https://... ./deploy-extras.sh --plugin plugins/sla-reporting
#   ./deploy-extras.sh --plugin plugins/sla-reporting --status     # show what's deployed
#   ./deploy-extras.sh --plugin plugins/sla-reporting --dry-run    # build bodies, push nothing
#   ./deploy-extras.sh --plugin plugins/sla-reporting --with-skill # also push the skill
#   ./deploy-extras.sh --plugin plugins/sla-reporting --skills-only # push ONLY the skill
#   ./deploy-extras.sh --plugin plugins/sla-reporting --workspace <name|guid|resourceId>
#                          # pin the Log Analytics workspace used for Activity
#                          # Log / history queries (overrides connector/auto-
#                          # discovery; or set LOG_ANALYTICS_WORKSPACE)
#
# Most users: install the SKILL from the marketplace in the portal, then run
# this (default extras-only). --with-skill / --skills-only are for maintainers
# who push the skill themselves instead of via the marketplace.
#
# Prereqs: az CLI (logged in), curl, python3/python with PyYAML (pip install pyyaml).
# Auth: your account needs the "SRE Agent Administrator" role on the agent.
# =============================================================================
set -uo pipefail

# ── Pretty output ────────────────────────────────────────────────────────────
RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; BLUE=$'\033[0;34m'; NC=$'\033[0m'

# ── Python (python3 on Linux/macOS, often python on Windows) ──────────────────
if command -v python3 &>/dev/null; then PYTHON=python3
elif command -v python &>/dev/null; then PYTHON=python
else echo "${RED}❌ Python not found. Install Python 3 (winget install Python.Python.3.12).${NC}"; exit 1; fi

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TMP_DIR="$SCRIPT_DIR/.tmp"; mkdir -p "$TMP_DIR"

# ── Args ─────────────────────────────────────────────────────────────────────
PLUGIN=""; RESOURCE_GROUP=""; AGENT_NAME=""; ENDPOINT_ARG=""
STATUS_ONLY=""; DRY_RUN=""; SKILLS_ONLY=""; WITH_SKILL=""; WORKSPACE_ARG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --plugin|-p)         PLUGIN="$2"; shift 2 ;;
    --resource-group|-g) RESOURCE_GROUP="$2"; shift 2 ;;
    --agent-name)        AGENT_NAME="$2"; shift 2 ;;
    --endpoint)          ENDPOINT_ARG="$2"; shift 2 ;;
    --workspace|-w)      WORKSPACE_ARG="$2"; shift 2 ;;
    --status)            STATUS_ONLY="true"; shift ;;
    --dry-run)           DRY_RUN="true"; shift ;;
    --skills-only)       SKILLS_ONLY="true"; shift ;;
    --with-skill)        WITH_SKILL="true"; shift ;;
    --extras-only)       shift ;;   # now the default — accepted for back-compat
    -h|--help)           grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "${RED}Unknown argument: $1${NC}"; exit 1 ;;
  esac
done

# Optional Log Analytics workspace override for Activity Log / history queries
# (flag wins over env). Empty = let the skill/agent use its connector or
# auto-discovery. Exported so the Python body builders can inject a
# WORKSPACE OVERRIDE directive into the subagent + scheduled-task prompts.
LOG_ANALYTICS_WORKSPACE="${WORKSPACE_ARG:-${LOG_ANALYTICS_WORKSPACE:-}}"; export LOG_ANALYTICS_WORKSPACE

# ── Resolve the plugin directory ──────────────────────────────────────────────
if [ -z "$PLUGIN" ]; then
  echo "${RED}❌ --plugin <path> is required (e.g. --plugin plugins/sla-reporting).${NC}"; exit 1
fi
if [ -d "$PLUGIN" ]; then PLUGIN_DIR="$(cd "$PLUGIN" && pwd)"
elif [ -d "$REPO_ROOT/$PLUGIN" ]; then PLUGIN_DIR="$(cd "$REPO_ROOT/$PLUGIN" && pwd)"
else echo "${RED}❌ Plugin folder not found: $PLUGIN${NC}"; exit 1; fi

SKILLS_GLOB="$PLUGIN_DIR/skills"
KB_DIR="$PLUGIN_DIR/extras/knowledge-base"
AGENTS_DIR="$PLUGIN_DIR/extras/agents"
TASKS_DIR="$PLUGIN_DIR/extras/scheduled-tasks"

# ── Verify PyYAML is importable ───────────────────────────────────────────────
if ! "$PYTHON" -c "import yaml" 2>/dev/null; then
  echo "${RED}❌ PyYAML not installed. Run: ${PYTHON} -m pip install pyyaml${NC}"; exit 1
fi

# ── Helper: data-plane bearer token (audience = https://azuresre.dev) ────────
get_token() { az account get-access-token --resource https://azuresre.dev --query accessToken -o tsv 2>/dev/null | tr -d '\r'; }

# Same call but KEEPS stderr — used only to surface the real Azure error when the
# silent get_token() comes back empty (e.g. Conditional Access blocking the token).
token_error() { az account get-access-token --resource https://azuresre.dev --query accessToken -o tsv 2>&1 1>/dev/null | tr -d '\r'; }

# ── Resolve the agent endpoint ───────────────────────────────────────────────
resolve_endpoint() {
  if [ -n "$ENDPOINT_ARG" ]; then echo "$ENDPOINT_ARG"; return; fi
  if [ -n "${SRE_AGENT_ENDPOINT:-}" ]; then echo "$SRE_AGENT_ENDPOINT"; return; fi
  local ep; ep="$(azd env get-value SRE_AGENT_ENDPOINT 2>/dev/null | tr -d '\r')"
  if echo "$ep" | grep -qiE 'http'; then echo "$ep"; return; fi
  if [ -n "$RESOURCE_GROUP" ]; then
    [ -z "$AGENT_NAME" ] && AGENT_NAME="$(az resource list -g "$RESOURCE_GROUP" --resource-type Microsoft.App/agents --query "[0].name" -o tsv 2>/dev/null | tr -d '\r')"
    [ -n "$AGENT_NAME" ] && az resource show -g "$RESOURCE_GROUP" --resource-type Microsoft.App/agents --name "$AGENT_NAME" --query "properties.agentEndpoint" -o tsv 2>/dev/null | tr -d '\r'
  fi
}

AGENT_ENDPOINT="$(resolve_endpoint)"
AGENT_ENDPOINT="${AGENT_ENDPOINT%/}"  # strip trailing slash
if [ -z "$AGENT_ENDPOINT" ] || ! echo "$AGENT_ENDPOINT" | grep -qiE 'http'; then
  echo "${RED}❌ Could not resolve the SRE Agent endpoint.${NC}"
  echo "   Pass one of: --endpoint <url>, --resource-group <rg>, or set SRE_AGENT_ENDPOINT."
  exit 1
fi

echo "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo "${BLUE}  Deploy plugin extras → SRE Agent${NC}"
echo "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo "  📦 Plugin:   $(basename "$PLUGIN_DIR")"
echo "  📡 Endpoint: ${AGENT_ENDPOINT}"
echo "  📁 Source:   ${PLUGIN_DIR}"
[ -n "$LOG_ANALYTICS_WORKSPACE" ] && echo "  🎯 Workspace override (Activity Log): ${LOG_ANALYTICS_WORKSPACE}"
[ -n "$DRY_RUN" ] && echo "  🧪 DRY RUN — bodies will be built but nothing is pushed"
echo ""

# Fail fast if we cannot get a token (not logged in / wrong tenant / Conditional Access)
if [ -z "$DRY_RUN" ] && [ -z "$(get_token)" ]; then
  echo "${RED}❌ Could not acquire a data-plane token (audience https://azuresre.dev).${NC}"
  err="$(token_error)"
  [ -n "$err" ] && { echo "${YELLOW}   Azure CLI said:${NC}"; echo "$err" | sed 's/^/     /'; }
  echo ""
  echo "   Common causes:"
  echo "     • Not signed in / wrong subscription → 'az login' then 'az account set --subscription <id>'."
  echo "     • Conditional Access requires a compliant/Entra-joined device. Azure Cloud"
  echo "       Shell is NOT a managed device, so token acquisition for this audience can be"
  echo "       blocked (AADSTS53000/53003). Run this deployer from an enrolled/compliant"
  echo "       workstation instead (Git Bash or WSL with the Azure CLI), or from a managed"
  echo "       VM that satisfies the policy — then re-run with --endpoint or --resource-group."
  echo "     • Your account lacks the 'SRE Agent Administrator' role on the target agent."
  exit 1
fi

# ── Read a skill name from its frontmatter ───────────────────────────────────
skill_name_of() { # $1=SKILL.md path
  "$PYTHON" - "$1" <<'PY'
import sys, yaml, os
t = open(sys.argv[1], encoding='utf-8').read()
fm = yaml.safe_load(t.split('---', 2)[1]) if t.startswith('---') else {}
print((fm or {}).get('name') or os.path.basename(os.path.dirname(sys.argv[1])))
PY
}
spec_name_of() { # $1=yaml path
  "$PYTHON" -c "import yaml,sys;print(yaml.safe_load(open(sys.argv[1],encoding='utf-8'))['spec']['name'])" "$1"
}

# ── Status-only mode ─────────────────────────────────────────────────────────
if [ -n "$STATUS_ONLY" ]; then
  TOKEN="$(get_token)"
  echo "${YELLOW}Deployed state:${NC}"
  for s in "$SKILLS_GLOB"/*/SKILL.md; do
    [ -f "$s" ] || continue
    n="$(skill_name_of "$s")"
    sc=$(curl -s -o /dev/null -w "%{http_code}" "${AGENT_ENDPOINT}/api/v2/extendedAgent/skills/${n}" -H "Authorization: Bearer ${TOKEN}")
    [ "$sc" = "200" ] && echo "  ${GREEN}✓${NC} skill   ${n}" || echo "  ${RED}✗${NC} skill   ${n} (HTTP ${sc})"
  done
  for a in "$AGENTS_DIR"/*.yaml; do
    [ -f "$a" ] || continue
    n="$(spec_name_of "$a")"
    ac=$(curl -s -o /dev/null -w "%{http_code}" "${AGENT_ENDPOINT}/api/v2/extendedAgent/agents/${n}" -H "Authorization: Bearer ${TOKEN}")
    [ "$ac" = "200" ] && echo "  ${GREEN}✓${NC} agent   ${n}" || echo "  ${RED}✗${NC} agent   ${n} (HTTP ${ac})"
  done
  for t in "$TASKS_DIR"/*.yaml; do
    [ -f "$t" ] || continue
    n="$(spec_name_of "$t")"
    found=$(curl -s "${AGENT_ENDPOINT}/api/v1/scheduledtasks" -H "Authorization: Bearer ${TOKEN}" 2>/dev/null \
      | N="$n" "$PYTHON" -c "import sys,json,os;print(sum(1 for t in (json.load(sys.stdin) or []) if t.get('name')==os.environ['N']))" 2>/dev/null || echo 0)
    [ "${found:-0}" -ge 1 ] 2>/dev/null && echo "  ${GREEN}✓${NC} task    ${n}" || echo "  ${RED}✗${NC} task    ${n}"
  done
  exit 0
fi

# ── Helper: PUT a JSON body file, echo HTTP code ─────────────────────────────
put_json() { # $1=url  $2=bodyfile
  curl -s -o "$TMP_DIR/resp.txt" -w "%{http_code}" -X PUT "$1" \
    -H "Authorization: Bearer $(get_token)" -H "Content-Type: application/json" \
    --data-binary "@$2"
}

# ── 1/4 Skills ───────────────────────────────────────────────────────────────
# By default the skill is installed from the Plugin Marketplace, so this step is
# skipped. Pass --with-skill (or --skills-only) to push it from this repo instead.
if [ -n "$WITH_SKILL" ] || [ -n "$SKILLS_ONLY" ]; then
  echo "${YELLOW}[1/4] Skills — skills/*/SKILL.md${NC}"
  any_skill=""
  for SKILL_FILE in "$SKILLS_GLOB"/*/SKILL.md; do
    [ -f "$SKILL_FILE" ] || continue
    any_skill=1
    SKILL_NAME="$(skill_name_of "$SKILL_FILE")"
    SKILL_BODY="$TMP_DIR/skill-body.json"
    SKILL_FILE="$SKILL_FILE" SKILL_NAME="$SKILL_NAME" "$PYTHON" - "$SKILL_BODY" <<'PY'
import os, sys, json, yaml
text = open(os.environ['SKILL_FILE'], encoding='utf-8').read()
fm = yaml.safe_load(text.split('---', 2)[1]) if text.startswith('---') else {}
fm = fm or {}
body = {
    "name": os.environ['SKILL_NAME'],
    "type": "Skill",
    "properties": {
        "description": (fm.get('description') or '').strip(),
        "tools": fm.get('tools', []),
        "skillContent": text,
    },
}
json.dump(body, open(sys.argv[1], 'w', encoding='utf-8'))
PY
    if [ -n "$DRY_RUN" ]; then
      echo "  ${BLUE}dry-run${NC} → PUT /api/v2/extendedAgent/skills/${SKILL_NAME} ($(wc -c <"$SKILL_BODY" | tr -d ' ') bytes)"
    else
      code=$(put_json "${AGENT_ENDPOINT}/api/v2/extendedAgent/skills/${SKILL_NAME}" "$SKILL_BODY")
      case "$code" in 200|201|202|204) echo "  ${GREEN}✓ ${SKILL_NAME}${NC} (HTTP ${code})";;
        *) echo "  ${RED}✗ ${SKILL_NAME} HTTP ${code}${NC}: $(head -c 200 "$TMP_DIR/resp.txt")";; esac
    fi
  done
  [ -z "$any_skill" ] && echo "  ${YELLOW}⏭️  no skills found${NC}"
  echo ""
else
  echo "${YELLOW}[1/4] Skills — installed from the marketplace (use --with-skill to push from this repo)${NC}"
  echo ""
fi

[ -n "$SKILLS_ONLY" ] && { rm -f "$TMP_DIR"/resp.txt "$TMP_DIR"/*-body.json 2>/dev/null || true; echo "${GREEN}Done (skills only).${NC}"; exit 0; }

# ── 2/4 Knowledge base ───────────────────────────────────────────────────────
# Run curl from *inside* KB_DIR with bare filenames. On Git Bash for Windows,
# native curl.exe cannot open a MinGW absolute path (/c/Users/...) embedded in
# -F "files=@...;type=...": MSYS path conversion is skipped because of the ';'
# and '=', so curl never makes the request and returns HTTP 000. Relative
# basenames avoid the conversion problem entirely.
echo "${YELLOW}[2/4] Knowledge base — extras/knowledge-base/*.md${NC}"
if ls "$KB_DIR"/*.md >/dev/null 2>&1; then
  NAMES=""; FORM_ARGS=()
  for f in "$KB_DIR"/*.md; do
    b="$(basename "$f")"; FORM_ARGS+=(-F "files=@${b};type=text/plain"); NAMES="${NAMES} ${b}"
  done
  if [ -n "$DRY_RUN" ]; then
    echo "  ${BLUE}dry-run${NC} → POST /api/v1/AgentMemory/upload :${NAMES}"
  else
    : > "$TMP_DIR/resp.txt"
    code=$(cd "$KB_DIR" && curl -s -o "$TMP_DIR/resp.txt" -w "%{http_code}" \
      -X POST "${AGENT_ENDPOINT}/api/v1/AgentMemory/upload" \
      -H "Authorization: Bearer $(get_token)" \
      -F "triggerIndexing=true" "${FORM_ARGS[@]}")
    case "$code" in 200|201|202) echo "  ${GREEN}✓ uploaded${NC}:${NAMES}";;
      *) echo "  ${RED}✗ HTTP ${code}${NC}: $(head -c 200 "$TMP_DIR/resp.txt")";; esac
  fi
else
  echo "  ${YELLOW}⏭️  no .md files in extras/knowledge-base${NC}"
fi
echo ""

# ── 3/4 Subagents ────────────────────────────────────────────────────────────
echo "${YELLOW}[3/4] Subagents — extras/agents/*.yaml${NC}"
any_agent=""
for AGENT_FILE in "$AGENTS_DIR"/*.yaml; do
  [ -f "$AGENT_FILE" ] || continue
  any_agent=1
  AGENT_ID_NAME="$(spec_name_of "$AGENT_FILE")"
  AGENT_BODY="$TMP_DIR/agent-body.json"
  AGENT_FILE="$AGENT_FILE" "$PYTHON" - "$AGENT_BODY" <<'PY'
import os, sys, json, yaml
spec = yaml.safe_load(open(os.environ['AGENT_FILE'], encoding='utf-8'))['spec']
instructions = spec.get("system_prompt", "")
ws = os.environ.get("LOG_ANALYTICS_WORKSPACE", "").strip()
if ws:
    instructions = (instructions.rstrip() + "\n\n"
        f"WORKSPACE OVERRIDE: When querying the Activity Log / Log Analytics for "
        f"history, use the workspace '{ws}' with QueryLogAnalyticsByWorkspaceId. "
        f"This overrides any connector or auto-discovery. If '{ws}' is a "
        f"customerId GUID, pass it directly; if it is a workspace name or "
        f"resource ID, resolve its customerId first.")
body = {
    "name": spec["name"],
    "type": "ExtendedAgent",
    "tags": [],
    "owner": "",
    "properties": {
        "instructions": instructions,
        "handoffDescription": spec.get("handoff_description", ""),
        "handoffs": spec.get("handoffs", []),
        "tools": spec.get("tools", []),
        "mcpTools": spec.get("mcp_tools", []),
        "allowParallelToolCalls": True,
        "enableSkills": True,
    },
}
json.dump(body, open(sys.argv[1], 'w', encoding='utf-8'))
PY
  if [ -n "$DRY_RUN" ]; then
    echo "  ${BLUE}dry-run${NC} → PUT /api/v2/extendedAgent/agents/${AGENT_ID_NAME} ($(wc -c <"$AGENT_BODY" | tr -d ' ') bytes)"
  else
    code=$(put_json "${AGENT_ENDPOINT}/api/v2/extendedAgent/agents/${AGENT_ID_NAME}" "$AGENT_BODY")
    case "$code" in 200|201|202|204) echo "  ${GREEN}✓ ${AGENT_ID_NAME}${NC} (HTTP ${code})";;
      *) echo "  ${RED}✗ ${AGENT_ID_NAME} HTTP ${code}${NC}: $(head -c 200 "$TMP_DIR/resp.txt")";; esac
  fi
done
[ -z "$any_agent" ] && echo "  ${YELLOW}⏭️  no agents in extras/agents${NC}"
echo ""

# ── 4/4 Scheduled tasks (update in place so run history is preserved) ────────
echo "${YELLOW}[4/4] Scheduled tasks — extras/scheduled-tasks/*.yaml${NC}"
any_task=""
for TASK_FILE in "$TASKS_DIR"/*.yaml; do
  [ -f "$TASK_FILE" ] || continue
  any_task=1
  TASK_NAME="$(spec_name_of "$TASK_FILE")"
  TASK_BODY="$TMP_DIR/task-body.json"
  TASK_FILE="$TASK_FILE" "$PYTHON" - "$TASK_BODY" <<'PY'
import os, sys, json, yaml
spec = yaml.safe_load(open(os.environ['TASK_FILE'], encoding='utf-8'))['spec']
prompt = spec.get("agent_prompt", "")
ws = os.environ.get("LOG_ANALYTICS_WORKSPACE", "").strip()
if ws:
    prompt = (prompt.rstrip() + "\n\n"
        f"WORKSPACE OVERRIDE: When querying the Activity Log / Log Analytics for "
        f"history, use the workspace '{ws}' with QueryLogAnalyticsByWorkspaceId — "
        f"this overrides connector/auto-discovery. If '{ws}' is a customerId GUID, "
        f"pass it directly; if it is a workspace name or resource ID, resolve its "
        f"customerId first.")
body = {
    "name": spec["name"],
    "description": (spec.get("description") or spec["name"]).strip(),
    "cronExpression": spec["cron"],
    "agentPrompt": prompt,
}
if spec.get("agent"):
    body["agent"] = spec["agent"]
json.dump(body, open(sys.argv[1], 'w', encoding='utf-8'))
PY
  if [ -n "$DRY_RUN" ]; then
    echo "  ${BLUE}dry-run${NC} → PUT /api/v1/scheduledtasks/{id} if it exists, else POST /api/v1/scheduledtasks (${TASK_NAME})"
  else
    TOKEN="$(get_token)"
    # Find an existing task with this name. If one exists, PUT to its id so the
    # run/query HISTORY (executionCount, createdAt, lastExecutionTime) is PRESERVED
    # across bug-fix redeploys. PATCH is not supported (405); PUT replaces fields
    # but keeps the id and history. Only POST-create when none exists. If legacy
    # duplicates exist (from the old delete-then-create flow), keep the OLDEST and
    # delete the rest. List + update inside one Python urllib call — a
    # curl|python|while-read pipeline runs in a subshell on Git Bash and silently
    # no-ops.
    EXISTING_ID=$(AGENT_ENDPOINT="$AGENT_ENDPOINT" TOKEN="$TOKEN" TASK_NAME="$TASK_NAME" "$PYTHON" - <<'PY'
import os, json, urllib.request
ep, tok, name = os.environ['AGENT_ENDPOINT'], os.environ['TOKEN'], os.environ['TASK_NAME']
hdr = {'Authorization': 'Bearer ' + tok}
def req(method, path):
    r = urllib.request.Request(ep + path, method=method, headers=hdr)
    return urllib.request.urlopen(r, timeout=30)
try:
    data = json.load(req('GET', '/api/v1/scheduledtasks')) or []
except Exception:
    data = []
matches = [t for t in data if t.get('name') == name and t.get('id')]
matches.sort(key=lambda t: t.get('createdAt') or '')  # oldest first: keep longest history
keep = matches[0]['id'] if matches else ''
for t in matches[1:]:
    try: req('DELETE', '/api/v1/scheduledtasks/' + t['id']).read()
    except Exception: pass
print(keep)
PY
)
    if [ -n "$EXISTING_ID" ]; then
      code=$(curl -s -o "$TMP_DIR/resp.txt" -w "%{http_code}" -X PUT \
        "${AGENT_ENDPOINT}/api/v1/scheduledtasks/${EXISTING_ID}" \
        -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \
        --data-binary "@$TASK_BODY")
      VERB="updated (history kept)"
    else
      code=$(curl -s -o "$TMP_DIR/resp.txt" -w "%{http_code}" -X POST \
        "${AGENT_ENDPOINT}/api/v1/scheduledtasks" \
        -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \
        --data-binary "@$TASK_BODY")
      VERB="scheduled"
    fi
    case "$code" in 200|201|202) echo "  ${GREEN}✓ ${TASK_NAME} ${VERB}${NC} (HTTP ${code}) — cron $(grep -m1 'cron:' "$TASK_FILE" | sed 's/.*cron: *//' | tr -d '\r')";;
      *) echo "  ${RED}✗ ${TASK_NAME} HTTP ${code}${NC}: $(head -c 200 "$TMP_DIR/resp.txt")";; esac
  fi
done
[ -z "$any_task" ] && echo "  ${YELLOW}⏭️  no tasks in extras/scheduled-tasks${NC}"
echo ""

rm -f "$TMP_DIR"/resp.txt "$TMP_DIR"/*-body.json 2>/dev/null || true
echo "${GREEN}Done.${NC} Re-run after any edit to a skill, subagent, or scheduled task."
if [ -z "$DRY_RUN" ]; then
  echo "Verify with: ${0##*/} --plugin ${PLUGIN} --endpoint ${AGENT_ENDPOINT} --status"
fi
exit 0
