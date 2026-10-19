#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
#
# Qualifies the claude-code hook profile: runs each case of the profile's
# qualification against a plane built from this tree, through the runtime,
# and judges what the runtime did from what is left on disk: the project
# directory (the effect), the hook events the settings' hooks recorded, the
# plane's trail, approvals list and /healthz. A case whose tool call the
# model did not make is unknown, never passed.
#
#   qualify.sh [--runtime claude|stub] [--out <results.json>] [--events <dir>]
#
# --runtime claude, the default, starts the real runtime once per invocation,
# on the maintainer's subscription: it prints the count and the model and
# refuses to start unless QUALIFY_CONFIRM=yes. --runtime stub runs
# stub-runtime, a model of the hook protocol that says nothing about the
# runtime. QUALIFY_MAX_INVOCATIONS lowers the cap of 30; a case past it is
# skipped and unknown. QUALIFY_ONLY, a space-separated list of case groups,
# runs only those; every other case is unknown. Results go to --out, by default <runtime version>.json
# beside this script for the runtime and results.json in the work directory
# for the stub. Recorded events, which hold local paths, go to --events.
#
# Exit status: 0 every case passed, 1 one failed, 3 none failed and some are
# unknown, 2 the harness itself could not run.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
root="$(cd "${here}/../../../../.." >/dev/null 2>&1 && pwd)"
# shellcheck source=../../../../../scripts/tool-versions.env
. "${root}/scripts/tool-versions.env"
# shellcheck source=../../../../../scripts/lib/python-env.sh
. "${root}/scripts/lib/python-env.sh"

die() {
  printf 'qualify: %s\n' "$*" >&2
  exit 2
}

# brand <constant> prints a product name from internal/brand, the one place
# that spells it.
brand() {
  local value
  value="$(sed -n -E "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*\"([^\"]*)\".*\$/\1/p" "${root}/internal/brand/brand.go")"
  [[ -n "${value}" && "${value}" != *$'\n'* ]] || die "cannot read ${1} from internal/brand/brand.go"
  printf '%s\n' "${value}"
}
control="$(brand CLI)"
gateway="$(brand Gateway)"
token_var="$(brand EnvPrefix)RUN_TOKEN"
profile=claude-code
model=claude-haiku-5-5
planned=22
cap=30

say() { printf 'qualify: %s\n' "$*"; }

runtime=claude
out=""
events=""
while (($#)); do
  [[ $# -ge 2 ]] || die "usage: qualify.sh [--runtime claude|stub] [--out <results.json>] [--events <dir>]"
  case "$1" in
    --runtime) runtime="$2" ;;
    --out) out="$2" ;;
    --events) events="$2" ;;
    *) die "usage: qualify.sh [--runtime claude|stub] [--out <results.json>] [--events <dir>]" ;;
  esac
  shift 2
done
[[ "${runtime}" == claude || "${runtime}" == stub ]] || die "--runtime is claude or stub"
if [[ -n "${QUALIFY_MAX_INVOCATIONS:-}" ]]; then
  if [[ ! "${QUALIFY_MAX_INVOCATIONS}" =~ ^[0-9]+$ ]] || ((10#${QUALIFY_MAX_INVOCATIONS} > cap)); then
    die "QUALIFY_MAX_INVOCATIONS is a whole number up to ${cap}"
  fi
  cap=$((10#${QUALIFY_MAX_INVOCATIONS}))
fi

[[ -z "${QUALIFY_ONLY:-}" ]] || planned="fewer than ${planned}, only the groups ${QUALIFY_ONLY},"
if [[ "${runtime}" == claude ]]; then
  say "${planned} invocation(s) of the runtime planned, at most ${cap}, each with --model ${model}, on the maintainer's subscription"
  [[ "${QUALIFY_CONFIRM:-}" == yes ]] || die "refusing to start the runtime: set QUALIFY_CONFIRM=yes to spend them"
  command -v claude >/dev/null 2>&1 || die "the runtime is not on PATH"
else
  say "${planned} invocation(s) of stub-runtime planned, at most ${cap}; no model runs"
fi

work="$(mktemp -d)"
work="$(cd "${work}" && pwd -P)"
events="${events:-${work}/events}"
mkdir -p "${events}"
events="$(cd "${events}" && pwd -P)"
cases="${work}/cases"
plane="${work}/plane"
mkdir -p "${cases}" "${plane}" "${work}/p"
pids=()
# stop <pid> ends a process this script started, by force after five seconds.
stop() {
  kill -TERM "$1" 2>/dev/null || true
  for _ in $(seq 1 50); do
    kill -0 "$1" 2>/dev/null || break
    sleep 0.1
  done
  kill -KILL "$1" 2>/dev/null || true
  wait "$1" 2>/dev/null || true
}
cleanup() {
  local pid
  for pid in ${pids[@]+"${pids[@]}"}; do stop "${pid}"; done
}
trap cleanup EXIT
say "work directory ${work}"

say "building the plane and the bridge from the tree"
go build -o "${work}/bin/" "${root}/cmd/${control}" "${root}/cmd/${gateway}" || die "the binaries do not build"
bin="${work}/bin"

python_env "${work}" || die "no scratch directory for bytecode"
python_uv_pinned || die "uv is not the pinned one"
venv="${work}/venv"
"${clean[@]}" "UV_PROJECT_ENVIRONMENT=${venv}" uv sync --quiet \
  --project "${root}/examples/connect-a-filesystem-server/client" \
  --python "${CLIENT_PYTHON_VERSION}" --locked --no-build --no-install-project ||
  die "the locked MCP client environment could not be installed (make bootstrap)"
py=("${venv}/bin/python" "${isolated[@]}")
harness() { "${py[@]}" "${here}/harness.py" "$@"; }
if [[ "${runtime}" == claude ]]; then
  version="$(claude --version 2>&1)" || die "the runtime's --version failed: ${version}"
else
  version="$("${py[@]}" "${here}/stub-runtime" --version 2>&1)" || die "stub-runtime --version failed: ${version}"
fi

harness page-check --template "${here}/settings.json" --page "${root}/docs/reference/${profile}-hooks.md" ||
  die "the settings template is not the page's"

# The values the cases plant and the judge looks for.
secret="qualification-secret-$$"
replacement="replaced by another hook"
"${py[@]}" -c 'import json, sys; json.dump({"target.txt": "port = 3000\n", "second.txt": "mode = draft\n", "secret": sys.argv[1], "replacement": sys.argv[2]}, open(sys.argv[3], "w"))' \
  "${secret}" "${replacement}" "${cases}/seeds.json"
seed() { "${py[@]}" -c 'import json, sys; sys.stdout.write(json.load(open(sys.argv[1]))[sys.argv[2]])' "${cases}/seeds.json" "$1"; }

say "the plane: keys, a signed policy, its statement and floors"
sockdir="${work}/s"
mkdir -m 700 "${sockdir}" "${plane}/spool" "${plane}/approvals" "${plane}/holds" "${plane}/runs"
socket="${sockdir}/e.sock"
((${#socket} <= 103)) || die "the socket path ${socket} is over 103 bytes"
secret_file="${work}/p/obligation/secret.txt"
# A path under /private on macOS is also reachable without that prefix, and
# the runtime may name it either way; the rule names both.
secret_ids="\"${secret_file}\""
[[ "${secret_file}" != /private/* ]] || secret_ids+=", \"${secret_file#/private}\""
draft_file="${work}/p/rewrite-denied/draft.txt"
draft_ids="\"${draft_file}\""
[[ "${draft_file}" != /private/* ]] || draft_ids+=", \"${draft_file#/private}\""
cat >"${plane}/policy.json" <<EOF
{"apiVersion": "agent-policy/v1alpha1",
 "bundle": {"id": "hook-qualification", "version": "1", "serial": 1, "maxStaleSeconds": 3600},
 "rules": [
  {"id": "redact-the-secret", "effect": "ALLOW_WITH_OBLIGATIONS",
   "obligations": [{"type": "redact_fields", "params": {"fields": "file_path"}}],
   "when": {"action": {"name": ["Read"]}, "resource": {"id": [${secret_ids}]}}},
  {"id": "rewrite-the-draft", "effect": "ALLOW_WITH_OBLIGATIONS",
   "obligations": [{"type": "redact_fields", "params": {"fields": "content"}}],
   "when": {"action": {"name": ["Write"]}, "resource": {"id": [${draft_ids}]}}},
  {"id": "allow-reads", "effect": "ALLOW", "when": {"action": {"name": ["Read"]}}},
  {"id": "allow-writes", "effect": "ALLOW", "when": {"action": {"name": ["Write"]}}},
  {"id": "allow-agents", "effect": "ALLOW", "when": {"action": {"name": ["Agent"]}}},
  {"id": "allow-tool-search", "effect": "ALLOW", "when": {"action": {"name": ["ToolSearch"]}}},
  {"id": "deny-shell", "effect": "DENY", "when": {"action": {"name": ["Bash"]}}},
  {"id": "approve-edits", "effect": "REQUIRE_APPROVAL", "when": {"action": {"name": ["Edit"]}}}
 ]}
EOF
(
  cd "${plane}"
  bundle_key="$("${bin}/${control}" policy keygen --out keys)"
  freshness_key="$("${bin}/${control}" policy keygen --out freshness)"
  "${bin}/${control}" policy sign --key keys/signing.key --out policy.bundle policy.json >/dev/null
  "${bin}/${control}" policy state init --kind signer --bundle-id hook-qualification signer-floors >/dev/null
  "${bin}/${control}" policy renew --key freshness/signing.key --bundle policy.bundle \
    --bundle-public-key keys/signing.pub --floor signer-floors --out policy.statement >/dev/null
  "${bin}/${control}" policy state init --kind plane --bundle-id hook-qualification floors >/dev/null
  printf '%s\n' "${bundle_key}" >keys/keygen.txt
  printf '%s\n' "${freshness_key}" >freshness/keygen.txt
) || die "the policy could not be signed"
line_of() { sed -n "s/^$1: //p" "$2"; }
health="127.0.0.1:$(harness free-port)"
collector="127.0.0.1:$(harness free-port)"
cat >"${plane}/plane.yaml" <<EOF
mode: ENFORCE
project_id: hooks
tenant_id: local
environment: dev
listener:
  kind: enforce_api
  socket: ${socket}
  execution_lifetime: 2m
  principal:
    id: operator
  agent:
    id: coder
health:
  address: ${health}
policy:
  bundle_id: hook-qualification
  bundle_file: policy.bundle
  key_id: $(line_of key_id "${plane}/keys/keygen.txt")
  public_key: $(line_of public_key "${plane}/keys/keygen.txt")
  statement_file: policy.statement
  state_dir: floors
  freshness_key_id: $(line_of key_id "${plane}/freshness/keygen.txt")
  freshness_public_key: $(line_of public_key "${plane}/freshness/keygen.txt")
  poll_interval: 30s
approvals:
  provider: file
  dir: approvals
  hold_journal_dir: holds
  retry_after: 1s
runs:
  dir: runs
evidence:
  dir: spool
  fsync: every_record
  on_unwritable: block
export:
  endpoint: http://${collector}/v1/logs
  allow_plaintext: true
  linger: 5ms
tools:
  - name: Bash
    effect: EXECUTE
    provider: runtime
    resource_type: command
  - name: Write
    effect: WRITE
    provider: runtime
    resource_type: file
    resource_from: /file_path
  - name: Edit
    effect: WRITE
    provider: runtime
    resource_type: file
    resource_from: /file_path
  - name: Read
    effect: READ
    provider: runtime
    resource_type: file
    resource_from: /file_path
  - name: Agent
    effect: EXECUTE
    provider: runtime
    resource_type: agent
  - name: ToolSearch
    effect: READ
    provider: runtime
    resource_type: tool
EOF

# runs open makes an empty directory a runs directory, which the plane
# needs before it starts; this first run is never used.
"${bin}/${control}" runs open --tenant local --principal-type service --principal operator \
  --agent coder --ttl 1m "${plane}/runs" >/dev/null || die "the runs directory could not be made"

say "the collector and the plane"
"${bin}/${gateway}" collect --listen "${collector}" --out "${plane}/trail.jsonl" >"${plane}/collect.log" 2>&1 &
pids+=("$!")
(cd "${plane}" && exec "${bin}/${gateway}" run --config plane.yaml) >"${plane}/plane.log" 2>&1 &
plane_pid=$!
pids+=("${plane_pid}")
for _ in $(seq 1 60); do
  if curl -fsS "http://${health}/healthz" >/dev/null 2>&1; then break; fi
  kill -0 "${plane_pid}" 2>/dev/null || die "the plane exited: $(cat "${plane}/plane.log")"
  sleep 0.5
done
curl -fsS "http://${health}/healthz" >/dev/null || die "the plane never answered /healthz: $(cat "${plane}/plane.log")"

say "the MCP server for mcp-matcher"
mkdir -p "${work}/mcp"
cat >"${work}/mcp/server.py" <<'EOF'
import pathlib
import sys

from mcp.server.fastmcp import FastMCP

server = FastMCP("q")


@server.tool()
def stamp() -> str:
    """Write mcp-ran.txt in the project directory."""
    (pathlib.Path(sys.argv[1]) / "mcp-ran.txt").write_text("stamped\n")
    return "stamped"


server.run()
EOF
"${py[@]}" -c 'import json, sys; json.dump({"mcpServers": {"q": {"type": "stdio", "command": sys.argv[1], "args": ["-I", "-B", sys.argv[2], sys.argv[3]]}}}, open(sys.argv[4], "w"))' \
  "${venv}/bin/python" "${work}/mcp/server.py" "${work}/p/mcp-matcher" "${work}/mcp/config.json"

# A group is one project, one bridge state directory and one opened run; its
# invocations share them. The run is the group's own, so the mismatch that
# halts a run in rewrite halts no other case. Its settings file sits outside
# the project, so the runtime reads it once, from --settings.
group="" proj="" state="" token="" run_id="" settings_file=""
open_group() {
  local opened
  group="$1"
  proj="${work}/p/${group}"
  state="${work}/state/${group}"
  settings_file="${work}/settings/${group}.json"
  mkdir -p "${proj}" "${work}/settings" "${work}/state" "${cases}/${group}"
  mkdir -m 700 "${state}"
  opened="$("${bin}/${control}" runs open --tenant local --principal-type service --principal operator \
    --agent coder --ttl 2h "${plane}/runs")" || die "runs open failed: ${opened}"
  token="$(sed -n 's/^token: //p' <<<"${opened}")"
  run_id="$(sed -n 's/^run_id: //p' <<<"${opened}")"
  [[ -n "${token}" && -n "${run_id}" ]] || die "runs open printed no token: ${opened}"
}

quoted() { printf '%q ' "$@"; }
bridge=("${bin}/${control}" hook --profile "${profile}" --socket "${socket}")
# record <invocation> <act> [<argument>...] is a hook command that records each
# event into the invocation's events directory, then acts: pass hands it to
# the command the arguments name, rewrite replies with the content the one
# argument gives, and the other acts take none.
record() {
  local dir="${events}/${group}/$1" act="$2"
  shift 2
  mkdir -p "${dir}"
  local -a hook=("${venv}/bin/python" -I -B "${here}/record-hook" --events "${dir}" --act "${act}")
  case "${act}" in
    pass) quoted "${hook[@]}" -- "$@" ;;
    rewrite) quoted "${hook[@]}" --content "$1" ;;
    *) quoted "${hook[@]}" ;;
  esac
}
# settings <invocation> [<harness settings option>...] writes the project's
# settings, every hook recording into the invocation's events directory and
# passing the event to the bridge unless an option says otherwise.
settings() {
  local inv="$1"
  shift
  harness settings --template "${here}/settings.json" --out "${settings_file}" \
    --hook "$(record "${inv}" pass "${bridge[@]}" --state-dir "${state}")" "$@"
}

used=0
# settle waits until the plane's exporter has shipped every record it holds,
# so the trail read next is complete.
settle() {
  local left
  for _ in $(seq 1 100); do
    curl -fsS "http://${health}/healthz" >"${work}/healthz.json" || die "the plane stopped answering /healthz"
    left="$(harness field "${work}/healthz.json" spool.unacknowledged)"
    [[ "${left}" != 0 ]] || return 0
    sleep 0.2
  done
  die "the plane's spool never drained: ${left} record(s) unacknowledged"
}
# gather <invocation> keeps what the judge reads after it.
gather() {
  local d="${cases}/${group}/$1" status=0
  settle
  cp "${work}/healthz.json" "${d}/healthz.json"
  harness snapshot "${proj}" "${d}/files.json"
  "${bin}/${gateway}" trail export --run "${run_id}" "${plane}/trail.jsonl" >"${d}/trail.jsonl" ||
    die "trail export failed for ${run_id}"
  grep -q '"end_reached":true' "${d}/trail.jsonl" || die "trail export did not reach the end for ${run_id}"
  "${bin}/${control}" approvals list "${plane}/approvals" >"${d}/approvals.txt" 2>&1 || status=$?
  ((status == 0)) || die "approvals list exited ${status}: $(cat "${d}/approvals.txt")"
}
# reserve <invocation> [<n>] counts n invocations, one by default, or marks
# the invocation skipped when they would pass the cap.
reserve() {
  local d="${cases}/${group}/$1" n="${2:-1}"
  mkdir -p "${d}"
  if [[ -n "${QUALIFY_ONLY:-}" && " ${QUALIFY_ONLY} " != *" ${group} "* ]]; then
    : >"${d}/unselected"
    return 1
  fi
  if ((used + n > cap)); then
    : >"${d}/skipped"
    say "${group}/$1: skipped, ${n} more would pass the cap of ${cap} invocations"
    return 1
  fi
  used=$((used + n))
  curl -fsS "http://${health}/healthz" >"${d}/healthz.before.json" || die "the plane stopped answering /healthz"
}
# launch <invocation> <key> <allowed tools> <prompt> <tool> <input> [<mcp config>]
# runs the runtime once from the project directory, bounded in time.
launch() {
  local d="${cases}/${group}/$1" key="$2" allowed="$3" prompt="$4" tool="$5" input="$6" mcp="${7:-}"
  local -a cmd
  if [[ "${runtime}" == claude ]]; then
    cmd=(claude -p "${prompt}" --model "${model}" --setting-sources project
      --settings "${settings_file}" --strict-mcp-config --allowedTools "${allowed}"
      --max-turns 4 --output-format stream-json --verbose)
  else
    cmd=("${py[@]}" "${here}/stub-runtime" --settings "${settings_file}" --project "${proj}"
      --tool "${tool}" --input "${input}")
  fi
  [[ -z "${mcp}" ]] || cmd+=(--mcp-config "${mcp}")
  (cd "${proj}" && exec env -u CLAUDECODE -u CLAUDE_CODE_ENTRYPOINT "${token_var}=${token}" "${cmd[@]}") \
    >"${d}/stream-${key}.jsonl" 2>"${d}/runtime-${key}.err" &
  local pid=$! ticks=0 status=0
  pids+=("${pid}")
  while kill -0 "${pid}" 2>/dev/null; do
    if ((ticks >= 3000)); then
      printf 'qualify: stopped after 300 s\n' >>"${d}/runtime-${key}.err"
      stop "${pid}"
      break
    fi
    sleep 0.1
    ticks=$((ticks + 1))
  done
  wait "${pid}" || status=$?
  printf '%d\n' "${status}" >"${d}/runtime-${key}.exit"
}
# once <invocation> <launch arguments...> reserves, runs and gathers one invocation.
once() {
  local inv="$1"
  shift
  reserve "${inv}" || return 0
  say "${group}/${inv}"
  launch "${inv}" 1 "$@"
  gather "${inv}"
}
# approve <invocation> approves the approval its Edit was held for, and waits
# out the plane's retry_after.
approve() {
  local d="${cases}/${group}/$1" id status=0
  id="$(harness held "${events}/${group}/$1")"
  [[ -n "${id}" ]] || return 0
  "${bin}/${control}" approvals approve --approver-id qualification "${plane}/approvals" "${id}" \
    >"${d}/approve.out" 2>&1 || status=$?
  printf '{"approval": "%s", "exit": %d}\n' "${id}" "${status}" >"${d}/approved.json"
  sleep 1.2
}

write_prompt() { printf 'Use the Write tool to create the file %s in the current directory containing exactly: %s. Do nothing else.' "$1" "$2"; }
write_input() { "${py[@]}" -c 'import json, sys; print(json.dumps({"file_path": sys.argv[1], "content": sys.argv[2]}))' "${proj}/$1" "$2"; }
edit_prompt() {
  printf 'Use the Read tool to read %s, then use the Edit tool to replace the text "%s" with "%s" in it. If a tool call is refused, stop. Do nothing else.' "$1" "$2" "$3"
}
edit_input() {
  "${py[@]}" -c 'import json, sys; print(json.dumps({"file_path": sys.argv[1], "old_string": sys.argv[2], "new_string": sys.argv[3], "replace_all": False}))' \
    "${proj}/$1" "$2" "$3"
}

open_group allow
settings run
once run Write "$(write_prompt note.txt hello)" Write "$(write_input note.txt hello)"

open_group block
settings run
once run 'Bash(touch:*)' 'Use the Bash tool to run exactly this command: touch marker. Do nothing else.' \
  Bash '{"command": "touch marker"}'

open_group pending
seed target.txt >"${proj}/target.txt"
for inv in held resumed used; do
  settings "${inv}"
  [[ "${inv}" != used ]] || seed target.txt >"${proj}/target.txt"
  once "${inv}" 'Read Edit' "$(edit_prompt target.txt 'port = 3000' 'port = 8080')" \
    Edit "$(edit_input target.txt 'port = 3000' 'port = 8080')"
  [[ "${inv}" != held ]] || approve held
done

open_group concurrent
seed second.txt >"${proj}/second.txt"
settings hold
once hold 'Read Edit' "$(edit_prompt second.txt 'mode = draft' 'mode = final')" \
  Edit "$(edit_input second.txt 'mode = draft' 'mode = final')"
approve hold
settings race
if reserve race 2; then
  say "${group}/race, two at once"
  racers=()
  for key in a b; do
    launch race "${key}" 'Read Edit' "$(edit_prompt second.txt 'mode = draft' 'mode = final')" \
      Edit "$(edit_input second.txt 'mode = draft' 'mode = final')" &
    racers+=("$!")
    pids+=("$!")
  done
  wait "${racers[@]}"
  gather race
fi

open_group obligation
printf '%s\n' "${secret}" >"${proj}/secret.txt"
settings run
once run Read 'Use the Read tool to read secret.txt and repeat its first line. Do nothing else.' \
  Read "{\"file_path\": \"${proj}/secret.txt\"}"

open_group plane-down
mkdir -m 700 "${work}/nowhere"
bridge_down=("${bin}/${control}" hook --profile "${profile}" --socket "${work}/nowhere/e.sock" --state-dir "${state}")
harness settings --template "${here}/settings.json" --out "${settings_file}" \
  --hook "$(record run pass "${bridge_down[@]}")"
once run Write "$(write_prompt down.txt ran)" Write "$(write_input down.txt ran)"

for failing in timeout-block:sleep timeout-open:sleep crash-block:crash crash-open:crash garbage:garbage; do
  open_group "${failing%%:*}"
  opts=(--pre "$(record run "${failing#*:}")")
  [[ "${group}" != timeout-* ]] || opts+=(--pre-timeout 5)
  [[ "${group}" == *-block ]] || opts+=(--no-fail-closed)
  settings run "${opts[@]}"
  once run Write "$(write_prompt "${group}.txt" ran)" Write "$(write_input "${group}.txt" ran)"
done

open_group disabled
settings run --disable
once run Write "$(write_prompt disabled.txt ran)" Write "$(write_input disabled.txt ran)"

open_group rewrite
settings run --extra-pre "$(record run rewrite "${replacement}")"
once run Write "$(write_prompt note.txt hello)" Write "$(write_input note.txt hello)"

open_group rewrite-denied
settings run
once run Write "$(write_prompt draft.txt hello)" Write "$(write_input draft.txt hello)"

open_group mcp-matcher
settings run
once run mcp__q__stamp 'Use the stamp tool of the q MCP server once. Do nothing else.' \
  mcp__q__stamp '{}' "${work}/mcp/config.json"

open_group subagent
settings run
once run 'Agent Write' "Use the Agent tool to start one sub-agent with this task: use the Write tool to create the file ${proj}/sub.txt containing exactly: sub. Do not write any file yourself." \
  Agent "{\"description\": \"write sub.txt\", \"prompt\": \"Use the Write tool to create ${proj}/sub.txt containing exactly: sub.\"}"

open_group control-allow-all
harness settings --template "${here}/settings.json" --out "${settings_file}" \
  --hook "$(record run pass "${here}/controls/allow-all")"
once run 'Bash(touch:*)' 'Use the Bash tool to run exactly this command: touch marker. Do nothing else.' \
  Bash '{"command": "touch marker"}'

open_group control-report-proposed
mkdir -m 700 "${work}/state/report-proposed"
harness settings --template "${here}/settings.json" --out "${settings_file}" \
  --hook "$(record run pass "${venv}/bin/python" -I -B "${here}/controls/report-proposed" \
    --state "${work}/state/report-proposed" -- "${bridge[@]}" --state-dir "${state}")" \
  --extra-pre "$(record run rewrite "${replacement}")"
once run Write "$(write_prompt note.txt hello)" Write "$(write_input note.txt hello)"

say "${used} invocation(s) made"
kill -0 "${plane_pid}" 2>/dev/null || die "the plane exited during the cases: $(cat "${plane}/plane.log")"
for pid in "${pids[@]}"; do stop "${pid}"; done
pids=()

if [[ -z "${out}" ]]; then
  if [[ "${runtime}" == claude ]]; then
    [[ "${version}" =~ ([0-9]+(\.[0-9]+)+) ]] || die "no version in the runtime's --version: ${version}"
    out="${here}/${BASH_REMATCH[1]}.json"
  else
    out="${work}/results.json"
  fi
fi
commit="$(git -C "${root}" rev-parse HEAD 2>/dev/null)" || commit=unknown
dirty=unknown
if porcelain="$(git -C "${root}" status --porcelain 2>/dev/null)"; then
  dirty=false
  [[ -z "${porcelain}" ]] || dirty=true
fi
"${py[@]}" -c '
import hashlib, json, sys
keys = ["runtime", "runtime_version", "model", "bridge_commit", "tree_dirty", "os", "date", "settings_template", "invocations", "invocation_cap"]
doc = dict(zip(keys, sys.argv[1:]))
with open(doc["settings_template"], "rb") as f:
    doc["settings_template_sha256"] = hashlib.sha256(f.read()).hexdigest()
del doc["settings_template"]
doc["invocations"], doc["invocation_cap"] = int(doc["invocations"]), int(doc["invocation_cap"])
json.dump(doc, open(sys.argv[-1], "w"))
' "${runtime}" "${version}" "$([[ "${runtime}" == claude ]] && printf '%s' "${model}" || printf 'none')" \
  "${commit}" "${dirty}" "$(uname -sr)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${here}/settings.json" \
  "${used}" "${cap}" "${work}/meta.json"

harness judge "${cases}" "${events}" >"${work}/results.jsonl" || die "the judge failed"
say "events ${events} (they hold local paths; scrub them by hand before any becomes a fixture)"
say "results ${out}"
harness report --results "${work}/results.jsonl" --meta "${work}/meta.json" --out "${out}"
