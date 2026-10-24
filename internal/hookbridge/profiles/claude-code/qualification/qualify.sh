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

# shellcheck source=plane.sh
. "${here}/plane.sh"
# shellcheck source=invocations.sh
. "${here}/invocations.sh"

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
