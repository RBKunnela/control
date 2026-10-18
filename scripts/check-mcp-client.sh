#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
#
# Runs docs/guides/connect-an-existing-mcp-setup.md end to end with an MCP
# client this module does not contain: the MCP project's Python SDK, locked in
# examples/connect-a-filesystem-server/client/uv.lock, against the reference
# filesystem server locked in that example's package-lock.json, through a
# plane built from this tree. It holds the plane to the guide's verify list:
# doctor classifies all 14 tools; a read runs; a write is pending and writes
# nothing; once approved, the same write runs once; retried, it is refused as
# used; a write the approver rejects is refused; and the trail is an unbroken
# chain the report program reads. It is not part of make quality; CI runs it
# as a job of its own on every pull request (ADR-0057).
#
#   scripts/check-mcp-client.sh
#
# Node.js is the node on PATH and must be NODE_VERSION; uv must be UV_VERSION.
set -euo pipefail

_CHECK_MCP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
# shellcheck source=tool-versions.env
. "${_CHECK_MCP_DIR}/tool-versions.env"
# shellcheck source=lib/python-env.sh
. "${_CHECK_MCP_DIR}/lib/python-env.sh"

root="$(cd "${_CHECK_MCP_DIR}/.." >/dev/null 2>&1 && pwd)"
example="${root}/examples/connect-a-filesystem-server"
# The product's names, as scripts/rename-product.sh rewrites them.
control=guardana-control
gateway=guardana-gateway
ns=guardana.control/

die() {
  printf 'check-mcp-client: %s\n' "$*" >&2
  exit 1
}

say() { printf 'check-mcp-client: %s\n' "$*"; }

have_node="$(node --version 2>/dev/null)" || die "node is not on PATH; Node.js ${NODE_VERSION} is needed"
[[ "${have_node}" == "v${NODE_VERSION}" ]] || die "node: want v${NODE_VERSION}, have ${have_node}"
python_uv_pinned || die "uv is not the pinned one"

work="$(mktemp -d)"
pids=()
# stop <pid> ends a process this script started, by force after five
# seconds, and forgets it.
stop() {
  local pid="$1" left i
  kill -TERM "${pid}" 2>/dev/null || true
  for i in $(seq 1 50); do
    kill -0 "${pid}" 2>/dev/null || break
    sleep 0.1
  done
  kill -KILL "${pid}" 2>/dev/null || true
  wait "${pid}" 2>/dev/null || true
  left=()
  for i in ${pids[@]+"${pids[@]}"}; do [[ "${i}" == "${pid}" ]] || left+=("${i}"); done
  pids=(${left[@]+"${left[@]}"})
}
cleanup() {
  local pid
  for pid in ${pids[@]+"${pids[@]}"}; do stop "${pid}"; done
  rm -rf "${work}"
}
trap cleanup EXIT

say "building the plane and the client"
go build -o "${work}/bin/" "${root}/cmd/${control}" "${root}/cmd/${gateway}" || die "the binaries do not build"
PATH="${work}/bin:${PATH}"

python_env "${work}" || die "no scratch directory for bytecode"
venv="${work}/venv"
"${clean[@]}" "UV_PROJECT_ENVIRONMENT=${venv}" uv sync --quiet --project "${example}/client" \
  --python "${CLIENT_PYTHON_VERSION}" --locked --no-build --no-install-project ||
  die "the locked client could not be installed; is CPython ${CLIENT_PYTHON_VERSION} there (make bootstrap)?"
py=("${clean[@]}" "${venv}/bin/python" -I)

# free_port prints a loopback port nothing listens on now, so two trees can
# run the check at once.
free_port() {
  "${py[@]}" -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}
listen="127.0.0.1:$(free_port)"
health="127.0.0.1:$(free_port)"
collector="127.0.0.1:$(free_port)"

say "step 1: the profile, the policy and the server"
cp -R "${example}" "${work}/plane"
cp "${root}/examples/starter-packs/approval-for-writes/policy.json" "${work}/plane/"
go -C "${root}/examples/evidence-report" build -o "${work}/plane/bin/" . || die "the report program does not build"
cd "${work}/plane"
npm ci --ignore-scripts --no-audit --no-fund --silent || die "npm ci refused the lockfile"
mkdir -m 700 spool approvals holds

say "step 2: keys, a signed policy and its statement"
bundle_key="$("${control}" policy keygen --out keys)"
freshness_key="$("${control}" policy keygen --out freshness)"
"${control}" policy sign --key keys/signing.key --out policy.bundle policy.json
"${control}" policy state init --kind signer --bundle-id starter-approval-for-writes signer-floors
"${control}" policy renew --key freshness/signing.key --bundle policy.bundle \
  --bundle-public-key keys/signing.pub --floor signer-floors --out policy.statement
"${control}" policy state init --kind plane --bundle-id starter-approval-for-writes floors

say "step 3: the profile filled in"
share="${work}/share"
mkdir -m 700 "${share}"
share="$(cd "${share}" && pwd -P)"
printf 'read through the plane\n' >"${share}/hello.txt"
line_of() { sed -n "s/^$1: //p" <<<"$2"; }
sed -e "s|BUNDLE_KEY_ID_FROM_KEYGEN|$(line_of key_id "${bundle_key}")|" \
  -e "s|BUNDLE_PUBLIC_KEY_FROM_KEYGEN|$(line_of public_key "${bundle_key}")|" \
  -e "s|FRESHNESS_KEY_ID_FROM_KEYGEN|$(line_of key_id "${freshness_key}")|" \
  -e "s|FRESHNESS_PUBLIC_KEY_FROM_KEYGEN|$(line_of public_key "${freshness_key}")|" \
  -e "s|/absolute/path/to/the/directory/to/share|${share}|" \
  -e "s|address: 127.0.0.1:8080|address: ${listen}|" \
  -e "s|http://127.0.0.1:4318/v1/logs|http://${collector}/v1/logs|" \
  plane.yaml >plane.yaml.filled
printf '\nhealth:\n  address: %s\n' "${health}" >>plane.yaml.filled
mv plane.yaml.filled plane.yaml
if grep -q 'FROM_KEYGEN\|/absolute/path' plane.yaml; then
  die "a placeholder is left in plane.yaml"
fi

say "step 4: a collector"
"${gateway}" collect --listen "${collector}" --out trail.jsonl &
collect_pid=$!
pids+=("${collect_pid}")

say "step 5: the classification"
doctor="$("${gateway}" doctor --config plane.yaml)" || die "doctor failed: ${doctor}"
grep -qE '(^|[^0-9])14 tool\(s\) listed, 14 classified, 0 unclassified' <<<"${doctor}" ||
  die "doctor did not classify all 14 tools: ${doctor}"

say "step 6: the plane"
"${gateway}" run --config plane.yaml >plane.log 2>&1 &
plane_pid=$!
pids+=("${plane_pid}")
for _ in $(seq 1 60); do
  if curl -fsS "http://${health}/healthz" >/dev/null 2>&1; then break; fi
  kill -0 "${plane_pid}" 2>/dev/null || die "the plane exited: $(cat plane.log)"
  sleep 0.5
done
curl -fsS "http://${health}/healthz" >/dev/null || die "the plane never answered /healthz: $(cat plane.log)"

url="http://${listen}/mcp"
drive() { "${py[@]}" "${example}/client/drive.py" --url "${url}" --ns "${ns}" "$@"; }
# field <name> <json> prints one member of an answer drive.py printed.
field() { "${py[@]}" -c 'import json, sys; print(json.loads(sys.argv[2]).get(sys.argv[1], ""))' "$1" "$2"; }
# blocked_with <code> <json> succeeds when the answer is the plane's block
# naming code among its reason codes.
blocked_with() {
  "${py[@]}" -c 'import json, sys; a = json.loads(sys.argv[2]); sys.exit(not (a["answer"] == "blocked" and sys.argv[1] in a["reason_codes"]))' "$1" "$2"
}

say "step 7: the client connects"
tools="$(drive tools)" || die "the client could not list the tools"
[[ "$(field protocol "${tools}")" == "2025-11-25" ]] || die "negotiated another protocol: ${tools}"
profiled="$(sed -n 's/^    tool: //p' plane.yaml | LC_ALL=C sort | tr '\n' ' ')"
listed="$("${py[@]}" -c 'import json, sys; print(" ".join(json.loads(sys.argv[1])["tools"]) + " ")' "${tools}")"
[[ "${listed}" == "${profiled}" ]] || die "the client saw tools ${listed}, the profile classifies ${profiled}"

say "step 8: a read and a write"
read_answer="$(drive call read_text_file "{\"path\": \"${share}/hello.txt\"}")"
[[ "$(field is_error "${read_answer}")" == False ]] || die "the read was refused: ${read_answer}"
grep -q 'read through the plane' <<<"$(field text "${read_answer}")" || die "the read did not return the file: ${read_answer}"

write_args="{\"path\": \"${share}/written.txt\", \"content\": \"written once\"}"
pending="$(drive call write_file "${write_args}")"
[[ "$(field answer "${pending}")" == pending && "$(field reason_code "${pending}")" == APPROVAL_PENDING ]] ||
  die "the write was not held: ${pending}"
[[ ! -e "${share}/written.txt" ]] || die "a held write reached the server"
approval="$(field approval_id "${pending}")"
[[ -n "${approval}" ]] || die "the held write names no approval: ${pending}"
"${control}" approvals list approvals |
  awk -v id="${approval}" '$1 == "approval" { this = ($2 == id) } this && /state/ && /APPROVAL_STATE_PENDING/ { found = 1 } END { exit !found }' ||
  die "approvals list does not show ${approval} pending"
"${control}" approvals approve --approver-id check approvals "${approval}" >/dev/null

ran="$(drive call write_file "${write_args}")"
[[ "$(field is_error "${ran}")" == False ]] || die "the approved write did not run: ${ran}"
[[ "$(cat "${share}/written.txt")" == "written once" ]] || die "the approved write wrote something else"

rm "${share}/written.txt"
used="$(drive call write_file "${write_args}")"
blocked_with APPROVAL_ALREADY_USED "${used}" || die "a second run of one approval was not refused: ${used}"
[[ ! -e "${share}/written.txt" ]] || die "a spent approval wrote again"

reject_args="{\"path\": \"${share}/rejected.txt\", \"content\": \"never written\"}"
held="$(drive call write_file "${reject_args}")"
[[ "$(field answer "${held}")" == pending && "$(field reason_code "${held}")" == APPROVAL_PENDING ]] ||
  die "the second write was not held: ${held}"
rejected_id="$(field approval_id "${held}")"
[[ -n "${rejected_id}" ]] || die "the second write names no approval: ${held}"
"${control}" approvals reject --approver-id check approvals "${rejected_id}" >/dev/null
refused="$(drive call write_file "${reject_args}")"
blocked_with APPROVAL_REJECTED "${refused}" || die "a rejected write was not refused: ${refused}"
[[ ! -e "${share}/rejected.txt" ]] || die "a rejected write reached the server"

say "step 9: the trail and the report"
# The rows the steps above make, one per request, as action, verdict, block,
# held, approval and end: the read, the approved write, the retry refused as
# used on a trail of its own, and the rejected write.
want_rows='read_text_file ALLOW - no - completed
write_file REQUIRE_APPROVAL - yes approved completed
write_file REQUIRE_APPROVAL DENY APPROVAL_ALREADY_USED no - blocked
write_file REQUIRE_APPROVAL DENY APPROVAL_REJECTED yes rejected blocked'
# report_rows succeeds when the report program reads every request as ended
# and its rows are exactly the ones above.
report_rows() {
  report="$("${gateway}" trail export trail.jsonl | bin/evidence-report 2>&1)" || return 1
  "${py[@]}" -c '
import sys
lines = [line.split("\t") for line in sys.argv[1].splitlines()]
head = lines[0]
cols = ["action", "verdict", "block", "held", "approval", "end"]
rows = sorted(" ".join(dict(zip(head, line))[c] for c in cols) for line in lines[1:] if len(line) == len(head))
sys.exit(rows != sorted(sys.argv[2].splitlines()))
' "${report}" "${want_rows}"
}
# The exporter ships while the plane runs; a plane that stops leaves what it
# did not ship in its spool for its next start, so the report is read first.
for _ in $(seq 1 60); do
  if report_rows; then break; fi
  sleep 0.5
done
report_rows || die "the report never held exactly the rows the steps made: ${report}"
"${gateway}" trail trail.jsonl >/dev/null || die "the trail is not one unbroken chain per request"
kill -TERM "${plane_pid}"
wait "${plane_pid}" || die "the plane did not stop cleanly: $(cat plane.log)"
kill -TERM "${collect_pid}"
wait "${collect_pid}" || die "the collector did not stop cleanly"
pids=()
say "ok: 14 tools classified; read ran; write held, approved, run once, then refused as used; rejected write refused; trail and report read"
