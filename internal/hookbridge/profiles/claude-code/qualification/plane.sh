#!/usr/bin/env bash
# The plane the qualification's cases run against: its keys, its signed policy,
# statement and floors, the collector, and the MCP server mcp-matcher calls.
# qualify.sh sources this file; it is not run on its own. The guard names what
# it reads from qualify.sh, so shellcheck still catches a misspelt variable.
: "${work?}" "${bin?}" "${plane?}" "${control?}" "${gateway?}" "${venv?}" "${py[0]?}"

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
"${bin}/${control}" runs open --project hooks --tenant local --principal-type service --principal operator \
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
