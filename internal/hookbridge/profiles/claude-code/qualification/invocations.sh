#!/usr/bin/env bash
# How one case group and each of its invocations are prepared, run, bounded
# and kept for the judge, and the prompts and inputs the cases give the
# runtime. qualify.sh sources this file after plane.sh, which sets socket and
# health; it is not run on its own. The guard names what it reads from both.
: "${work?}" "${bin?}" "${plane?}" "${control?}" "${gateway?}" "${venv?}" "${py[0]?}" \
  "${here?}" "${cases?}" "${events?}" "${profile?}" "${model?}" "${runtime?}" "${cap?}" \
  "${token_var?}" "${socket?}" "${health?}"

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
  # A snapshot that fails leaves none, and the invocation's cases are unknown.
  harness snapshot "${proj}" "${d}/files.json" || say "${group}/$1: the project's snapshot failed"
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
# launch <invocation> <key> <allowed tools> <prompt> <tool> <input> [<mcp config> [<tool> <input>]]
# runs the runtime once from the project directory, bounded in time. The tools
# and inputs are the calls stub-runtime makes in the prompt's place; the
# second pair is a call it makes after the first.
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
    [[ $# -lt 9 ]] || cmd+=(--tool "$8" --input "$9")
  fi
  [[ -z "${mcp}" ]] || cmd+=(--mcp-config "${mcp}")
  # The token is set by builtins, so it never sits in a process's arguments.
  (cd "${proj}" && unset CLAUDECODE CLAUDE_CODE_ENTRYPOINT && export "${token_var}=${token}" && exec "${cmd[@]}") \
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
