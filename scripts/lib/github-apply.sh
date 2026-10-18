#!/usr/bin/env bash
# The calls scripts/github-bootstrap.sh changes GitHub with, apart from it so
# that a test can run them against a fake gh. Sourced, not run; it makes no
# call of its own, and reads REPO from scripts/lib/github-settings.sh.

# Every call is echoed before it is made, so the transcript shows exactly what
# was sent rather than what the script meant to send.
run() {
  local arg
  # %q so the echoed line is the line that ran, quoting included.
  printf '+'
  for arg in "$@"; do printf ' %q' "${arg}"; done
  printf '\n'
  "$@"
}

# run_quiet <command>...; as run, with the command's own output discarded,
# for calls whose answer is a JSON document nobody reads.
run_quiet() {
  local arg
  printf '+'
  for arg in "$@"; do printf ' %q' "${arg}"; done
  printf '\n'
  "$@" >/dev/null
}

# run_json <method> <endpoint>; reads the request body on stdin and prints it
# with the call, because the body is where the setting actually lives.
run_json() {
  local method="$1" endpoint="$2" body
  body="$(cat)"
  printf '+ gh api --method %s %s --input - <<JSON\n%s\nJSON\n' \
    "${method}" "${endpoint}" "${body}"
  printf '%s' "${body}" | gh api --method "${method}" "${endpoint}" --input - >/dev/null
}

# apply_environment <name> <body> <policy body> <policy type> <policy name>
apply_environment() {
  local environment="$1" body="$2" policy_body="$3" want_type="$4" want_name="$5"
  local policies policy_id policy_type policy_name have_policy=0
  run_json PUT "repos/${REPO}/environments/${environment}" <<<"${body}"
  # Any other policy on the environment would let another ref deploy to it, so
  # every policy but the declared one is removed.
  # Read by assignment, so a failed listing stops the run instead of leaving a
  # stray policy in place behind a report of success.
  policies="$(gh api "repos/${REPO}/environments/${environment}/deployment-branch-policies" --paginate \
    --jq '.branch_policies[] | "\(.id) \(.type) \(.name)"' </dev/null)"
  while read -r policy_id policy_type policy_name; do
    [[ -n "${policy_id}" ]] || continue
    if [[ "${policy_type}" == "${want_type}" && "${policy_name}" == "${want_name}" ]]; then
      have_policy=1
    else
      run_quiet gh api --method DELETE \
        "repos/${REPO}/environments/${environment}/deployment-branch-policies/${policy_id}" </dev/null
    fi
  done <<<"${policies}"
  if ((have_policy == 1)); then
    printf 'environment %s already takes the %s %s\n' "${environment}" "${want_type}" "${want_name}"
  else
    run_json POST "repos/${REPO}/environments/${environment}/deployment-branch-policies" <<<"${policy_body}"
  fi
}
