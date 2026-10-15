#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
#
# Applies the GitHub configuration of guardana/control that ADR-0025 and
# GOVERNANCE.md describe: repository settings, security features, Actions
# permissions, the two teams, labels, milestones, the release environments and
# the rulesets. What it sets is declared in scripts/lib/github-settings.sh,
# which scripts/github-settings-check.sh compares with GitHub without changing
# anything. Every step is idempotent: a run sets what that file names, and
# replaces a ruleset or the environment's tag policy of the same name, but it
# leaves a label, a ruleset or a team it does not name as it found it, apart
# from the retired labels it deletes, the retired milestones it closes and a
# two-approval part the declarations no longer need, which it deletes. A
# change to the configuration starts there.
#
# Nothing calls this file. It is not part of `make quality` and no workflow
# runs it: it changes a public repository, so a maintainer with the admin role
# runs it by hand, after reading the diff to this file and to the declarations.
#
#   CONFIRM=i-understand scripts/github-bootstrap.sh
#
# gh must be signed in with the repo and admin:org scopes, because the teams
# belong to the organization, and jq must be on PATH for the preflight. The repository must exist and hold main; this
# script creates neither.
set -euo pipefail

# Resolved from this file's location, so the script works from any directory.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)"
# shellcheck source=lib/github-settings.sh
. "${REPO_ROOT}/scripts/lib/github-settings.sh"

if [[ "${CONFIRM:-}" != "i-understand" ]]; then
  cat >&2 <<MSG
github-bootstrap: refusing to run.

This would change the settings, teams, environment and rulesets of the public
repository ${REPO}. Read the header of this file first. If that is what you
want:

  CONFIRM=i-understand scripts/github-bootstrap.sh

No GitHub call has been made.
MSG
  exit 2
fi

# Reads workflow YAML as this repository writes it rather than parsing YAML in
# general: indentation is the discriminator. Two spaces under `jobs:` is a job
# id, four spaces is a key of that job. A job's `name` wins when it has one,
# because that is the context GitHub reports; the id is used only when it does
# not. A `name` built from an expression is printed as written and will not
# match, which fails towards refusing rather than towards applying.
read -r -d '' CONTEXTS_AWK <<'AWK' || true
function flush() {
  if (job != "") {
    print (name != "" ? name : job)
    job = ""
    name = ""
  }
}
/^jobs:[[:space:]]*$/ { in_jobs = 1; next }
in_jobs == 0 { next }
/^[^[:space:]]/ { flush(); in_jobs = 0; next }
/^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
  flush()
  job = $1
  sub(/:$/, "", job)
  next
}
/^    name:[[:space:]]/ {
  if (job != "" && name == "") {
    name = $0
    sub(/^[[:space:]]*name:[[:space:]]*/, "", name)
    sub(/[[:space:]]+$/, "", name)
    gsub(/^["']|["']$/, "", name)
  }
  next
}
END { flush() }
AWK

# workflow_contexts <dir>; one check-run context per job, one per line.
workflow_contexts() {
  local dir="$1" file
  for file in "${dir}"/*.yml "${dir}"/*.yaml; do
    [[ -f "${file}" ]] || continue
    awk "${CONTEXTS_AWK}" "${file}"
  done
}

# A required check that no job reports blocks every merge to main until an
# admin removes the rule. So the list is checked against the workflow
# definitions in this tree before anything is changed. If it is wrong,
# reconcile the two lists; do not delete the check.
require_contexts_exist() {
  local dir="$1" available missing=0 context
  if [[ ! -d "${dir}" ]]; then
    printf 'github-bootstrap: no workflow directory at %s\n' "${dir}" >&2
    exit 1
  fi
  available="$(workflow_contexts "${dir}")"
  if [[ -z "${available}" ]]; then
    printf 'github-bootstrap: found no workflow jobs in %s\n' "${dir}" >&2
    exit 1
  fi
  for context in "${REQUIRED_CHECKS[@]}"; do
    if ! grep -qxF -- "${context}" <<<"${available}"; then
      printf 'github-bootstrap: no job reports the status check %s\n' "${context}" >&2
      missing=$((missing + 1))
    fi
  done
  if ((missing > 0)); then
    printf 'github-bootstrap: the contexts these workflows do report are:\n' >&2
    printf '%s\n' "${available}" | sed 's/^/  /' >&2
    printf 'github-bootstrap: refusing to require a check nothing reports.\n' >&2
    exit 1
  fi
  printf 'preflight: every required status check is reported by a job in %s\n' "${dir}"
}

# require_security_owned; every TWO_APPROVAL_PATHS entry lies under a path
# .github/CODEOWNERS gives to @guardana/security-maintainers.
require_security_owned() {
  local owned path entry covered missing=0
  owned="$(awk '$1 !~ /^#/ && $2 == "@guardana/security-maintainers" {
    p = $1; sub(/^\//, "", p); sub(/\/$/, "", p); print p }' "${REPO_ROOT}/.github/CODEOWNERS")"
  for path in "${TWO_APPROVAL_PATHS[@]}"; do
    path="${path%/\*\*}"
    covered=0
    while IFS= read -r entry; do
      [[ -n "${entry}" ]] || continue
      if [[ "${path}" == "${entry}" || "${path}" == "${entry}/"* ]]; then
        covered=1
      fi
    done <<<"${owned}"
    if ((covered == 0)); then
      printf 'github-bootstrap: CODEOWNERS gives %s to no security maintainer\n' "${path}" >&2
      missing=$((missing + 1))
    fi
  done
  if ((missing > 0)); then
    exit 1
  fi
  printf 'preflight: every two-approval path is owned by @guardana/security-maintainers\n'
}

# GitHub takes at most this many file patterns per required reviewer. It is
# written here rather than read from the declarations, so a change to their
# chunk size cannot also move the check of it.
GITHUB_REVIEWER_PATTERN_LIMIT=15

# require_reviewer_limits; refuses, before any GitHub call, a ruleset body
# GitHub would refuse with a 422 halfway through a run.
require_reviewer_limits() {
  local problems
  if ! command -v jq >/dev/null 2>&1; then
    printf 'github-bootstrap: jq is not on PATH, and the preflight reads the ruleset bodies with it\n' >&2
    exit 1
  fi
  problems="$(reviewer_limit_problems "${GITHUB_REVIEWER_PATTERN_LIMIT}")"
  if [[ -n "${problems}" ]]; then
    printf '%s\n' "${problems}" | sed 's/^/github-bootstrap: /' >&2
    printf 'github-bootstrap: refusing to send a ruleset GitHub would refuse.\n' >&2
    exit 1
  fi
  printf 'preflight: no required reviewer holds more than %d patterns, and the rulesets hold every two-approval path once\n' \
    "${GITHUB_REVIEWER_PATTERN_LIMIT}"
}

require_contexts_exist "${REPO_ROOT}/.github/workflows"
require_security_owned
require_reviewer_limits

# Every body is built here, by assignment, so a refusal stops the run before
# any GitHub call. The two that need a team id are built once with a stand-in
# id for that reason, and again once the id is known.
REPOSITORY_BODY="$(repository_json)"
TOPICS_BODY="$(topics_json)"
SECURITY_CONFIGURATION="$(security_configuration_json)"
TAG_POLICY_BODY="$(environment_tag_policy_json)"
LABEL_LINES="$(labels)"
TEAM_LINES="$(teams)"
MEMBER_LINES="$(team_members)"
RULESET_NAMES="$(ruleset_names)"
while IFS= read -r ruleset; do
  ruleset_json "${ruleset}" 0 >/dev/null
done <<<"${RULESET_NAMES}"
environment_json 0 >/dev/null

command -v gh >/dev/null 2>&1 || {
  printf 'github-bootstrap: gh is not on PATH\n' >&2
  exit 1
}

# The scopes of the signed-in token, from the header GitHub answers with.
scopes="$(gh api -i user | tr -d '\r' | sed -n 's/^[Xx]-[Oo][Aa]uth-[Ss]copes:[[:space:]]*//p')"
for scope in repo admin:org; do
  if ! tr ',' '\n' <<<"${scopes}" | sed 's/^[[:space:]]*//' | grep -qxF "${scope}"; then
    printf 'github-bootstrap: the gh token lacks the %s scope; run: gh auth refresh -h github.com -s %s\n' \
      "${scope}" "${scope}" >&2
    exit 1
  fi
done

if ! gh repo view "${REPO}" >/dev/null 2>&1; then
  printf 'github-bootstrap: %s does not exist; this script configures it and never creates it\n' "${REPO}" >&2
  exit 1
fi
if ! gh api "repos/${REPO}/branches/${DEFAULT_BRANCH}" >/dev/null 2>&1; then
  printf 'github-bootstrap: %s has no %s branch; push the history first\n' "${REPO}" "${DEFAULT_BRANCH}" >&2
  exit 1
fi

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

run gh auth status

# ensure_team <slug> <repository permission> <description>
ensure_team() {
  local slug="$1" permission="$2" description="$3"
  if gh api "orgs/${OWNER}/teams/${slug}" >/dev/null 2>&1; then
    printf 'team %s already exists\n' "${slug}"
  else
    run_quiet gh api --method POST "orgs/${OWNER}/teams" \
      -f "name=${slug}" -f "description=${description}" -f privacy=closed
  fi
  run_quiet gh api --method PUT "orgs/${OWNER}/teams/${slug}/repos/${REPO}" \
    -f "permission=${permission}"
}

while IFS='|' read -r team_slug team_permission team_description; do
  [[ -n "${team_slug}" ]] || continue
  ensure_team "${team_slug}" "${team_permission}" "${team_description}" </dev/null
done <<<"${TEAM_LINES}"
# The bootstrap adds the declared members and removes nobody: a member it does
# not know is for a maintainer to look at, and the check reports one.
while IFS='|' read -r team_slug member_login member_role; do
  [[ -n "${team_slug}" ]] || continue
  run_quiet gh api --method PUT "orgs/${OWNER}/teams/${team_slug}/memberships/${member_login}" \
    -f "role=${member_role}" </dev/null
done <<<"${MEMBER_LINES}"
MAINTAINERS_TEAM_ID="$(gh api "orgs/${OWNER}/teams/maintainers" --jq .id)"
require_id "the maintainers team" "${MAINTAINERS_TEAM_ID}"
SECURITY_TEAM_ID="$(gh api "orgs/${OWNER}/teams/security-maintainers" --jq .id)"
require_id "the security-maintainers team" "${SECURITY_TEAM_ID}"

# apply_ruleset <name>; reads the ruleset on stdin and creates it, or replaces
# the repository's ruleset of that name, so a re-run converges on the
# declarations.
apply_ruleset() {
  local name="$1" id
  id="$(gh api "repos/${REPO}/rulesets?includes_parents=false" --paginate \
    --jq ".[] | select(.name == \"${name}\") | .id" </dev/null)"
  if [[ -z "${id}" ]]; then
    run_json POST "repos/${REPO}/rulesets"
  elif [[ "${id}" =~ ^[0-9]+$ ]]; then
    run_json PUT "repos/${REPO}/rulesets/${id}"
  else
    printf 'github-bootstrap: more than one ruleset is named %s\n' "${name}" >&2
    exit 1
  fi
}

# Rulesets come first after the teams, in the order ruleset_names gives.
while IFS= read -r ruleset; do
  body="$(ruleset_json "${ruleset}" "${SECURITY_TEAM_ID}")"
  apply_ruleset "${ruleset}" <<<"${body}"
done <<<"${RULESET_NAMES}"
# A two-approval part beyond the count the declarations need is left over from
# a longer list. Only a ruleset named exactly as a part is deleted; its paths
# are held by the parts applied above.
existing_rulesets="$(gh api "repos/${REPO}/rulesets?includes_parents=false" --paginate \
  --jq '.[] | "\(.id)\t\(.name)"' </dev/null)"
while IFS=$'\t' read -r ruleset_id ruleset_name; do
  [[ "${ruleset_name}" == "${TWO_APPROVAL_PART_PREFIX}"* ]] || continue
  [[ "${ruleset_name#"${TWO_APPROVAL_PART_PREFIX}"}" =~ ^[0-9]+$ ]] || continue
  if grep -qxF -- "${ruleset_name}" <<<"${RULESET_NAMES}"; then
    continue
  fi
  if [[ ! "${ruleset_id}" =~ ^[0-9]+$ ]]; then
    printf 'github-bootstrap: no numeric id for the ruleset %s\n' "${ruleset_name}" >&2
    exit 1
  fi
  printf 'deleting the leftover ruleset %s: the two-approval paths need fewer parts\n' "${ruleset_name}"
  run_quiet gh api --method DELETE "repos/${REPO}/rulesets/${ruleset_id}" </dev/null
done <<<"${existing_rulesets}"

ENVIRONMENT_BODY="$(environment_json "${MAINTAINERS_TEAM_ID}")"
for environment in "${ENVIRONMENTS[@]}"; do
  run_json PUT "repos/${REPO}/environments/${environment}" <<<"${ENVIRONMENT_BODY}"
  # Any other policy on the environment would let another ref deploy to it, so
  # every policy but the one for v* tags is removed.
  # Read by assignment, so a failed listing stops the run instead of leaving a
  # stray policy in place behind a report of success.
  policies="$(gh api "repos/${REPO}/environments/${environment}/deployment-branch-policies" --paginate \
    --jq '.branch_policies[] | "\(.id) \(.type) \(.name)"' </dev/null)"
  have_tag_policy=0
  while read -r policy_id policy_type policy_name; do
    [[ -n "${policy_id}" ]] || continue
    if [[ "${policy_type}" == "tag" && "${policy_name}" == "${ENVIRONMENT_TAG_POLICY}" ]]; then
      have_tag_policy=1
    else
      run_quiet gh api --method DELETE \
        "repos/${REPO}/environments/${environment}/deployment-branch-policies/${policy_id}" </dev/null
    fi
  done <<<"${policies}"
  if ((have_tag_policy == 1)); then
    printf 'environment %s already takes %s tags\n' "${environment}" "${ENVIRONMENT_TAG_POLICY}"
  else
    run_json POST "repos/${REPO}/environments/${environment}/deployment-branch-policies" <<<"${TAG_POLICY_BODY}"
  fi
done

run_json PATCH "repos/${REPO}" <<<"${REPOSITORY_BODY}"

run_json PUT "repos/${REPO}/topics" <<<"${TOPICS_BODY}"

configuration_id="$(gh api "orgs/${OWNER}/code-security/configurations" --paginate \
  --jq ".[] | select(.name == \"${REPO_NAME}\") | .id" </dev/null)"
if [[ -z "${configuration_id}" ]]; then
  printf '+ gh api --method POST orgs/%s/code-security/configurations --input - <<JSON\n%s\nJSON\n' \
    "${OWNER}" "${SECURITY_CONFIGURATION}"
  configuration_id="$(printf '%s' "${SECURITY_CONFIGURATION}" |
    gh api --method POST "orgs/${OWNER}/code-security/configurations" --input - --jq .id)"
else
  printf '%s' "${SECURITY_CONFIGURATION}" |
    run_json PATCH "orgs/${OWNER}/code-security/configurations/${configuration_id}"
fi
if [[ ! "${configuration_id}" =~ ^[0-9]+$ ]]; then
  printf 'github-bootstrap: no numeric id for the security configuration\n' >&2
  exit 1
fi
REPO_ID="$(gh api "repos/${REPO}" --jq .id </dev/null)"
if [[ ! "${REPO_ID}" =~ ^[0-9]+$ ]]; then
  printf 'github-bootstrap: no numeric id for %s\n' "${REPO}" >&2
  exit 1
fi
run_json POST "orgs/${OWNER}/code-security/configurations/${configuration_id}/attach" <<JSON
{ "scope": "selected", "selected_repository_ids": [${REPO_ID}] }
JSON

# A published release keeps its tag and its assets as they were published.
run gh api --method PUT "repos/${REPO}/immutable-releases"

actions_permissions_json | run_json PUT "repos/${REPO}/actions/permissions"
actions_workflow_json | run_json PUT "repos/${REPO}/actions/permissions/workflow"
actions_fork_approval_json | run_json PUT "repos/${REPO}/actions/permissions/fork-pr-contributor-approval"

# --force updates a label that already exists instead of failing, so this is
# safe to re-run after the label set changes.
while IFS='|' read -r name color description; do
  [[ -n "${name}" ]] || continue
  run gh label create "${name}" --repo "${REPO}" \
    --color "${color}" --description "${description}" --force </dev/null
done <<<"${LABEL_LINES}"
# Read by assignment, so a failed listing stops the run rather than leaving a
# retired label in place. A retired label an issue or a pull request still
# holds is kept, so deleting it takes nothing off them unseen.
existing_labels="$(gh api "repos/${REPO}/labels" --paginate --jq '.[].name' </dev/null)"
for retired in "${RETIRED_LABELS[@]}"; do
  name="$(awk -v n="${retired}" 'tolower($0) == tolower(n) { print; exit }' <<<"${existing_labels}")"
  [[ -n "${name}" ]] || continue
  holders="$(gh api --method GET "repos/${REPO}/issues" -f "labels=${name}" -f state=all -f per_page=100 \
    --paginate --jq 'length' </dev/null | awk '{ n += $1 } END { print n + 0 }')"
  if [[ "${holders}" != "0" ]]; then
    printf 'label %s kept: %s issue(s) or pull request(s) hold it\n' "${name}" "${holders}"
  else
    run gh label delete "${name}" --repo "${REPO}" --yes </dev/null
  fi
done

existing_milestones="$(gh api "repos/${REPO}/milestones?state=all" --paginate \
  --jq '.[] | "\(.number)\t\(.state)\t\(.title)"' </dev/null)"
# milestone_field <title> <field number>; the number or the state of the
# milestone of that title, empty when there is none.
milestone_field() {
  awk -F '\t' -v title="$1" -v field="$2" '$3 == title { print $field; exit }' <<<"${existing_milestones}"
}
for milestone in "${MILESTONES[@]}"; do
  number="$(milestone_field "${milestone}" 1)"
  if [[ -z "${number}" ]]; then
    run_quiet gh api --method POST "repos/${REPO}/milestones" -f "title=${milestone}" </dev/null
  elif [[ "$(milestone_field "${milestone}" 2)" != "open" ]]; then
    run_quiet gh api --method PATCH "repos/${REPO}/milestones/${number}" -f state=open </dev/null
  else
    printf 'milestone %s already exists\n' "${milestone}"
  fi
done
for milestone in "${RETIRED_MILESTONES[@]}"; do
  number="$(milestone_field "${milestone}" 1)"
  if [[ -n "${number}" && "$(milestone_field "${milestone}" 2)" == "open" ]]; then
    run_quiet gh api --method PATCH "repos/${REPO}/milestones/${number}" -f state=closed </dev/null
  fi
done

printf 'github-bootstrap: finished for %s\n' "${REPO}"
