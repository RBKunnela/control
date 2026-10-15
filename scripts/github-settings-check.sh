#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
#
# Compares the GitHub configuration of guardana/control with what
# scripts/lib/github-settings.sh declares and scripts/github-bootstrap.sh
# applies: the repository settings, topics, immutable releases, the Actions
# permissions, the two teams with their members, who else holds maintain or
# admin, the release environments, the rulesets, the labels, the milestones
# and the code security configuration. It only reads: every call is a GET
# through `gh api`, and the bodies it compares against are the ones the
# bootstrap sends.
#
# It prints one line per item: `ok <item>`, `drift <item>: <declared vs live>`,
# or `unknown <item>: <why>` when an answer could not be read or parsed. It
# exits 0 only when every item is ok, 1 when any item drifted, and 2 when none
# drifted but one is unknown, or when it could not start or failed on the way.
#
# Nothing calls this file. It is not part of `make quality` and no workflow
# runs it: some of what it reads, such as a ruleset's bypass actors or the
# security configuration, needs a token with admin access to the repository.
#
#   scripts/github-settings-check.sh [--save <dir>]
#
# --save writes every answer it read into <dir>, a new directory it creates
# with mode 700 or an empty one of the caller's, as a record of the live
# settings to restore from. It never writes through a link or over a file.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)"
# shellcheck source=lib/github-settings.sh
. "${REPO_ROOT}/scripts/lib/github-settings.sh"

# Every planned exit sets `planned`. Any other, such as a set -e exit on a
# failure nothing below handles, ends the run as unknown with status 2, so it
# can never pass for ok or for drift.
planned=""
work=""
failed_line=""
trap 'failed_line="${LINENO}"' ERR
# shellcheck disable=SC2329 # the EXIT trap calls it
on_exit() {
  local status=$?
  [[ -z "${work}" ]] || rm -rf "${work}"
  if [[ -z "${planned}" ]]; then
    printf 'unknown all: the run stopped early (status %s, line %s), so the lines above are not the whole check\n' \
      "${status}" "${failed_line:-unknown}"
    exit 2
  fi
}
trap on_exit EXIT

die() {
  printf 'github-settings-check: %s\n' "$*" >&2
  planned=2
  exit 2
}

save_dir=""
while (($# > 0)); do
  case "$1" in
    --save)
      (($# >= 2)) && [[ -n "$2" ]] || die "usage: scripts/github-settings-check.sh [--save <dir>]"
      save_dir="$2"
      shift 2
      ;;
    *) die "usage: scripts/github-settings-check.sh [--save <dir>]" ;;
  esac
done

if [[ -n "${save_dir}" ]]; then
  [[ ! -L "${save_dir}" ]] || die "--save ${save_dir} is a symbolic link"
  if [[ -e "${save_dir}" ]]; then
    [[ -d "${save_dir}" ]] || die "--save ${save_dir} exists and is not a directory"
    [[ -O "${save_dir}" ]] || die "--save ${save_dir} belongs to someone else"
    entries="$(ls -A -- "${save_dir}")" || die "--save ${save_dir} cannot be listed"
    [[ -z "${entries}" ]] || die "--save ${save_dir} is not empty; refusing to mix two records"
  else
    mkdir -m 700 -- "${save_dir}" || die "--save ${save_dir} could not be created"
  fi
fi

for tool in gh jq; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    printf 'unknown all: %s is not on PATH, so nothing was read\n' "${tool}"
    planned=2
    exit 2
  fi
done

work="$(mktemp -d)" || die "no temporary directory"

drifted=0
unknowns=0
oks=0

report() {
  local verdict="$1" item="$2" text="${3:-}"
  case "${verdict}" in
    ok)
      printf 'ok %s\n' "${item}"
      oks=$((oks + 1))
      ;;
    drift)
      printf 'drift %s: %s\n' "${item}" "${text}"
      drifted=$((drifted + 1))
      ;;
    *)
      printf 'unknown %s: %s\n' "${item}" "${text:-no reason was given}"
      unknowns=$((unknowns + 1))
      ;;
  esac
}

# fetch <endpoint> [list|pages]; sets LIVE to the answer as one JSON document,
# or WHY to the reason there is none and HTTP to the status gh named, and then
# returns 1. `list` reads every page of a list and joins them; `pages` reads
# every page and keeps each. With --save the answer is saved, or it is none.
fetch() {
  local endpoint="$1" mode="${2:-}" raw rc=0 filter file
  LIVE=""
  WHY=""
  HTTP=""
  if [[ -n "${mode}" ]]; then
    raw="$(gh api --paginate "${endpoint}" 2>"${work}/err" </dev/null)" || rc=$?
  else
    raw="$(gh api "${endpoint}" 2>"${work}/err" </dev/null)" || rc=$?
  fi
  if ((rc != 0)); then
    WHY="$(head -n 1 "${work}/err" || true)"
    HTTP="$(sed -n 's/.*(HTTP \([0-9][0-9][0-9]\)).*/\1/p' "${work}/err" | head -n 1 || true)"
    WHY="GET ${endpoint}: ${WHY:-gh exited ${rc} with no message}"
    return 1
  fi
  if [[ -z "${raw}" ]]; then
    WHY="GET ${endpoint}: the answer has no content"
    return 1
  fi
  case "${mode}" in
    list) filter='if length > 0 and all(.[]; type == "array") then add else error("a page is not a list") end' ;;
    pages) filter='if length > 0 then . else error("no page") end' ;;
    *) filter='if length == 1 then .[0] else error("not one document") end' ;;
  esac
  if ! LIVE="$(jq -cs "${filter}" <<<"${raw}" 2>"${work}/err")"; then
    WHY="GET ${endpoint}: the answer is not the JSON expected: $(head -n 1 "${work}/err" || true)"
    LIVE=""
    return 1
  fi
  if [[ -n "${save_dir}" ]]; then
    file="${save_dir}/$(printf '%s' "${endpoint}" | tr -c 'A-Za-z0-9._-' '_').json"
    # noclobber makes the shell create the file exclusively, so an existing
    # file or a planted link is refused rather than written through.
    if ! (set -C && printf '%s\n' "${LIVE}" >"${file}") 2>"${work}/err"; then
      WHY="GET ${endpoint} was read but not saved to ${file}: $(head -n 1 "${work}/err" || true)"
      LIVE=""
      return 1
    fi
  fi
}

# The comparison. Arrays are compared as sets, since no list GitHub keeps here
# has an order that means anything. A declared key absent from an answer is
# unknown rather than drift, since GitHub leaves out what the token may not see,
# such as the merge settings without admin access; where the answer shows it
# was read in full (`strict`), absent is drift.
read -r -d '' JQ_LIB <<'JQ' || true
def pathname: if length == 0 then "the answer" else map(tostring) | join(".") end;
def diff($d; $l; $p):
  if ($d | type) == "object" and ($l | type) == "object" then
    (($d | keys[]) as $k
      | if ($l | has($k)) then diff($d[$k]; $l[$k]; $p + [$k])
        else {kind: "absent", text: "\($p + [$k] | pathname): declared \($d[$k] | tojson), absent from the answer"} end),
    (($l | keys[]) as $k | select(($d | has($k)) | not)
      | {kind: "drift", text: "\($p + [$k] | pathname): live \($l[$k] | tojson), not declared"})
  elif ($d | type) == "array" and ($l | type) == "array" then
    ($d | map(tojson)) as $ds | ($l | map(tojson)) as $ls
    | (($ds - $ls) | select(length > 0) | {kind: "drift", text: "\($p | pathname): lacks \(join(", "))"}),
      (($ls - $ds) | select(length > 0) | {kind: "drift", text: "\($p | pathname): holds \(join(", ")), not declared"})
  elif $d == $l then empty
  else {kind: "drift", text: "\($p | pathname): declared \($d | tojson), live \($l | tojson)"} end;
def verdict:
  (.strict // false) as $strict
  | [diff(.d; .l; []) | if $strict and .kind == "absent" then .kind = "drift" else . end] as $r
  | if any($r[]; .kind == "drift") then "drift\t\([$r[] | select(.kind == "drift") | .text] | join("; "))"
    elif ($r | length) > 0 then "unknown\t\([$r[] | .text] | join("; "))"
    else "ok\t" end;
def project: .d as $d | .l |= (if type == "object" and ($d | type) == "object" then with_entries(select(.key as $k | $d | has($k))) else . end);
def rule_params:
  (if has("required_status_checks") then .required_status_checks |= map("\(.context) from app \(.integration_id)") else . end)
  | (if has("required_reviewers") then .required_reviewers |= (map({key: "\(.reviewer.type) \(.reviewer.id)", value: del(.reviewer)}) | from_entries) else . end)
  | (if has("code_scanning_tools") then .code_scanning_tools |= map("\(.tool) security \(.security_alerts_threshold) alerts \(.alerts_threshold)") else . end);
def ruleset_shape:
  with_entries(select(.key | IN("name", "target", "enforcement", "conditions", "bypass_actors", "rules")))
  | (if has("bypass_actors") then .bypass_actors |= map("\(.actor_type) \(.actor_id) \(.bypass_mode)") else . end)
  | (if has("rules") then .rules |= (map({key: .type, value: ((.parameters // {}) | rule_params)}) | from_entries) else . end);
def blind_reviewers: if (.rules.pull_request.required_reviewers? | type) == "object" then .rules.pull_request.required_reviewers |= with_entries(.key |= sub(" [0-9]+$"; " (id not read)")) else . end;
# GitHub answers bypass_actors only to a token that may edit the ruleset, so
# its presence marks a full read. GitHub may leave a rule parameter out of its
# answer when it is false, so there, and nowhere else, a declared false matches
# an absent key.
def ruleset:
  (.l | type == "object" and has("bypass_actors")) as $full
  | .d |= ruleset_shape | .l |= ruleset_shape
  | (if $blind then .d |= blind_reviewers | .l |= blind_reviewers else . end)
  | .strict = $full
  | .d as $d
  | .l.rules |= (if type == "object" and ($d.rules | type) == "object" then
      with_entries(.key as $t | if ($d.rules | has($t)) and (.value | type) == "object" then
        .value as $lv
        | .value = (($d.rules[$t] | with_entries(select(.value == false and (.key as $k | $lv | has($k) | not)))) + $lv)
      else . end)
    else . end);
def environment:
  .l |= ((.protection_rules // []) as $rules
    | ([$rules[] | select(.type == "required_reviewers")] | first) as $r
    | {deployment_branch_policy, can_admins_bypass,
       reviewers: (if $r == null then [] else [$r.reviewers[] | {type, id: .reviewer.id}] end),
       prevent_self_review: (if $r == null then null else $r.prevent_self_review end)})
  | if $blind then .d.reviewers |= map(.id = null) | .l.reviewers |= map(.id = null) else . end;
JQ

# compare <item> <declared JSON> <live JSON> [jq shaping] [what was not compared]
compare() {
  local item="$1" declared="$2" live="$3" shaping="${4:-project}" missing="${5:-}" blind=false out verdict text
  [[ -z "${missing}" ]] || blind=true
  if ! out="$(jq -nr --argjson d "${declared}" --argjson l "${live}" --argjson blind "${blind}" \
    "${JQ_LIB} {d: \$d, l: \$l} | ${shaping} | verdict" 2>&1)"; then
    report unknown "${item}" "the comparison could not run: ${out}"
    return 0
  fi
  verdict="${out%%$'\t'*}"
  text="${out#*$'\t'}"
  if [[ -n "${missing}" ]]; then
    case "${verdict}" in
      ok) verdict=unknown text="${missing}" ;;
      unknown) text="${text}; ${missing}" ;;
    esac
  fi
  report "${verdict}" "${item}" "${text}"
}

# check_simple <item> <endpoint> <declared JSON>
check_simple() {
  if fetch "$2"; then
    compare "$1" "$3" "${LIVE}"
  else
    report unknown "$1" "${WHY}"
  fi
}

REPO_ADMIN=false
if fetch "repos/${REPO}"; then
  REPO_ADMIN="$(jq -r '.permissions.admin == true' <<<"${LIVE}")"
  compare "repository settings" "$(repository_json)" "${LIVE}"
else
  report unknown "repository settings" "${WHY}"
fi
check_simple "topics" "repos/${REPO}/topics" "$(topics_json)"

# GitHub documents a 404 here as immutable releases being off. A 404 is also
# what a token without access gets, so it counts as drift only for an admin.
if fetch "repos/${REPO}/immutable-releases"; then
  compare "immutable releases" '{ "enabled": true }' "${LIVE}"
elif [[ "${HTTP}" == "404" && "${REPO_ADMIN}" == "true" ]]; then
  report drift "immutable releases" "not enabled: ${WHY}, read with admin access"
else
  report unknown "immutable releases" "${WHY}"
fi
check_simple "actions permissions" "repos/${REPO}/actions/permissions" "$(actions_permissions_json)"
check_simple "actions workflow permissions" "repos/${REPO}/actions/permissions/workflow" "$(actions_workflow_json)"
check_simple "actions fork pull request approval" \
  "repos/${REPO}/actions/permissions/fork-pr-contributor-approval" "$(actions_fork_approval_json)"

# check_team <slug> <repository permission>; sets TEAM_ID when the team's id
# was read.
check_team() {
  local slug="$1" permission="$2" item="team $1" listed children members login role declared live
  TEAM_ID=""
  if ! fetch "orgs/${OWNER}/teams/${slug}"; then
    report unknown "${item}" "${WHY}"
    return 0
  fi
  TEAM_ID="$(jq -r '.id // empty' <<<"${LIVE}")"
  [[ "${TEAM_ID}" =~ ^[0-9]+$ ]] || TEAM_ID=""
  if [[ -z "${team_roles}" ]]; then
    report unknown "${item}" "${team_roles_why}"
    return 0
  fi
  if ! fetch "orgs/${OWNER}/teams/${slug}/members?per_page=100" list; then
    report unknown "${item}" "${WHY}"
    return 0
  fi
  listed="${LIVE}"
  if ! fetch "orgs/${OWNER}/teams/${slug}/teams?per_page=100" list; then
    report unknown "${item}" "${WHY}"
    return 0
  fi
  children="${LIVE}"
  declared="$(jq -nc --arg p "${permission}" '{permission: $p, members: {}, children: []}')"
  members='{}'
  while IFS='|' read -r team login role; do
    [[ "${team}" == "${slug}" ]] || continue
    declared="$(jq -c --arg l "${login}" --arg r "${role}" '.members[$l] = {role: $r, state: "active"}' <<<"${declared}")"
    if ! fetch "orgs/${OWNER}/teams/${slug}/memberships/${login}"; then
      report unknown "${item}" "${WHY}"
      return 0
    fi
    members="$(jq -c --arg l "${login}" --argjson m "${LIVE}" '.[$l] = {role: $m.role, state: $m.state}' <<<"${members}")"
  done <<<"$(team_members)"
  live="$(jq -c --arg s "${slug}" --argjson listed "${listed}" --argjson children "${children}" --argjson members "${members}" '
    {permission: ([.[] | select(.slug == $s) | .permission] | first),
     members: ($members + ([$listed[] | .login | select(. as $l | $members | has($l) | not) | {(.): {listed: true}}] | add // {})),
     children: [$children[] | .slug]}' <<<"${team_roles}")"
  compare "${item}" "${declared}" "${live}"
}

team_roles=""
team_roles_why=""
if fetch "repos/${REPO}/teams?per_page=100" list; then
  team_roles="${LIVE}"
else
  team_roles_why="${WHY}"
fi
MAINTAINERS_TEAM_ID=""
SECURITY_TEAM_ID=""
declared_slugs='[]'
while IFS='|' read -r slug permission _; do
  [[ -n "${slug}" ]] || continue
  declared_slugs="$(jq -c --arg s "${slug}" '. + [$s]' <<<"${declared_slugs}")"
  check_team "${slug}" "${permission}"
  case "${slug}" in
    maintainers) MAINTAINERS_TEAM_ID="${TEAM_ID}" ;;
    security-maintainers) SECURITY_TEAM_ID="${TEAM_ID}" ;;
  esac
done <<<"$(teams)"

if [[ -n "${team_roles}" ]]; then
  compare "other teams" '[]' "$(jq -c --argjson declared "${declared_slugs}" \
    '[.[] | select((.permission == "admin" or .permission == "maintain") and (.slug as $s | $declared | index($s) | not)) | "\(.slug) \(.permission)"]' \
    <<<"${team_roles}")"
else
  report unknown "other teams" "${team_roles_why}"
fi

declared_collaborators="$(direct_collaborators | jq -Rnc '[inputs | select(length > 0) | split("|") | "\(.[0]) \(.[1])"]')"
if fetch "repos/${REPO}/collaborators?affiliation=direct&per_page=100" list; then
  compare "direct collaborators" "${declared_collaborators}" \
    "$(jq -c '[.[] | select(.role_name == "admin" or .role_name == "maintain") | "\(.login) \(.role_name)"]' <<<"${LIVE}")"
else
  report unknown "direct collaborators" "${WHY}"
fi
if fetch "repos/${REPO}/collaborators?affiliation=all&per_page=100" list; then
  compare "repository admins" "$(json_strings "${REPOSITORY_ADMINS[@]}")" \
    "$(jq -c '[.[] | select(.role_name == "admin") | .login]' <<<"${LIVE}")"
else
  report unknown "repository admins" "${WHY}"
fi

for environment in "${ENVIRONMENTS[@]}"; do
  item="environment ${environment}"
  if fetch "repos/${REPO}/environments/${environment}"; then
    if [[ -n "${MAINTAINERS_TEAM_ID}" ]]; then
      compare "${item}" "$(environment_json "${MAINTAINERS_TEAM_ID}")" "${LIVE}" environment
    else
      compare "${item}" "$(environment_json 0)" "${LIVE}" environment \
        "the maintainers team's id could not be read, so the reviewer's id was not compared"
    fi
  else
    report unknown "${item}" "${WHY}"
  fi

  item="environment ${environment} deployment policies"
  if fetch "repos/${REPO}/environments/${environment}/deployment-branch-policies" pages; then
    compare "${item}" "[$(environment_tag_policy_json)]" \
      "$(jq -c '[.[].branch_policies[] | {name, type}]' <<<"${LIVE}")"
  else
    report unknown "${item}" "${WHY}"
  fi
done

rulesets=""
rulesets_why=""
if fetch "repos/${REPO}/rulesets?includes_parents=false" list; then
  rulesets="${LIVE}"
else
  rulesets_why="${WHY}"
fi
while IFS= read -r name; do
  item="ruleset ${name}"
  if [[ -z "${rulesets}" ]]; then
    report unknown "${item}" "${rulesets_why}"
    continue
  fi
  ids="$(jq -r --arg n "${name}" '.[] | select(.name == $n) | .id' <<<"${rulesets}")"
  count="$(grep -c . <<<"${ids}" || true)"
  if ((count == 0)); then
    report drift "${item}" "no ruleset has this name"
    continue
  fi
  if ((count > 1)); then
    report drift "${item}" "${count} rulesets have this name"
    continue
  fi
  if ! fetch "repos/${REPO}/rulesets/${ids}"; then
    report unknown "${item}" "${WHY}"
    continue
  fi
  if [[ -n "${SECURITY_TEAM_ID}" ]]; then
    compare "${item}" "$(ruleset_json "${name}" "${SECURITY_TEAM_ID}")" "${LIVE}" ruleset
  elif [[ "$(ruleset_json "${name}" 0)" == "$(ruleset_json "${name}" 1)" ]]; then
    compare "${item}" "$(ruleset_json "${name}" 0)" "${LIVE}" ruleset
  else
    compare "${item}" "$(ruleset_json "${name}" 0)" "${LIVE}" ruleset \
      "the security-maintainers team's id could not be read, so a reviewer's id was not compared"
  fi
done <<<"$(ruleset_names)"

# A two-approval part the declarations no longer need still binds main; the
# bootstrap deletes it.
item="leftover two-approval parts"
if [[ -n "${rulesets}" ]]; then
  compare "${item}" '[]' "$(jq -c --arg prefix "${TWO_APPROVAL_PART_PREFIX}" --argjson declared "$(ruleset_names | jq -Rnc '[inputs]')" \
    '[.[] | .name | select(startswith($prefix) and (ltrimstr($prefix) | test("^[0-9]+$")) and (. as $n | $declared | index($n) | not))]' \
    <<<"${rulesets}")"
else
  report unknown "${item}" "${rulesets_why}"
fi

# retired_label_text <live name>; the drift line for a retired label still
# present, with how many issues and pull requests hold it.
retired_label_text() {
  local held
  if fetch "repos/${REPO}/issues?labels=$(jq -rn --arg n "$1" '$n | @uri')&state=all&per_page=100" list; then
    held="$(jq -r 'length' <<<"${LIVE}")"
    printf '"%s" present, held by %s issue(s) or pull request(s)' "$1" "${held}"
  else
    printf '"%s" present, holders unknown: %s' "$1" "${WHY}"
  fi
}

declared_labels="$(labels | jq -Rnc '[inputs | select(length > 0) | split("|") | {name: .[0], color: .[1], description: (.[2:] | join("|"))}]')"
retired_labels="$(json_strings "${RETIRED_LABELS[@]}")"
if fetch "repos/${REPO}/labels?per_page=100" list; then
  live_labels="${LIVE}"
  out="$(jq -r --argjson decl "${declared_labels}" '
    . as $live
    | [$decl[] as $x
        | ([$live[] | select(.name == $x.name)] | first) as $y
        | if $y == null then "\($x.name | tojson) missing"
          else (if ($y.color | ascii_downcase) != ($x.color | ascii_downcase)
                  then "\($x.name | tojson) colour: declared \($x.color), live \($y.color)" else empty end),
               (if ($y.description // "") != $x.description
                  then "\($x.name | tojson) description: declared \($x.description | tojson), live \($y.description | tojson)" else empty end)
          end]
    | join("; ")' <<<"${live_labels}")"
  if [[ -z "${out}" ]]; then report ok "labels"; else report drift "labels" "${out}"; fi
  present="$(jq -r --argjson retired "${retired_labels}" \
    '.[] | .name as $n | select(any($retired[]; ascii_downcase == ($n | ascii_downcase))) | $n' <<<"${live_labels}")"
  out=""
  while IFS= read -r name; do
    [[ -n "${name}" ]] || continue
    out="${out:+${out}; }$(retired_label_text "${name}")"
  done <<<"${present}"
  if [[ -z "${out}" ]]; then report ok "labels retired"; else report drift "labels retired" "${out}"; fi
else
  report unknown "labels" "${WHY}"
  report unknown "labels retired" "${WHY}"
fi

declared_milestones="$(json_strings "${MILESTONES[@]}")"
retired_milestones="$(json_strings "${RETIRED_MILESTONES[@]}")"
if fetch "repos/${REPO}/milestones?state=all&per_page=100" list; then
  out="$(jq -r --argjson decl "${declared_milestones}" '
    . as $live
    | [$decl[] as $t
        | [$live[] | select(.title == $t)] as $hits
        | if ($hits | length) == 0 then "\($t | tojson) missing"
          elif all($hits[]; .state != "open") then "\($t | tojson) is closed"
          else empty end]
    | join("; ")' <<<"${LIVE}")"
  if [[ -z "${out}" ]]; then report ok "milestones"; else report drift "milestones" "${out}"; fi
  out="$(jq -r --argjson retired "${retired_milestones}" '
    . as $live
    | [$retired[] as $t | select(any($live[]; .title == $t and .state == "open")) | "\($t | tojson) is open"]
    | join("; ")' <<<"${LIVE}")"
  if [[ -z "${out}" ]]; then report ok "milestones retired"; else report drift "milestones retired" "${out}"; fi
else
  report unknown "milestones" "${WHY}"
  report unknown "milestones retired" "${WHY}"
fi

# A repository with no configuration attached answers 204 with no content; the
# documentation does not say that is the only meaning, so it stays unknown.
item="code security configuration"
if ! fetch "orgs/${OWNER}/code-security/configurations" list; then
  report unknown "${item}" "${WHY}"
else
  configurations="${LIVE}"
  ids="$(jq -r --arg n "${REPO_NAME}" '.[] | select(.name == $n) | .id' <<<"${configurations}")"
  count="$(grep -c . <<<"${ids}" || true)"
  if ((count != 1)); then
    report drift "${item}" "${count} configurations of ${OWNER} are named ${REPO_NAME}, want 1"
  elif ! fetch "repos/${REPO}/code-security-configuration"; then
    report unknown "${item}" "${WHY}"
  else
    declared="$(security_configuration_json | jq -c --argjson id "${ids}" '. + {attached: {id: $id, status: "enforced"}}')"
    live="$(jq -c --argjson id "${ids}" --argjson repo "${LIVE}" \
      '.[] | select(.id == $id) | . + {attached: {id: $repo.configuration.id, status: $repo.status}}' <<<"${configurations}")"
    compare "${item}" "${declared}" "${live}"
  fi
fi

printf 'github-settings-check: %s: %d ok, %d drift, %d unknown\n' "${REPO}" "${oks}" "${drifted}" "${unknowns}" >&2
planned=0
if ((drifted > 0)); then
  planned=1
elif ((unknowns > 0)); then
  planned=2
fi
exit "${planned}"
