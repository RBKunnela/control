#!/usr/bin/env bash
# The ruleset bodies, built from what scripts/lib/github-settings.sh declares:
# their names in the order they are applied, the parts the two-approval paths
# take, and the limits GitHub holds a required reviewer to. That file sources
# this one; nothing else does.

# checks_json; REQUIRED_CHECKS as the ruleset's required_status_checks array,
# each bound to the Actions app, so the list the bootstrap checks against the
# workflows and the list applied cannot drift apart.
checks_json() {
  local separator="" context out="["
  for context in "${REQUIRED_CHECKS[@]}"; do
    json_string "${context}" >/dev/null || return 1
    out+="${separator}{ \"context\": \"${context}\", \"integration_id\": $((ACTIONS_APP_ID)) }"
    separator=", "
  done
  emit "${out}]"
}

# two_approval_parts; how many parts TWO_APPROVAL_PATHS takes.
two_approval_parts() {
  emit "$(((${#TWO_APPROVAL_PATHS[@]} + REVIEWER_PATTERN_LIMIT - 1) / REVIEWER_PATTERN_LIMIT))"
}

# two_approval_patterns_json <part>; that part of TWO_APPROVAL_PATHS as a JSON
# array, refused for a part that holds nothing.
two_approval_patterns_json() {
  local part="$1" start
  start=$(((part - 1) * REVIEWER_PATTERN_LIMIT))
  if ((part < 1 || start >= ${#TWO_APPROVAL_PATHS[@]})); then
    printf 'github-settings: TWO_APPROVAL_PATHS has no part %s\n' "${part}" >&2
    return 1
  fi
  json_strings "${TWO_APPROVAL_PATHS[@]:start:REVIEWER_PATTERN_LIMIT}"
}

# ruleset_names; the rulesets in the order the bootstrap applies them. The
# simple ones come before the one that uses the newest rule types, so a setting
# GitHub refuses further down never leaves main or a release tag unprotected.
# The further two-approval parts come before "main: pull requests", so a path
# that moves out of it is held by its new part before it leaves the old one.
ruleset_names() {
  local part parts out
  out="main: history
release tags: create
other tags: create
release tags: immutable
main: merges"
  parts=$(((${#TWO_APPROVAL_PATHS[@]} + REVIEWER_PATTERN_LIMIT - 1) / REVIEWER_PATTERN_LIMIT))
  for ((part = 2; part <= parts; part++)); do
    out+=$'\n'"${TWO_APPROVAL_PART_PREFIX}${part}"
  done
  emit "${out}"$'\n'"main: pull requests"
}

# pull_request_rule_json <patterns JSON> <security-maintainers team id>; the
# pull_request rule every ruleset on main that asks for two approvals holds.
pull_request_rule_json() {
  require_id "the security-maintainers team" "$2" || return 1
  cat <<JSON
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 1,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": true,
        "require_last_push_approval": true,
        "required_review_thread_resolution": true,
        "require_extra_approval_for_unattributed_changes": true,
        "dismissal_restriction": { "enabled": false, "allowed_actors": [] },
        "allowed_merge_methods": ["squash"],
        "required_reviewers": [
          {
            "minimum_approvals": 2,
            "file_patterns": $1,
            "reviewer": { "id": $2, "type": "Team" }
          }
        ]
      }
    }
JSON
}

# ruleset_json <name> <security-maintainers team id>; the body the bootstrap
# sends for the ruleset of that name. Every fragment is built by assignment
# first, so a refusal stops it: inside a here-document a failed substitution
# would be silently empty.
ruleset_json() {
  local name="$1" security_team_id="$2" patterns checks rule part
  case "${name}" in
    "main: history")
      # No role bypasses this one: nobody deletes main, force-pushes it or
      # merges into it with a merge commit.
      cat <<'JSON'
{
  "name": "main: history",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "bypass_actors": [],
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "required_linear_history" }
  ]
}
JSON
      ;;
    "release tags: create")
      # Only the admin and the maintain role create a release tag.
      cat <<JSON
{
  "name": "release tags: create",
  "target": "tag",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["refs/tags/v*"], "exclude": [] } },
  "bypass_actors": [
    { "actor_id": ${ROLE_ADMIN}, "actor_type": "RepositoryRole", "bypass_mode": "always" },
    { "actor_id": ${ROLE_MAINTAIN}, "actor_type": "RepositoryRole", "bypass_mode": "always" }
  ],
  "rules": [
    { "type": "creation" }
  ]
}
JSON
      ;;
    "other tags: create")
      # Only the admin and the maintain role create any other tag either, so no
      # tag can take a branch's name, which a tag push run reports as its head
      # branch.
      cat <<JSON
{
  "name": "other tags: create",
  "target": "tag",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["~ALL"], "exclude": ["refs/tags/v*"] } },
  "bypass_actors": [
    { "actor_id": ${ROLE_ADMIN}, "actor_type": "RepositoryRole", "bypass_mode": "always" },
    { "actor_id": ${ROLE_MAINTAIN}, "actor_type": "RepositoryRole", "bypass_mode": "always" }
  ],
  "rules": [
    { "type": "creation" }
  ]
}
JSON
      ;;
    "release tags: immutable")
      # No role moves or deletes a release tag once it exists.
      cat <<'JSON'
{
  "name": "release tags: immutable",
  "target": "tag",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["refs/tags/v*"], "exclude": [] } },
  "bypass_actors": [],
  "rules": [
    { "type": "update", "parameters": { "update_allows_fetch_and_merge": false } },
    { "type": "deletion" },
    { "type": "non_fast_forward" }
  ]
}
JSON
      ;;
    "main: merges")
      # Only the admin and the maintain role update main; the maintain role only
      # by merging a pull request. A collaborator with write access cannot merge.
      cat <<JSON
{
  "name": "main: merges",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "bypass_actors": [
    { "actor_id": ${ROLE_ADMIN}, "actor_type": "RepositoryRole", "bypass_mode": "always" },
    { "actor_id": ${ROLE_MAINTAIN}, "actor_type": "RepositoryRole", "bypass_mode": "pull_request" }
  ],
  "rules": [
    { "type": "update", "parameters": { "update_allows_fetch_and_merge": false } }
  ]
}
JSON
      ;;
    "main: pull requests")
      # A change reaches main by squash-merged pull request, reviewed and green.
      # The admin bypasses this ruleset and its two-approval parts, and no
      # other, to merge a change no second maintainer can approve and to push
      # a release commit.
      patterns="$(two_approval_patterns_json 1)" || return 1
      rule="$(pull_request_rule_json "${patterns}" "${security_team_id}")" || return 1
      checks="$(checks_json)" || return 1
      cat <<JSON
{
  "name": "main: pull requests",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "bypass_actors": [
    { "actor_id": ${ROLE_ADMIN}, "actor_type": "RepositoryRole", "bypass_mode": "always" }
  ],
  "rules": [
${rule},
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": true,
        "do_not_enforce_on_create": false,
        "required_status_checks": ${checks}
      }
    },
    {
      "type": "code_scanning",
      "parameters": {
        "code_scanning_tools": [
          { "tool": "CodeQL", "security_alerts_threshold": "high_or_higher", "alerts_threshold": "errors" }
        ]
      }
    }
  ]
}
JSON
      ;;
    "${TWO_APPROVAL_PART_PREFIX}"*)
      # A further part of the two-approval paths: the same pull request rule,
      # its own patterns, no status check, which "main: pull requests" requires.
      part="${name#"${TWO_APPROVAL_PART_PREFIX}"}"
      if [[ ! "${part}" =~ ^[0-9]+$ ]] || ((part < 2)); then
        printf 'github-settings: no ruleset is named %s\n' "${name}" >&2
        return 1
      fi
      patterns="$(two_approval_patterns_json "${part}")" || return 1
      rule="$(pull_request_rule_json "${patterns}" "${security_team_id}")" || return 1
      cat <<JSON
{
  "name": "${name}",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "bypass_actors": [
    { "actor_id": ${ROLE_ADMIN}, "actor_type": "RepositoryRole", "bypass_mode": "always" }
  ],
  "rules": [
${rule}
  ]
}
JSON
      ;;
    *)
      printf 'github-settings: no ruleset is named %s\n' "${name}" >&2
      return 1
      ;;
  esac
}

# reviewer_limit_problems <patterns per reviewer>; one line per problem in the
# ruleset bodies, built with a stand-in team id: a required reviewer with more
# patterns than the limit, a team named twice in one ruleset, or rulesets that
# together hold other than exactly TWO_APPROVAL_PATHS. Prints nothing when there
# is none; needs jq.
reviewer_limit_problems() {
  local limit="$1" bodies="" ruleset body names expected
  names="$(ruleset_names)" || return 1
  while IFS= read -r ruleset; do
    body="$(ruleset_json "${ruleset}" 0)" || return 1
    bodies="${bodies}${body}"
  done <<<"${names}"
  expected="$(json_strings "${TWO_APPROVAL_PATHS[@]}")" || return 1
  jq -rs --argjson want "${expected}" --argjson limit "${limit}" '
    def reviewers: [.rules[]? | select(.type == "pull_request") | .parameters.required_reviewers[]?];
    ([.[] | .name as $name | reviewers
      | (.[] | select((.file_patterns | length) > $limit)
          | "\($name): a required reviewer holds \(.file_patterns | length) file patterns, GitHub takes at most \($limit)"),
        (map("\(.reviewer.type) \(.reviewer.id)") | group_by(.)[] | select(length > 1)
          | "\($name): \(.[0]) is a required reviewer \(length) times")]
    + ([.[] | reviewers[] | .file_patterns[]] as $all
      | if ($all | length) != ($want | length) or ($all | sort) != ($want | sort)
        then ["the rulesets hold \($all | length) two-approval patterns, not the \($want | length) of TWO_APPROVAL_PATHS"]
        else [] end))[]' <<<"${bodies}"
}
