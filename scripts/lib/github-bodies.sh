#!/usr/bin/env bash
# The JSON every request body is written in, and the bodies of the repository,
# its topics, environments, security configuration and Actions, built from what
# scripts/lib/github-settings.sh declares. That file sources this one; nothing
# else does.

# emit <text>; prints text and a newline through cat. Callers read these
# functions through pipes, and bash 3.2 fails a builtin's write to a pipe that
# a child's exit interrupts; cat has no children, so nothing interrupts it.
emit() {
  cat <<<"$1"
}

# json_strings <value>...; prints a JSON array of strings. A value holding a
# quote, a backslash or a control character is refused rather than escaped:
# every value here is a name the declarations control.
json_strings() {
  local separator="" value out="["
  for value in "$@"; do
    case "${value}" in
      *[\"\\]* | *[[:cntrl:]]*)
        printf 'github-settings: refusing to encode %s\n' "${value}" >&2
        return 1
        ;;
    esac
    out+="${separator}\"${value}\""
    separator=", "
  done
  emit "${out}]"
}

# json_string <value>; one JSON string, refused as json_strings refuses.
json_string() {
  local encoded
  encoded="$(json_strings "$1")" || return 1
  encoded="${encoded#[}"
  emit "${encoded%]}"
}

# require_id <what> <value>; refuses a team id that is not a number, which
# would otherwise be written into a body unquoted.
require_id() {
  if [[ ! "$2" =~ ^[0-9]+$ ]]; then
    printf 'github-settings: no numeric id for %s\n' "$1" >&2
    return 1
  fi
}

# environment_json <maintainers team id>; a job deploys to either environment
# only from a v* tag and waits for a maintainer to approve it. One maintainer
# may approve their own tag, and the admin may bypass the wait.
environment_json() {
  require_id "the maintainers team" "$1" || return 1
  cat <<JSON
{
  "deployment_branch_policy": { "protected_branches": false, "custom_branch_policies": true },
  "reviewers": [ { "type": "Team", "id": $1 } ],
  "prevent_self_review": false,
  "can_admins_bypass": true
}
JSON
}

environment_tag_policy_json() {
  local policy
  policy="$(json_string "${ENVIRONMENT_TAG_POLICY}")" || return 1
  emit "{ \"name\": ${policy}, \"type\": \"tag\" }"
}

# test_environment_json; the test index's environment: a job deploys to it
# from its one branch policy only, the admin's too, and waits for nobody.
test_environment_json() {
  cat <<JSON
{
  "deployment_branch_policy": { "protected_branches": false, "custom_branch_policies": true },
  "reviewers": [],
  "can_admins_bypass": false
}
JSON
}

test_environment_branch_policy_json() {
  local policy
  policy="$(json_string "${TEST_ENVIRONMENT_BRANCH_POLICY}")" || return 1
  emit "{ \"name\": ${policy}, \"type\": \"branch\" }"
}

# shellcheck disable=SC2153 # DESCRIPTION and HOMEPAGE are declared in github-settings.sh
repository_json() {
  local description homepage
  description="$(json_string "${DESCRIPTION}")" || return 1
  homepage="$(json_string "${HOMEPAGE}")" || return 1
  cat <<JSON
{
  "description": ${description},
  "homepage": ${homepage},
  "default_branch": "${DEFAULT_BRANCH}",
  "has_issues": true,
  "has_wiki": false,
  "has_projects": false,
  "has_discussions": false,
  "allow_squash_merge": true,
  "allow_merge_commit": false,
  "allow_rebase_merge": false,
  "squash_merge_commit_title": "PR_TITLE",
  "squash_merge_commit_message": "COMMIT_MESSAGES",
  "delete_branch_on_merge": true,
  "allow_update_branch": true,
  "allow_auto_merge": false,
  "web_commit_signoff_required": true
}
JSON
}

topics_json() {
  local names
  names="$(json_strings "${TOPICS[@]}")" || return 1
  emit "{ \"names\": ${names} }"
}

# security_configuration_json; the security features come from an organization
# configuration attached to this repository alone, enforced so they cannot
# drift at the repository. A new public repository has no dependency graph, and
# without it the required "Dependency review" check cannot run. Code scanning's
# default setup stays off: security.yml runs CodeQL itself, and GitHub refuses
# the results of one while the other is on. GitHub refuses secret scanning in a
# configuration that leaves advanced_security off; on a public repository it
# costs nothing.
security_configuration_json() {
  local name description
  name="$(json_string "${REPO_NAME}")" || return 1
  description="$(json_string "The security settings of ${REPO}, applied by its scripts/github-bootstrap.sh.")" || return 1
  cat <<JSON
{
  "name": ${name},
  "description": ${description},
  "advanced_security": "enabled",
  "dependency_graph": "enabled",
  "dependabot_alerts": "enabled",
  "dependabot_security_updates": "enabled",
  "code_scanning_default_setup": "disabled",
  "secret_scanning": "enabled",
  "secret_scanning_push_protection": "enabled",
  "private_vulnerability_reporting": "enabled",
  "enforcement": "enforced"
}
JSON
}

# Every action must be pinned to a commit, as scripts/check-actions-pinned.sh
# already requires of this tree. A workflow that needs to write asks for it in
# its own job. A first-time contributor's pull request runs its workflows only
# after a maintainer approves the run.
actions_permissions_json() {
  emit '{ "enabled": true, "allowed_actions": "all", "sha_pinning_required": true }'
}
actions_workflow_json() {
  emit '{ "default_workflow_permissions": "read", "can_approve_pull_request_reviews": false }'
}
actions_fork_approval_json() {
  emit '{ "approval_policy": "first_time_contributors" }'
}
