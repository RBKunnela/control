#!/usr/bin/env bash
# shellcheck disable=SC2034 # every array and value is read by a script that sources this file
# The GitHub configuration of guardana/control that ADR-0025 and GOVERNANCE.md
# describe, declared once: scripts/github-bootstrap.sh applies it and
# scripts/github-settings-check.sh compares it with what GitHub holds, so the
# two read the same values and the same request bodies. Sourced, not run; it
# makes no call of its own.
#
# TWO_APPROVAL_PATHS holds one double-quoted entry per line:
# internal/docscheck reads this file as text.

OWNER="${OWNER:-guardana}"
REPO_NAME="${REPO_NAME:-control}"
REPO="${OWNER}/${REPO_NAME}"
DEFAULT_BRANCH="main"
# The admin both teams start with, as a team maintainer.
ADMIN_LOGIN="${ADMIN_LOGIN:-karauda}"
HOMEPAGE="https://control.guardana.dev"

DESCRIPTION="Open-source AI agent supervision framework: MCP policy decisions, approvals and procedure checks. Experimental alpha."
TOPICS=(
  ai-agents
  agentic-ai
  agent-security
  ai-security
  mcp
  model-context-protocol
  mcp-gateway
  authorization
  policy-engine
  policy-as-code
  authzen
  human-in-the-loop
  opentelemetry
  audit-trail
  golang
  llm-security
  ai-governance
  security-tools
  agent-observability
  agent-supervision
)

# Status checks the main ruleset requires. A check-run context is a workflow
# job's `name` when it sets one and its job id otherwise.
#
# A required check has to report on every pull request or the merge waits for
# a run that never happens. Three contexts this repository produces are absent
# for that reason: `Supply-chain score`, whose workflow has no pull_request
# trigger; `actionlint, zizmor, pins`, whose pull_request trigger is filtered to
# .github/workflows/**; and the release workflow's jobs, which run on a tag.
REQUIRED_CHECKS=(
  "Quality gate"
  "Wire contract compatibility"
  "CodeQL"
  "Known Go vulnerabilities"
  "Dependency advisories"
  "Secret scan"
  "Dependency review"
  "Conventional title"
  "Sign-off"
)

# The GitHub Actions app. A required check names the app that must report it,
# so a check run of the same name from any other app does not satisfy it.
ACTIONS_APP_ID=15368

# The paths where GOVERNANCE.md asks for two independent approvals: the
# decision path, the enforcement pipeline, the approvals store, the digest and
# the keys, the evidence record, the judgement of a run against its procedure,
# the route and lift signatures and the stop judge, the commands that sign a
# route, turn findings into stops and start, list, carry and lift a stop list,
# the plane's reading of its route, the reading of a run's evidence for
# supervision, the runs directory and the findings log, the policy and route
# floors and their refresh, the owner and mode checks of the configuration and
# of every store, the external decision point's answer, which may only veto,
# the MCP adapter, which classifies a tool, sends only the authorized bytes
# under their obligations, names the run a call belongs to and withholds or
# rewrites answers, the enforcement API adapter, which builds a tool's envelope
# from the operator's table and hands out single-use handles, the wire
# contracts and their fixtures, the gate's Go code that
# reports test results and checks the documents, the plane's wiring of its
# decision point, adapter, approvals and stop, and every file ADR-0008 says the
# gate is built from: the scripts, the workflows and the rest of .github, the
# release definition, the Makefile, the linter and buf configurations, go.mod
# and go.sum. Each must be owned
# by @guardana/security-maintainers in .github/CODEOWNERS, so the team that has
# to approve is also the team a pull request asks. The rulesets carry them in
# parts of at most REVIEWER_PATTERN_LIMIT, in this order.
TWO_APPROVAL_PATHS=(
  "internal/core/**"
  "internal/policy/**"
  "internal/canon/**"
  "internal/evidence/**"
  "internal/supervise/**"
  "internal/gateway/**"
  "internal/approvals/**"
  "internal/policykey/**"
  "internal/reaction/**"
  "internal/policystate/**"
  "internal/gatewayconfig/**"
  "internal/files/**"
  "internal/policywatch/**"
  "internal/runs/**"
  "internal/findinglog/**"
  "cmd/guardana-control/route*.go"
  "cmd/guardana-control/react*.go"
  "cmd/guardana-control/stops.go"
  "cmd/guardana-control/supervise_input.go"
  "cmd/guardana-gateway/reaction.go"
  "cmd/guardana-gateway/pdp.go"
  "cmd/guardana-gateway/adapter.go"
  "cmd/guardana-gateway/build.go"
  "cmd/guardana-gateway/approvals.go"
  "cmd/guardana-gateway/serve.go"
  "cmd/guardana-gateway/stop.go"
  "adapters/authzen/**"
  "adapters/mcp/**"
  "adapters/enforce/**"
  "internal/adapterkit/**"
  "pkg/contract/**"
  "pkg/policyprovider/**"
  "api/proto/**"
  "testdata/**"
  "internal/testreport/**"
  "internal/docscheck/**"
  ".github/**"
  ".goreleaser.yaml"
  "scripts/**"
  "Makefile"
  ".golangci.yml"
  "buf.yaml"
  "buf.gen.yaml"
  "go.mod"
  "go.sum"
  "clients/python/*"
)

# GitHub refuses a required reviewer with more than 15 file patterns, and the
# same team twice in one ruleset. So the first REVIEWER_PATTERN_LIMIT paths go
# to "main: pull requests" and each further part to a ruleset of its own, named
# TWO_APPROVAL_PART_PREFIX and its number from 2; GitHub applies every ruleset
# that matches a branch, and the strictest value wins.
REVIEWER_PATTERN_LIMIT=15
TWO_APPROVAL_PART_PREFIX="main: two approvals, part "

# Repository roles as the rulesets API numbers them.
ROLE_MAINTAIN=2
ROLE_ADMIN=5

# teams; one team per line: slug|repository permission|description. The
# description is given only when the team is created. The security maintainers
# get write access, because a code owner without it is ignored. No other team
# may hold maintain or admin, and neither team may have a child team, which
# would inherit its access.
teams() {
  cat <<'TEAMS'
maintainers|maintain|Maintainers of guardana/control: merge reviewed pull requests and cut releases; see GOVERNANCE.md.
security-maintainers|push|Code owners of the paths in guardana/control that carry authorization meaning.
TEAMS
}

# team_members; one membership per line: team slug|login|team role. A member
# holds the team's role on the repository, and the maintain role bypasses
# rulesets, so the check reports any member not listed here.
team_members() {
  emit "maintainers|${ADMIN_LOGIN}|maintainer
security-maintainers|${ADMIN_LOGIN}|maintainer"
}

# direct_collaborators; one per line: login|role, for each collaborator added
# to the repository itself with the maintain or admin role. None is: the roles
# come through the teams and the organization. The bootstrap adds and removes
# no collaborator; the check reports one not listed here.
direct_collaborators() {
  :
}

# Everyone who holds the admin role on the repository by any route: the
# organization's owners, an admin team or collaborator, or the organization's
# base permission. The admin role bypasses the pull request ruleset.
REPOSITORY_ADMINS=(
  "${ADMIN_LOGIN}"
)

# labels; one label per line: name|colour|description. `good first issue` and
# `help wanted` are spelled as GitHub spells them, because its contribute page
# looks for those names.
labels() {
  cat <<'LABELS'
area:core|1d76db|The decision path
area:policy|1d76db|Policy model, matcher, external PDP
area:mcp|1d76db|Model Context Protocol adapter and gateway
area:a2a|1d76db|Agent-to-agent handoff and delegation
area:otel|1d76db|OpenTelemetry export and evidence transport
area:ui|1d76db|Web interface
area:detector|1d76db|Detectors and their fixtures
area:docs|1d76db|Documentation and decision records
area:release|1d76db|Release pipeline, signing and provenance
kind:bug|d73a4a|Behaves differently from what is documented
kind:feature|0e8a16|A problem the project does not solve yet
kind:trial|0e8a16|A report from trying it with your own setup
kind:security-hardening|b60205|Reduces attack surface; not a reported vulnerability
kind:design|5319e7|Needs a design agreed before code
good first issue|7057ff|Small, self-contained, well specified
help wanted|008672|Maintainers would welcome a contributor here
needs-repro|fbca04|Waiting on a reproduction
needs-adr|fbca04|Waiting on an architecture decision record
blocked|e11d21|Waiting on something outside this issue
breaking-change|b60205|Changes a public contract or a verdict's meaning
security-sensitive|b60205|Touches authorization, identity, approvals or release
LABELS
}

# Labels deleted when present and no issue or pull request holds them: the
# hyphenated spellings of GitHub's own two, and GitHub's defaults whose meaning
# kind:bug, kind:feature and area:docs carry. GitHub compares label names
# without regard to case, and so do the bootstrap and the check.
RETIRED_LABELS=(
  "good-first-issue"
  "help-wanted"
  "bug"
  "enhancement"
  "documentation"
)

# The outcomes of ROADMAP.md, in its order and without their numbers. That page
# has no dates, so neither do these. A finished outcome is deleted from
# ROADMAP.md, so it moves from here to RETIRED_MILESTONES, which is how it gets
# closed. A declared milestone that is closed is opened again.
MILESTONES=(
  "First value in one project"
  "Integrations without a fork"
  "A small team"
  "A fleet and wider protocols, when adopters need them"
)

# Milestones of an earlier roadmap, closed when open and never deleted, so an
# issue filed under one keeps it.
RETIRED_MILESTONES=(
  "Runs and evidence other tools can read"
  "Procedures and a supervisor"
)

# The release job deploys to release, and the job that uploads the Python
# client to the package index to pypi, whose publisher trusts that
# environment alone: a token the release job's tools could mint is refused.
ENVIRONMENTS=(release pypi)
# The only ref pattern, as a tag policy, that may deploy to either.
ENVIRONMENT_TAG_POLICY='v*'
# The dry run's upload to the test index deploys to testpypi, whose publisher
# trusts that environment alone, so only a run on main reaches the test index.
# Nobody approves it: a maintainer starts a dry run by hand.
TEST_ENVIRONMENT=testpypi
TEST_ENVIRONMENT_BRANCH_POLICY=main

# emit <text>; prints text and a newline through cat. Callers read these
# functions through pipes, and bash 3.2 fails a builtin's write to a pipe that
# a child's exit interrupts; cat has no children, so nothing interrupts it.
emit() {
  cat <<<"$1"
}

# json_strings <value>...; prints a JSON array of strings. A value holding a
# quote, a backslash or a control character is refused rather than escaped:
# every value here is a name this file controls.
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

# require_id <what> <value>; refuses a team id that is not a number, which
# would otherwise be written into a body unquoted.
require_id() {
  if [[ ! "$2" =~ ^[0-9]+$ ]]; then
    printf 'github-settings: no numeric id for %s\n' "$1" >&2
    return 1
  fi
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
