#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR disable=SC2034 # every array and value is read by a script that sources this file
# The GitHub configuration of guardana/control that ADR-0025 and GOVERNANCE.md
# describe, declared once: scripts/github-bootstrap.sh applies it and
# scripts/github-settings-check.sh compares it with what GitHub holds, so the
# two read the same values and the same request bodies. Sourced, not run; it
# makes no call of its own. The bodies are built in github-bodies.sh and
# github-rulesets.sh beside it, which this file sources.
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
  "External MCP client"
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
  "cmd/guardana-gateway/build*.go"
  "cmd/guardana-gateway/approvals.go"
  "cmd/guardana-gateway/serve*.go"
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

# Found by expansion alone: a caller may source this file with a PATH that
# holds no dirname.
_GITHUB_SETTINGS_DIR="${BASH_SOURCE[0]%/*}"
[[ "${_GITHUB_SETTINGS_DIR}" != "${BASH_SOURCE[0]}" ]] || _GITHUB_SETTINGS_DIR=.
# shellcheck source=github-bodies.sh
. "${_GITHUB_SETTINGS_DIR}/github-bodies.sh"
# shellcheck source=github-rulesets.sh
. "${_GITHUB_SETTINGS_DIR}/github-rulesets.sh"
