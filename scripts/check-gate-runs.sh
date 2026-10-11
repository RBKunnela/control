#!/usr/bin/env bash
# Refuses a commit on which CI or Security has no successful push run on main,
# so the release workflow builds only what the gate passed on main. Both
# workflows also run on pull requests, whose runs carry the pull request's
# head commit: a green pull request run says nothing about the push run on
# main, so the script counts only a push run on main of exactly this commit
# whose conclusion is success. A push of a tag named main reports main as its
# branch too, for any commit, so the commit must also be main's head. A run
# made green by a re-run counts, because GitHub reports a run's latest attempt.
# Security's analysis step succeeds whatever CodeQL raises, so an open CodeQL
# alert of severity high or critical on main refuses the commit too
# (Scorecard's alerts judge the repository, not the code). Alerts are kept per
# branch, not per commit, and judge main's newest CodeQL analysis, so that
# analysis has to be of this commit. An answer that cannot be read is a
# refusal.
# It asks GitHub, so it needs GH_TOKEN (or a gh login) with read access to the
# repository's contents, Actions and security events, and GITHUB_REPOSITORY as
# owner/name.
#
#   GITHUB_REPOSITORY=<owner>/<name> scripts/check-gate-runs.sh <commit sha>
set -euo pipefail

die() {
  printf 'check-gate-runs: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 1 && "$1" =~ ^[0-9a-f]{40}$ ]] || die "usage: scripts/check-gate-runs.sh <40-hex commit sha>"
sha="$1"
repo="${GITHUB_REPOSITORY:-}"
[[ "${repo}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "GITHUB_REPOSITORY must be owner/name, not '${repo}'"

# The branch is resolved by its full ref, because a bare "main" in a
# comparison may resolve to a tag of that name.
main="$(gh api "repos/${repo}/git/ref/heads/main" \
  --jq 'if .ref != "refs/heads/main" then error("the answer names no refs/heads/main") else .object.sha end')" ||
  die "could not read the head of main from GitHub"
[[ "${main}" =~ ^[0-9a-f]{40}$ ]] || die "GitHub answered '${main}' for the head of main"

status="$(gh api "repos/${repo}/compare/${main}...${sha}" \
  --jq 'if (.status | type) != "string" then error("the answer holds no status") else .status end')" ||
  die "could not compare ${sha} with main's head ${main} on GitHub"
# behind is refused too: an older commit of main was judged by its own runs, but
# main's alerts now describe a later commit.
[[ "${status}" == identical ]] ||
  die "${sha} is not main's head: compared with main's head ${main}, GitHub says '${status}'"

# The first line is the total GitHub counts and the number of runs it answered
# with; then one line per run: head_sha, event, head_branch, conclusion, with an
# absent field as "none" so that read cannot shift the columns. An answer
# without a workflow_runs array or a total_count is an error, never an empty list.
filter='if (.workflow_runs | type) != "array" then error("the answer holds no workflow_runs array")
  elif (.total_count | type) != "number" then error("the answer holds no total_count")
  else ([.total_count, (.workflow_runs | length)] | @tsv),
    (.workflow_runs[] | [.head_sha, .event, .head_branch, .conclusion] | map(if . == null or . == "" then "none" else tostring end) | @tsv)
  end'

for workflow in ci.yml security.yml; do
  runs="$(gh api "repos/${repo}/actions/workflows/${workflow}/runs?head_sha=${sha}&event=push&branch=main&per_page=100" --jq "${filter}")" ||
    die "could not read ${workflow}'s runs on ${sha} from GitHub"

  passed=0
  seen=""
  others=0
  {
    IFS=$'\t' read -r total answered || true
    [[ "${total:-}" =~ ^[0-9]+$ && "${answered:-}" =~ ^[0-9]+$ ]] ||
      die "GitHub answered '${total:-} ${answered:-}' for the number of ${workflow}'s runs on ${sha}"
    ((total <= answered)) ||
      die "${workflow}: GitHub counts ${total} run(s) of ${sha} and answered ${answered}; more runs than one page; refusing rather than guessing"
    while IFS=$'\t' read -r run_sha event branch conclusion; do
      [[ -n "${run_sha}" ]] || continue
      if [[ "${run_sha}" != "${sha}" ]]; then
        others=$((others + 1))
        continue
      fi
      if [[ "${event}" == push && "${branch}" == main && "${conclusion}" == success ]]; then
        passed=1
      fi
      seen+="${seen:+; }a ${event} run on ${branch} (conclusion ${conclusion})"
    done
  } <<<"${runs}"

  if ((passed == 0)); then
    [[ -n "${seen}" ]] || seen="no run of this commit"
    ((others == 0)) || seen+="; ${others} run(s) of other commits"
    die "${workflow} has no successful push run on main for ${sha}; GitHub listed: ${seen}"
  fi
  printf 'check-gate-runs: %s passed on %s (a successful push run on main)\n' "${workflow}" "${sha}"
done

# The first line is the number of alerts GitHub answered with; then one line per
# open CodeQL alert of severity high or critical: number, severity, rule. An
# answer that is no list, or an alert without a number, a state, a rule or a
# tool, is an error.
alerts_filter='if type != "array" then error("the answer is no list of alerts")
  else (length | tostring),
    (.[] | if (.number | type) != "number" or (.state | type) != "string" or (.rule | type) != "object"
        or (.tool.name | type) != "string"
      then error("an alert without a number, a state, a rule or a tool")
      elif .state == "open" and .tool.name == "CodeQL"
        and (.rule.security_severity_level == "high" or .rule.security_severity_level == "critical")
      then [(.number | tostring), .rule.security_severity_level, (.rule.id // "no rule id" | tostring)] | @tsv
      else empty end)
  end'
alerts="$(gh api "repos/${repo}/code-scanning/alerts?ref=refs/heads/main&state=open&per_page=100" --jq "${alerts_filter}")" ||
  die "could not read the open code scanning alerts on main; refusing rather than guessing"
severe=""
{
  read -r answered || true
  [[ "${answered:-}" =~ ^[0-9]+$ ]] ||
    die "GitHub answered '${answered:-}' for the number of open code scanning alerts on main"
  ((answered < 100)) ||
    die "GitHub answered a full page of ${answered} open code scanning alerts on main; more alerts than one page; refusing rather than guessing"
  while IFS=$'\t' read -r number level rule; do
    [[ -n "${number}" ]] || continue
    severe+="${severe:+; }#${number} ${level} (${rule})"
  done
} <<<"${alerts}"
[[ -z "${severe}" ]] || die "main has open CodeQL alerts of severity high or critical: ${severe}"

# Read after the alerts, so an analysis that lands in between is of another
# commit and refuses, rather than leaving alerts of a later commit judged as
# this one's. One line: commit, ref, tool and error of main's newest CodeQL
# analysis, or "none" when GitHub lists none; a field of the wrong type is an
# error.
analysis_filter='if type != "array" then error("the answer is no list of analyses")
  elif length == 0 then "none"
  else .[0] | if (.commit_sha | type) != "string" or (.ref | type) != "string" or (.tool.name | type) != "string"
      or (.error | type) != "string"
    then error("an analysis without a commit, a ref, a tool or an error")
    else [.commit_sha, .ref, .tool.name, (if .error == "" then "none" else .error end)] | @tsv end
  end'
analysis="$(gh api "repos/${repo}/code-scanning/analyses?tool_name=CodeQL&ref=refs/heads/main&sort=created&direction=desc&per_page=1" --jq "${analysis_filter}")" ||
  die "could not read main's newest CodeQL analysis; refusing rather than guessing"
IFS=$'\t' read -r analysed analysis_ref analysis_tool analysis_error <<<"${analysis}" || true
[[ "${analysed:-}" != none ]] || die "GitHub lists no CodeQL analysis on main; refusing rather than guessing"
[[ "${analysis_ref:-}" == refs/heads/main && "${analysis_tool:-}" == CodeQL ]] ||
  die "GitHub answered an analysis by '${analysis_tool:-}' on '${analysis_ref:-}' for main's newest CodeQL analysis"
[[ "${analysed}" == "${sha}" ]] ||
  die "main's newest CodeQL analysis is of ${analysed}, not ${sha}, so main's alerts do not judge this commit"
[[ "${analysis_error:-}" == none ]] ||
  die "main's newest CodeQL analysis, of ${sha}, reports an error: ${analysis_error:-}"
printf 'check-gate-runs: no open high or critical CodeQL alert on main (%d alert(s) read), whose newest CodeQL analysis is of %s\n' "${answered}" "${sha}"
