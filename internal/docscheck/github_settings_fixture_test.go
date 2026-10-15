package docscheck

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

// answers are the fake GitHub's answers by endpoint, in the shape GitHub
// answers with: ids, links and fields the bootstrap never sends included.
type answers map[string]any

// rawAnswer is served as written, not as JSON.
type rawAnswer string

// pages is a list GitHub answers page by page.
type pages [][]any

const (
	labelsPath   = "repos/acme/demo/labels?per_page=100"
	rulesetsPath = "repos/acme/demo/rulesets?includes_parents=false"
)

func (a answers) ruleset(t *testing.T, name string) map[string]any {
	t.Helper()
	for _, rs := range a[rulesetsPath].([]any) {
		if rs.(map[string]any)["name"] == name {
			return a["repos/acme/demo/rulesets/"+strconv.Itoa(rs.(map[string]any)["id"].(int))].(map[string]any)
		}
	}
	t.Fatalf("the answers hold no ruleset %q", name)
	return nil
}

func (a answers) rule(t *testing.T, ruleset, kind string) map[string]any {
	t.Helper()
	for _, r := range a.ruleset(t, ruleset)["rules"].([]any) {
		if r.(map[string]any)["type"] == kind {
			return r.(map[string]any)["parameters"].(map[string]any)
		}
	}
	t.Fatalf("ruleset %q holds no rule %q", ruleset, kind)
	return nil
}

func (a answers) pullRequestRule(t *testing.T) map[string]any {
	t.Helper()
	return a.rule(t, "main: pull requests", "pull_request")
}

// dropRule removes the rule of that type from the ruleset's answer.
func (a answers) dropRule(t *testing.T, ruleset, kind string) {
	t.Helper()
	rs := a.ruleset(t, ruleset)
	rs["rules"] = slices.DeleteFunc(rs["rules"].([]any), func(r any) bool { return r.(map[string]any)["type"] == kind })
}

func (a answers) labels() []any { return slices.Concat(a[labelsPath].(pages)...) }

// addLabel puts a label on the last page.
func (a answers) addLabel(name, color, description string) {
	p := a[labelsPath].(pages)
	p[len(p)-1] = append(p[len(p)-1], map[string]any{"id": 900, "name": name, "color": color, "description": description, "default": true})
}

func (a answers) milestones() []any {
	return a["repos/acme/demo/milestones?state=all&per_page=100"].([]any)
}

func (a answers) object(endpoint string) map[string]any { return a[endpoint].(map[string]any) }

func reversed(values []string) []any {
	out := make([]any, len(values))
	for i, v := range values {
		out[len(values)-1-i] = v
	}
	return out
}

// matchingAnswers is GitHub holding exactly what the declarations say. The
// lists the declarations hold are read from them, and served in reverse; the
// shape around them is written out here, apart from the functions the check
// builds its bodies with.
func matchingAnswers(t *testing.T) answers {
	t.Helper()
	member := map[string]any{"state": "active", "role": "maintainer"}
	octo := []any{map[string]any{"login": "octo", "id": 7}}
	a := answers{
		"repos/acme/demo": map[string]any{
			"id": 77, "full_name": "acme/demo", "private": false, "permissions": map[string]any{"admin": true},
			"description":    settingsValues(t, `printf '%s\n' "${DESCRIPTION}"`)[0],
			"homepage":       settingsValues(t, `printf '%s\n' "${HOMEPAGE}"`)[0],
			"default_branch": "main", "has_issues": true, "has_wiki": false, "has_projects": false, "has_discussions": false,
			"allow_squash_merge": true, "allow_merge_commit": false, "allow_rebase_merge": false,
			"squash_merge_commit_title": "PR_TITLE", "squash_merge_commit_message": "COMMIT_MESSAGES",
			"delete_branch_on_merge": true, "allow_update_branch": true, "allow_auto_merge": false, "web_commit_signoff_required": true,
		},
		"repos/acme/demo/topics":                                           map[string]any{"names": reversed(settingsValues(t, `printf '%s\n' "${TOPICS[@]}"`))},
		"repos/acme/demo/immutable-releases":                               map[string]any{"enabled": true, "enforced_by_owner": false},
		"repos/acme/demo/actions/permissions":                              map[string]any{"enabled": true, "allowed_actions": "all", "sha_pinning_required": true},
		"repos/acme/demo/actions/permissions/workflow":                     map[string]any{"default_workflow_permissions": "read", "can_approve_pull_request_reviews": false},
		"repos/acme/demo/actions/permissions/fork-pr-contributor-approval": map[string]any{"approval_policy": "first_time_contributors"},
		"repos/acme/demo/teams?per_page=100": []any{
			map[string]any{"id": 41, "slug": "maintainers", "permission": "maintain"},
			map[string]any{"id": 42, "slug": "security-maintainers", "permission": "push"},
			map[string]any{"id": 43, "slug": "readers", "permission": "pull"},
		},
		"orgs/acme/teams/maintainers":                                   map[string]any{"id": 41, "slug": "maintainers", "description": "anything"},
		"orgs/acme/teams/security-maintainers":                          map[string]any{"id": 42, "slug": "security-maintainers"},
		"orgs/acme/teams/maintainers/members?per_page=100":              octo,
		"orgs/acme/teams/security-maintainers/members?per_page=100":     octo,
		"orgs/acme/teams/maintainers/teams?per_page=100":                []any{},
		"orgs/acme/teams/security-maintainers/teams?per_page=100":       []any{},
		"orgs/acme/teams/maintainers/memberships/octo":                  member,
		"orgs/acme/teams/security-maintainers/memberships/octo":         map[string]any{"state": "active", "role": "maintainer"},
		"repos/acme/demo/collaborators?affiliation=direct&per_page=100": []any{map[string]any{"login": "helper", "role_name": "write"}},
		"repos/acme/demo/collaborators?affiliation=all&per_page=100": []any{
			map[string]any{"login": "octo", "role_name": "admin"}, map[string]any{"login": "helper", "role_name": "write"},
		},
		"repos/acme/demo/environments/release": map[string]any{
			"id": 3, "name": "release", "can_admins_bypass": true,
			"deployment_branch_policy": map[string]any{"protected_branches": false, "custom_branch_policies": true},
			"protection_rules": []any{
				map[string]any{"id": 1, "type": "branch_policy"},
				map[string]any{"id": 2, "type": "required_reviewers", "prevent_self_review": false, "reviewers": []any{
					map[string]any{"type": "Team", "reviewer": map[string]any{"id": 41, "slug": "maintainers"}},
				}},
			},
		},
		"repos/acme/demo/environments/release/deployment-branch-policies": map[string]any{
			"total_count": 1, "branch_policies": []any{map[string]any{"id": 5, "name": "v*", "type": "tag"}},
		},
		"repos/acme/demo/environments/pypi": map[string]any{
			"id": 4, "name": "pypi", "can_admins_bypass": true,
			"deployment_branch_policy": map[string]any{"protected_branches": false, "custom_branch_policies": true},
			"protection_rules": []any{
				map[string]any{"id": 1, "type": "branch_policy"},
				map[string]any{"id": 2, "type": "required_reviewers", "prevent_self_review": false, "reviewers": []any{
					map[string]any{"type": "Team", "reviewer": map[string]any{"id": 41, "slug": "maintainers"}},
				}},
			},
		},
		"repos/acme/demo/environments/pypi/deployment-branch-policies": map[string]any{
			"total_count": 1, "branch_policies": []any{map[string]any{"id": 5, "name": "v*", "type": "tag"}},
		},
		"orgs/acme/code-security/configurations": []any{
			map[string]any{"id": 8, "name": "GitHub recommended", "enforcement": "unenforced"},
			map[string]any{
				"id": 9, "name": "demo", "target_type": "organization",
				"description":       "The security settings of acme/demo, applied by its scripts/github-bootstrap.sh.",
				"advanced_security": "enabled", "dependency_graph": "enabled", "dependabot_alerts": "enabled",
				"dependabot_security_updates": "enabled", "code_scanning_default_setup": "disabled", "secret_scanning": "enabled",
				"secret_scanning_push_protection": "enabled", "private_vulnerability_reporting": "enabled", "enforcement": "enforced",
			},
		},
		"repos/acme/demo/code-security-configuration": map[string]any{"status": "enforced", "configuration": map[string]any{"id": 9, "name": "demo"}},
	}
	addRulesets(t, a)
	addLabelsAndMilestones(t, a)
	return a
}

// gitHubPatternLimit is how many file patterns GitHub takes per required
// reviewer, written here independently of the declarations' chunk size.
const gitHubPatternLimit = 15

// twoApprovalChunks cuts the declared paths, in their order, into the parts
// the rulesets carry: the first in "main: pull requests", each later one in a
// ruleset of its own.
func twoApprovalChunks(t *testing.T) [][]string {
	t.Helper()
	paths := settingsValues(t, `printf '%s\n' "${TWO_APPROVAL_PATHS[@]}"`)
	var chunks [][]string
	for len(paths) > 0 {
		n := min(gitHubPatternLimit, len(paths))
		chunks = append(chunks, paths[:n])
		paths = paths[n:]
	}
	return chunks
}

// partName names the ruleset that carries chunk i, counted from 0.
func partName(i int) string {
	if i == 0 {
		return "main: pull requests"
	}
	return "main: two approvals, part " + strconv.Itoa(i+1)
}

func pullRequestRule(patterns []string) any {
	return map[string]any{"type": "pull_request", "parameters": map[string]any{
		"required_approving_review_count": 1, "dismiss_stale_reviews_on_push": true,
		"require_code_owner_review": true, "require_last_push_approval": true,
		"required_review_thread_resolution": true, "allowed_merge_methods": []any{"squash"},
		"dismissal_restriction":                           map[string]any{"enabled": false, "allowed_actors": []any{}},
		"require_extra_approval_for_unattributed_changes": true,
		"required_reviewers": []any{map[string]any{
			"minimum_approvals": 2, "file_patterns": reversed(patterns), "reviewer": map[string]any{"id": 42, "type": "Team"},
		}},
	}}
}

func addRulesets(t *testing.T, a answers) {
	t.Helper()
	role := func(id int, mode string) any {
		return map[string]any{"actor_id": id, "actor_type": "RepositoryRole", "bypass_mode": mode}
	}
	refs := func(include, exclude []any) any {
		return map[string]any{"ref_name": map[string]any{"exclude": exclude, "include": include}}
	}
	main, tags, none := []any{"~DEFAULT_BRANCH"}, []any{"refs/tags/v*"}, []any{}
	rule := func(kind string) any { return map[string]any{"type": kind} }
	var checks []any
	for _, c := range settingsValues(t, `printf '%s\n' "${REQUIRED_CHECKS[@]}"`) {
		checks = append([]any{map[string]any{"context": c, "integration_id": 15368}}, checks...)
	}
	chunks := twoApprovalChunks(t)
	rulesets := []map[string]any{
		{"name": "main: history", "target": "branch", "conditions": refs(main, none), "bypass_actors": []any{},
			"rules": []any{rule("deletion"), rule("non_fast_forward"), rule("required_linear_history")}},
		{"name": "release tags: create", "target": "tag", "conditions": refs(tags, none),
			"bypass_actors": []any{role(2, "always"), role(5, "always")}, "rules": []any{rule("creation")}},
		{"name": "other tags: create", "target": "tag", "conditions": refs([]any{"~ALL"}, tags),
			"bypass_actors": []any{role(5, "always"), role(2, "always")}, "rules": []any{rule("creation")}},
		{"name": "release tags: immutable", "target": "tag", "conditions": refs(tags, none), "bypass_actors": []any{},
			"rules": []any{rule("non_fast_forward"), rule("update"), rule("deletion")}},
		{"name": "main: merges", "target": "branch", "conditions": refs(main, none),
			"bypass_actors": []any{role(2, "pull_request"), role(5, "always")}, "rules": []any{rule("update")}},
		{"name": "main: pull requests", "target": "branch", "conditions": refs(main, none),
			"bypass_actors": []any{role(5, "always")}, "rules": []any{
				pullRequestRule(chunks[0]),
				map[string]any{"type": "required_status_checks", "parameters": map[string]any{
					"strict_required_status_checks_policy": true, "do_not_enforce_on_create": false, "required_status_checks": checks,
				}},
				map[string]any{"type": "code_scanning", "parameters": map[string]any{"code_scanning_tools": []any{
					map[string]any{"tool": "CodeQL", "security_alerts_threshold": "high_or_higher", "alerts_threshold": "errors"},
				}}},
			}},
	}
	for i := 1; i < len(chunks); i++ {
		rulesets = append(rulesets, map[string]any{"name": partName(i), "target": "branch", "conditions": refs(main, none),
			"bypass_actors": []any{role(5, "always")}, "rules": []any{pullRequestRule(chunks[i])}})
	}
	list := []any{map[string]any{"id": 99, "name": "someone else's", "enforcement": "evaluate"}}
	for i, rs := range rulesets {
		id := i + 1
		rs["id"], rs["enforcement"], rs["source"] = id, "active", "acme/demo"
		rs["created_at"], rs["_links"] = "2026-01-01T00:00:00Z", map[string]any{"self": map[string]any{"href": "x"}}
		a["repos/acme/demo/rulesets/"+strconv.Itoa(id)] = rs
		list = append(list, map[string]any{"id": id, "name": rs["name"], "enforcement": "active"})
	}
	a[rulesetsPath] = list
	requireFixtureUnion(t, a, len(chunks))
}

// requireFixtureUnion fails unless the parts the answers hold carry the
// declared paths, each once: a fixture that lost one would pass the check for
// the wrong reason.
func requireFixtureUnion(t *testing.T, a answers, parts int) {
	t.Helper()
	var union []string
	for i := range parts {
		for _, p := range a.rule(t, partName(i), "pull_request")["required_reviewers"].([]any)[0].(map[string]any)["file_patterns"].([]any) {
			union = append(union, p.(string))
		}
	}
	want := settingsValues(t, `printf '%s\n' "${TWO_APPROVAL_PATHS[@]}"`)
	slices.Sort(union)
	sorted := slices.Sorted(slices.Values(want))
	if !slices.Equal(union, sorted) {
		t.Fatalf("the fixture's parts hold %d pattern(s) %q, want the %d declared %q", len(union), union, len(want), want)
	}
}

func addLabelsAndMilestones(t *testing.T, a answers) {
	t.Helper()
	first := []any{map[string]any{"id": 1, "name": "question", "color": "d876e3", "description": "Further information is requested"}}
	var second []any
	for i, line := range settingsValues(t, `labels`) {
		f := strings.SplitN(line, "|", 3)
		label := map[string]any{"id": i + 2, "name": f[0], "color": strings.ToUpper(f[1]), "description": f[2], "default": false}
		if i%2 == 0 {
			first = append(first, label)
		} else {
			second = append(second, label)
		}
	}
	a[labelsPath] = pages{first, second}
	var milestones []any
	for i, title := range settingsValues(t, `printf '%s\n' "${MILESTONES[@]}"`) {
		milestones = append(milestones, map[string]any{"number": i + 1, "title": title, "state": "open"})
	}
	milestones = append(milestones, map[string]any{"number": 90, "title": "Some other", "state": "open"})
	for i, title := range settingsValues(t, `printf '%s\n' "${RETIRED_MILESTONES[@]}"`) {
		milestones = append(milestones, map[string]any{"number": 100 + i, "title": title, "state": "closed"})
	}
	a["repos/acme/demo/milestones?state=all&per_page=100"] = milestones
}
