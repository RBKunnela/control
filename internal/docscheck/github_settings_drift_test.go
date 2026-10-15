package docscheck

import (
	"regexp"
	"slices"
	"testing"
)

type driftCase struct {
	mutate func(*testing.T, answers)
	item   string
	says   string
}

func TestSettingsCheckReportsRulesetDrift(t *testing.T) {
	t.Parallel()
	const pattern = "internal/supervise/**"
	if !slices.Contains(settingsValues(t, `printf '%s\n' "${TWO_APPROVAL_PATHS[@]}"`), pattern) {
		t.Fatalf("%s no longer declares %s; pick another pattern for this case", githubSettings, pattern)
	}
	if len(twoApprovalChunks(t)) < 2 {
		t.Fatal("the declared paths fit one ruleset, so the cases for further parts examine nothing")
	}
	runDriftCases(t, map[string]driftCase{
		"a file pattern missing": {func(t *testing.T, a answers) {
			reviewer := a.pullRequestRule(t)["required_reviewers"].([]any)[0].(map[string]any)
			reviewer["file_patterns"] = slices.DeleteFunc(reviewer["file_patterns"].([]any), func(p any) bool { return p == pattern })
		}, "ruleset main: pull requests", `lacks "` + pattern + `"`},
		"a required check from another app": {func(t *testing.T, a answers) {
			checks := a.rule(t, "main: pull requests", "required_status_checks")["required_status_checks"].([]any)
			checks[0].(map[string]any)["integration_id"] = 1
		}, "ruleset main: pull requests", "required_status_checks"},
		"a declared true set false": {func(t *testing.T, a answers) {
			a.pullRequestRule(t)["require_code_owner_review"] = false
		}, "ruleset main: pull requests", "require_code_owner_review: declared true, live false"},
		"a declared parameter missing": {func(t *testing.T, a answers) {
			delete(a.pullRequestRule(t), "require_code_owner_review")
		}, "ruleset main: pull requests", "require_code_owner_review: declared true, absent"},
		"the required reviewers missing": {func(t *testing.T, a answers) {
			delete(a.pullRequestRule(t), "required_reviewers")
		}, "ruleset main: pull requests", "required_reviewers"},
		"an undeclared parameter": {func(t *testing.T, a answers) {
			a.pullRequestRule(t)["automatic_copilot_code_review_enabled"] = false
		}, "ruleset main: pull requests", "automatic_copilot_code_review_enabled: live false, not declared"},
		"the code scanning rule missing": {func(t *testing.T, a answers) {
			a.dropRule(t, "main: pull requests", "code_scanning")
		}, "ruleset main: pull requests", "rules.code_scanning"},
		"a history rule missing": {func(t *testing.T, a answers) {
			a.dropRule(t, "main: history", "non_fast_forward")
		}, "ruleset main: history", "rules.non_fast_forward"},
		"an absent false parameter set true": {func(t *testing.T, a answers) {
			a.ruleset(t, "main: merges")["rules"] = []any{map[string]any{"type": "update", "parameters": map[string]any{"update_allows_fetch_and_merge": true}}}
		}, "ruleset main: merges", "update_allows_fetch_and_merge"},
		"an undeclared rule": {func(t *testing.T, a answers) {
			rs := a.ruleset(t, "main: history")
			rs["rules"] = append(rs["rules"].([]any), map[string]any{"type": "creation"})
		}, "ruleset main: history", "rules.creation"},
		"an extra bypass": {func(t *testing.T, a answers) {
			a.ruleset(t, "release tags: immutable")["bypass_actors"] = []any{map[string]any{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}}
		}, "ruleset release tags: immutable", "bypass_actors: holds"},
		"a two-approval part gone": {func(_ *testing.T, a answers) {
			a[rulesetsPath] = slices.DeleteFunc(a[rulesetsPath].([]any), func(rs any) bool { return rs.(map[string]any)["name"] == partName(1) })
		}, "ruleset " + partName(1), "no ruleset has this name"},
		"a two-approval part left over": {func(_ *testing.T, a answers) {
			a[rulesetsPath] = append(a[rulesetsPath].([]any), map[string]any{"id": 98, "name": "main: two approvals, part 9"})
		}, "leftover two-approval parts", `holds "main: two approvals, part 9"`},
		"a pattern in no part": {func(t *testing.T, a answers) {
			reviewer := a.rule(t, partName(1), "pull_request")["required_reviewers"].([]any)[0].(map[string]any)
			reviewer["file_patterns"] = reviewer["file_patterns"].([]any)[1:]
		}, "ruleset " + partName(1), "file_patterns: lacks"},
		"a ruleset gone": {func(_ *testing.T, a answers) {
			a[rulesetsPath] = slices.DeleteFunc(a[rulesetsPath].([]any), func(rs any) bool { return rs.(map[string]any)["name"] == "main: history" })
		}, "ruleset main: history", "no ruleset has this name"},
	})
}

func TestSettingsCheckReportsWhoElseHoldsAuthority(t *testing.T) {
	t.Parallel()
	runDriftCases(t, map[string]driftCase{
		"a team with less access": {func(_ *testing.T, a answers) {
			a["repos/acme/demo/teams?per_page=100"].([]any)[1].(map[string]any)["permission"] = "pull"
		}, "team security-maintainers", `declared "push", live "pull"`},
		"a membership pending": {func(_ *testing.T, a answers) {
			a.object("orgs/acme/teams/maintainers/memberships/octo")["state"] = "pending"
		}, "team maintainers", `members.octo.state: declared "active", live "pending"`},
		"an undeclared member": {func(_ *testing.T, a answers) {
			a["orgs/acme/teams/maintainers/members?per_page=100"] = []any{map[string]any{"login": "octo"}, map[string]any{"login": "mallory"}}
		}, "team maintainers", "members.mallory"},
		"a child team": {func(_ *testing.T, a answers) {
			a["orgs/acme/teams/security-maintainers/teams?per_page=100"] = []any{map[string]any{"slug": "juniors"}}
		}, "team security-maintainers", `children: holds "juniors"`},
		"another team with maintain": {func(_ *testing.T, a answers) {
			a["repos/acme/demo/teams?per_page=100"].([]any)[2].(map[string]any)["permission"] = "maintain"
		}, "other teams", `"readers maintain"`},
		"a direct collaborator with admin": {func(_ *testing.T, a answers) {
			a["repos/acme/demo/collaborators?affiliation=direct&per_page=100"].([]any)[0].(map[string]any)["role_name"] = "admin"
		}, "direct collaborators", `"helper admin"`},
		"another admin": {func(_ *testing.T, a answers) {
			a["repos/acme/demo/collaborators?affiliation=all&per_page=100"].([]any)[1].(map[string]any)["role_name"] = "admin"
		}, "repository admins", `"helper"`},
		"an environment reviewer of another type": {func(_ *testing.T, a answers) {
			rules := a.object("repos/acme/demo/environments/release")["protection_rules"].([]any)
			rules[1].(map[string]any)["reviewers"].([]any)[0].(map[string]any)["type"] = "User"
		}, "environment release", `"type":"User"`},
		"a second tag policy": {func(_ *testing.T, a answers) {
			env := a.object("repos/acme/demo/environments/release/deployment-branch-policies")
			env["branch_policies"] = append(env["branch_policies"].([]any), map[string]any{"id": 6, "name": "main", "type": "branch"})
		}, "environment release deployment policies", "not declared"},
		"the upload environment without its reviewers": {func(_ *testing.T, a answers) {
			env := a.object("repos/acme/demo/environments/pypi")
			env["protection_rules"] = env["protection_rules"].([]any)[:1]
		}, "environment pypi", "reviewers"},
		"the upload environment open to a branch": {func(_ *testing.T, a answers) {
			env := a.object("repos/acme/demo/environments/pypi/deployment-branch-policies")
			env["branch_policies"] = append(env["branch_policies"].([]any), map[string]any{"id": 7, "name": "main", "type": "branch"})
		}, "environment pypi deployment policies", "not declared"},
		"the test environment with a reviewer": {func(_ *testing.T, a answers) {
			env := a.object("repos/acme/demo/environments/testpypi")
			env["protection_rules"] = append(env["protection_rules"].([]any), map[string]any{
				"id": 2, "type": "required_reviewers", "prevent_self_review": false, "reviewers": []any{
					map[string]any{"type": "Team", "reviewer": map[string]any{"id": 41, "slug": "maintainers"}},
				},
			})
		}, "environment testpypi", "reviewers"},
		"the test environment open to a tag": {func(_ *testing.T, a answers) {
			env := a.object("repos/acme/demo/environments/testpypi/deployment-branch-policies")
			env["branch_policies"] = append(env["branch_policies"].([]any), map[string]any{"id": 9, "name": "v*", "type": "tag"})
		}, "environment testpypi deployment policies", "not declared"},
		"the test environment open to every branch": {func(_ *testing.T, a answers) {
			a.object("repos/acme/demo/environments/testpypi")["deployment_branch_policy"] = nil
		}, "environment testpypi", "deployment_branch_policy"},
		"the test environment an admin bypasses": {func(_ *testing.T, a answers) {
			a.object("repos/acme/demo/environments/testpypi")["can_admins_bypass"] = true
		}, "environment testpypi", "can_admins_bypass"},
		"the test environment on another branch": {func(_ *testing.T, a answers) {
			env := a.object("repos/acme/demo/environments/testpypi/deployment-branch-policies")
			env["branch_policies"].([]any)[0].(map[string]any)["name"] = "release/*"
		}, "environment testpypi deployment policies", "lacks"},
		"a configuration attached but not enforced": {func(_ *testing.T, a answers) {
			a.object("repos/acme/demo/code-security-configuration")["status"] = "attached"
		}, "code security configuration", `attached.status: declared "enforced", live "attached"`},
		"immutable releases off": {func(_ *testing.T, a answers) {
			delete(a, "repos/acme/demo/immutable-releases")
		}, "immutable releases", "not enabled"},
		"another description": {func(_ *testing.T, a answers) {
			a.object("repos/acme/demo")["description"] = "Watch what your agents do."
		}, "repository settings", "description: declared"},
	})
}

func TestSettingsCheckReportsLabelAndMilestoneDrift(t *testing.T) {
	t.Parallel()
	runDriftCases(t, map[string]driftCase{
		"a retired label on the second page, held": {func(_ *testing.T, a answers) {
			a.addLabel("Bug", "d73a4a", "Something isn't working")
			a["repos/acme/demo/issues?labels=Bug&state=all&per_page=100"] = []any{map[string]any{"number": 1}, map[string]any{"number": 2}}
		}, "labels retired", `"Bug" present, held by 2 issue(s) or pull request(s)`},
		"a label with another description": {func(_ *testing.T, a answers) {
			a.labels()[1].(map[string]any)["description"] = "something else"
		}, "labels", "description"},
		"a milestone closed": {func(_ *testing.T, a answers) {
			a.milestones()[0].(map[string]any)["state"] = "closed"
		}, "milestones", "is closed"},
		"a retired milestone open": {func(_ *testing.T, a answers) {
			a.milestones()[len(a.milestones())-1].(map[string]any)["state"] = "open"
		}, "milestones retired", "is open"},
	})
}

func runDriftCases(t *testing.T, cases map[string]driftCase) {
	t.Helper()
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			a := matchingAnswers(t)
			tc.mutate(t, a)
			out, code, _ := runSettingsCheck(t, a, settingsRun{})
			if code != 1 {
				t.Fatalf("exit %d, want 1:\n%s", code, out)
			}
			expectVerdicts(t, out, map[string]string{tc.item: "drift"}, regexp.QuoteMeta(tc.says))
		})
	}
}
