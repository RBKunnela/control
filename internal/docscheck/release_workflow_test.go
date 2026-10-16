package docscheck

import (
	"fmt"
	"maps"
	"regexp"
	"strings"
	"testing"
)

const releaseWorkflowPath = ".github/workflows/release.yml"

// Each index's publisher trusts one environment alone, so a job of
// release.yml that gains an environment gains whatever trusts it.
var releaseEnvironments = map[string]string{"release": "release", "index": "pypi", "test-index": "testpypi"}

// releaseJobEnvironments maps each job of a workflow that names an
// environment to it; a mapping without a name maps to "?". What this reader
// would take for something else is refused: a quoted or decorated key, a flow
// mapping, a tag, an anchor, an alias or a merge key, any of which could
// carry an environment past it.
func releaseJobEnvironments(lines []string) (map[string]string, error) {
	root, err := parseBlockYAML(lines)
	if err != nil {
		return nil, err
	}
	if n := unread(root); n != nil {
		return nil, fmt.Errorf("line %d: %q: %q is more YAML than this reader reads", n.line+1, n.key, n.value)
	}
	got := map[string]string{}
	jobs := root.children("jobs")
	if len(jobs) != 1 || len(jobs[0].kids) == 0 {
		return nil, fmt.Errorf("want one jobs mapping with jobs in it, found %d", len(jobs))
	}
	for _, job := range jobs[0].kids {
		for _, env := range job.children("environment") {
			name := env.value
			if name == "" {
				name = "?"
				for _, n := range env.children("name") {
					name = n.value
				}
			}
			got[job.key] = name
		}
	}
	return got, nil
}

var plainKey = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func unread(n *yamlNode) *yamlNode {
	if (n.key != "" && n.key != "-" && !plainKey.MatchString(n.key)) || strings.ContainsAny(n.value[:min(len(n.value), 1)], "{!&*") {
		return n
	}
	for _, kid := range n.kids {
		if found := unread(kid); found != nil {
			return found
		}
	}
	return nil
}

func TestReleaseJobsDeployToTheirOwnEnvironments(t *testing.T) {
	got, err := releaseJobEnvironments(readLines(t, repoFS(t), releaseWorkflowPath))
	if err != nil {
		t.Fatalf("%s: %v", releaseWorkflowPath, err)
	}
	if !maps.Equal(got, releaseEnvironments) {
		t.Errorf("%s: jobs deploy to %v, want %v", releaseWorkflowPath, got, releaseEnvironments)
	}
}

func TestReleaseJobEnvironmentsAreRead(t *testing.T) {
	const workflow = `name: Release
jobs:
  snapshot:
    runs-on: ubuntu-24.04
  release:
    environment: release
  index:
    environment: pypi
  test-index:
    environment: testpypi
`
	if got, err := releaseJobEnvironments(strings.Split(workflow, "\n")); err != nil || !maps.Equal(got, releaseEnvironments) {
		t.Fatalf("the matching fixture reads %v, %v", got, err)
	}
	for name, change := range map[string][2]string{
		"the snapshot in the test environment":  {"    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-24.04\n    environment: testpypi\n"},
		"the upload in the release environment": {"    environment: pypi\n", "    environment: release\n"},
		"the test upload with none":             {"    environment: testpypi\n", ""},
		"an environment as a mapping":           {"    environment: pypi\n", "    environment:\n      url: https://example.org\n"},
		"a job copied by an alias":              {"  index:\n", "  copy: *upload\n  index:\n"},
		"a job that anchors itself":             {"  index:\n", "  index: &upload\n"},
		"a merge key":                           {"    runs-on: ubuntu-24.04\n", "    <<: *upload\n"},
		"a flow mapping":                        {"  snapshot:\n    runs-on: ubuntu-24.04\n", "  snapshot: {environment: pypi}\n"},
		"a quoted key":                          {"    runs-on: ubuntu-24.04\n", "    \"environment\": pypi\n"},
		"an anchor on a key":                    {"    runs-on: ubuntu-24.04\n", "    &e environment: pypi\n"},
		"a tagged anchor":                       {"  index:\n", "  index: !!map &upload\n"},
	} {
		t.Run(name, func(t *testing.T) {
			changed := strings.Replace(workflow, change[0], change[1], 1)
			if changed == workflow {
				t.Fatalf("the fixture holds no %q", change[0])
			}
			if got, err := releaseJobEnvironments(strings.Split(changed, "\n")); err == nil && maps.Equal(got, releaseEnvironments) {
				t.Fatalf("%v passed", got)
			}
		})
	}
}
