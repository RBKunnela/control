package docscheck

import (
	"maps"
	"strings"
	"testing"
)

const releaseWorkflowPath = ".github/workflows/release.yml"

// Each index's publisher trusts one environment alone, so a job of
// release.yml that gains an environment gains whatever trusts it.
var releaseEnvironments = map[string]string{"release": "release", "index": "pypi", "test-index": "testpypi"}

// releaseJobEnvironments maps each job of a workflow that names an
// environment to it; a mapping without a name maps to "?".
func releaseJobEnvironments(t *testing.T, lines []string) map[string]string {
	t.Helper()
	root, err := parseBlockYAML(lines)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	jobs := root.children("jobs")
	if len(jobs) != 1 || len(jobs[0].kids) == 0 {
		t.Fatalf("want one jobs mapping with jobs in it, found %d", len(jobs))
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
	return got
}

func TestReleaseJobsDeployToTheirOwnEnvironments(t *testing.T) {
	got := releaseJobEnvironments(t, readLines(t, repoFS(t), releaseWorkflowPath))
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
	if got := releaseJobEnvironments(t, strings.Split(workflow, "\n")); !maps.Equal(got, releaseEnvironments) {
		t.Fatalf("the matching fixture reads %v", got)
	}
	for name, change := range map[string][2]string{
		"the snapshot in the test environment":  {"    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-24.04\n    environment: testpypi\n"},
		"the upload in the release environment": {"    environment: pypi\n", "    environment: release\n"},
		"the test upload with none":             {"    environment: testpypi\n", ""},
		"an environment as a mapping":           {"    environment: pypi\n", "    environment:\n      url: https://example.org\n"},
	} {
		t.Run(name, func(t *testing.T) {
			changed := strings.Replace(workflow, change[0], change[1], 1)
			if changed == workflow {
				t.Fatalf("the fixture holds no %q", change[0])
			}
			if got := releaseJobEnvironments(t, strings.Split(changed, "\n")); maps.Equal(got, releaseEnvironments) {
				t.Fatalf("%v passed", got)
			}
		})
	}
}
