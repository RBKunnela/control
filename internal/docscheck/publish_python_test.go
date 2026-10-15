package docscheck

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The fakes of scripts/publish-python-dist.sh: uv answers its version and
// logs every other call, failing with FAKE_UV_RC; curl logs its arguments and
// prints the file FAKE_DIR/answer, or fails as a refused request does when
// that file is missing; sleep returns at once.
const (
	fakePublishUv = `#!/usr/bin/env bash
if [[ "$*" == --version ]]; then echo "uv ${FAKE_UV_VERSION}"; exit 0; fi
printf '%s\n' "$*" >>"${FAKE_DIR}/uv"
exit "${FAKE_UV_RC:-0}"
`
	fakePublishCurl = `#!/usr/bin/env bash
printf '%s\n' "$*" >>"${FAKE_DIR}/curl"
[[ -f "${FAKE_DIR}/answer" ]] || exit 22
cat "${FAKE_DIR}/answer"
`
	fakePublishSleep = "#!/usr/bin/env bash\nexit 0\n"
)

var publishTools = []string{"bash", "env", "cat", "dirname", "find", "wc", "tr", "basename", "sha256sum", "cut", "sort", "jq"}

type publishRun struct {
	files   map[string]string // name -> content of the directory handed over
	index   string
	version string
	answer  *string // nil: every read of the index fails
	uvRC    string
	uv      string // the version the fake uv reports; the pinned one when empty
}

// runPublish runs the script with the fakes and returns its output, exit
// status, and the calls uv and curl received.
func runPublish(t *testing.T, run publishRun) (string, int, []string, []string) {
	t.Helper()
	dir := t.TempDir()
	bin, dist := publishFakes(t, dir, run)
	args := []string{filepath.Join(repoRoot(t), "scripts", "publish-python-dist.sh"), dist, run.index}
	if run.version != "" {
		args = append(args, run.version)
	}
	cmd := exec.Command(settingsTool(t, "bash"), args...) //nolint:gosec // G204: bash from PATH running this repository's own script
	uv := run.uv
	if uv == "" {
		uv = pinnedUv(t)
	}
	cmd.Env = []string{"PATH=" + bin, "FAKE_DIR=" + dir, "FAKE_UV_VERSION=" + uv, "FAKE_UV_RC=" + run.uvRC, "HOME=" + dir, "TMPDIR=" + dir}
	out, err := fileOutput(t, cmd, true)
	return out, exitCode(t, err), fakeCalls(t, filepath.Join(dir, "uv")), fakeCalls(t, filepath.Join(dir, "curl"))
}

// publishFakes writes the bin directory of tools and fakes, the files handed
// over and the index's answer under dir, and returns the bin and files
// directories.
func publishFakes(t *testing.T, dir string, run publishRun) (string, string) {
	t.Helper()
	bin := filepath.Join(dir, "bin")
	dist := filepath.Join(dir, "dist")
	for _, d := range []string{bin, dist} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, tool := range publishTools {
		if err := os.Symlink(settingsTool(t, tool), filepath.Join(bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"uv": fakePublishUv, "curl": fakePublishCurl, "sleep": fakePublishSleep} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o700); err != nil { //nolint:gosec // G306: the fake has to be executable
			t.Fatal(err)
		}
	}
	for name, content := range run.files {
		if err := os.WriteFile(filepath.Join(dist, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if run.answer != nil {
		if err := os.WriteFile(filepath.Join(dir, "answer"), []byte(*run.answer), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return bin, dist
}

func fakeCalls(t *testing.T, file string) []string {
	t.Helper()
	b, err := os.ReadFile(file) //nolint:gosec // G304: the test's own temporary directory
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

func pinnedUv(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", "tool-versions.env"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^UV_VERSION=v?([0-9]+\.[0-9]+\.[0-9]+)$`).FindSubmatch(b)
	if m == nil {
		t.Fatal("scripts/tool-versions.env pins no uv version")
	}
	return string(m[1])
}

const (
	pubWheel   = "guardana_control-1.2.3-py3-none-any.whl"
	pubArchive = "guardana_control-1.2.3.tar.gz"
)

var pubFiles = map[string]string{pubWheel: "wheel bytes", pubArchive: "archive bytes"}

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// listing is the index's JSON answer for a release holding these files.
func listing(t *testing.T, files map[string]string) *string {
	t.Helper()
	type entry struct {
		Filename string            `json:"filename"`
		Digests  map[string]string `json:"digests"`
	}
	urls := []entry{}
	for name, content := range files {
		urls = append(urls, entry{name, map[string]string{"sha256": digest(content)}})
	}
	b, err := json.Marshal(map[string]any{"urls": urls})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	return &s
}

func text(s string) *string { return &s }

func TestPublishReadsBackExactlyTheUploadedFiles(t *testing.T) {
	for index, hosts := range map[string][2]string{
		"pypi":     {"https://upload.pypi.org/legacy/", "https://pypi.org/pypi/guardana_control/1.2.3/json"},
		"testpypi": {"https://test.pypi.org/legacy/", "https://test.pypi.org/pypi/guardana_control/1.2.3/json"},
	} {
		t.Run(index, func(t *testing.T) {
			out, code, uv, curl := runPublish(t, publishRun{files: pubFiles, index: index, version: "1.2.3", answer: listing(t, pubFiles)})
			if code != 0 {
				t.Fatalf("exit %d, want 0:\n%s", code, out)
			}
			if len(uv) != 1 || !strings.HasPrefix(uv[0], "publish --trusted-publishing always --publish-url "+hosts[0]+" ") {
				t.Fatalf("uv calls %q, want one trusted upload to %s", uv, hosts[0])
			}
			if len(curl) != 1 || !strings.Contains(curl[0], hosts[1]) {
				t.Fatalf("curl calls %q, want one read of %s", curl, hosts[1])
			}
		})
	}
}

func TestPublishRefusesBeforeUploading(t *testing.T) {
	cases := map[string]publishRun{
		"no version given":       {files: pubFiles, index: "pypi"},
		"another version given":  {files: pubFiles, index: "pypi", version: "1.2.4"},
		"a version with a tail":  {files: pubFiles, index: "pypi", version: "1.2.3+local"},
		"an index of no name":    {files: pubFiles, index: "elsewhere", version: "1.2.3"},
		"another uv":             {files: pubFiles, index: "pypi", version: "1.2.3", uv: "0.0.1"},
		"a post release":         {files: map[string]string{"guardana_control-1.2.3.post1-py3-none-any.whl": "w", "guardana_control-1.2.3.post1.tar.gz": "a"}, index: "pypi", version: "1.2.3.post1"},
		"a wheel of another":     {files: map[string]string{"guardana_control-1.2.4-py3-none-any.whl": "w", pubArchive: "a"}, index: "pypi", version: "1.2.3"},
		"an archive of another":  {files: map[string]string{pubWheel: "w", "guardana_control-1.2.4.tar.gz": "a"}, index: "pypi", version: "1.2.3"},
		"a third file":           {files: map[string]string{pubWheel: "w", pubArchive: "a", "notes.txt": "n"}, index: "pypi", version: "1.2.3"},
		"no archive":             {files: map[string]string{pubWheel: "w"}, index: "pypi", version: "1.2.3"},
		"a wheel for a platform": {files: map[string]string{"guardana_control-1.2.3-cp311-cp311-linux_x86_64.whl": "w", pubArchive: "a"}, index: "pypi", version: "1.2.3"},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			run.answer = listing(t, run.files)
			out, code, uv, _ := runPublish(t, run)
			if code == 0 {
				t.Fatalf("exit 0, want a refusal:\n%s", out)
			}
			if len(uv) != 0 {
				t.Fatalf("uv was called %q before the refusal", uv)
			}
		})
	}
}

func TestPublishFailsUnlessTheIndexListsExactlyTheFiles(t *testing.T) {
	altered := map[string]string{pubWheel: "other bytes", pubArchive: "archive bytes"}
	extra := map[string]string{pubWheel: "wheel bytes", pubArchive: "archive bytes", "guardana_control-1.2.3-py3-none-any.whl.x": "x"}
	wheelOnly := map[string]string{pubWheel: "wheel bytes"}
	cases := map[string]publishRun{
		"the upload fails":        {answer: listing(t, pubFiles), uvRC: "1"},
		"the index never answers": {},
		"no files listed":         {answer: text(`{"urls":[]}`)},
		"no urls key":             {answer: text(`{}`)},
		"not JSON":                {answer: text(`<html>busy</html>`)},
		"a file altered":          {answer: listing(t, altered)},
		"a file more":             {answer: listing(t, extra)},
		"a file fewer":            {answer: listing(t, wheelOnly)},
		"a file listed twice": {answer: text(`{"urls":[` +
			`{"filename":"` + pubWheel + `","digests":{"sha256":"` + digest("wheel bytes") + `"}},` +
			`{"filename":"` + pubWheel + `","digests":{"sha256":"` + digest("wheel bytes") + `"}},` +
			`{"filename":"` + pubArchive + `","digests":{"sha256":"` + digest("archive bytes") + `"}}]}`)},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			run.files, run.index, run.version = pubFiles, "pypi", "1.2.3"
			out, code, _, _ := runPublish(t, run)
			if code == 0 {
				t.Fatalf("exit 0, want a failure:\n%s", out)
			}
		})
	}
}
