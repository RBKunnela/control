#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# The negative control of the gate targets that loop over every Go module. It
# stages a tree holding this repository's Makefile, .golangci.yml, scripts/lib
# and scripts/fuzz-smoke.sh, a small root module and a nested module that
# imports it through a replace, as a consumer example does, and runs the real
# targets there with make:
#   clean     vet, test, test-race, lint, tidy-check, fuzz-list and fuzz-smoke each pass
#             and report two modules, with a go.work beside them naming the
#             root alone and a go.mod under the nested module's testdata; test
#             prints the reporter's transcript and its count of no skip
#   skip      a skipping test in the nested module, refused by name until the
#             staged expected-skips.txt lists it, then passed with its message
#   planted   one defect at a time in the nested module, and the target that
#             answers for it must fail on that defect and name the module:
#               vet         a format verb with the wrong argument
#               vet         the same in a file only GOOS=windows compiles
#               test        a failing test, shown in the reporter's lines
#               test-race   a data race
#               test-race   a TestMain only a race build compiles, which
#                           returns before m.Run and so runs no test
#               lint        a gosec finding, with a .golangci.yml in the
#                           module that switches gosec off, so a target that
#                           discovered its configuration would pass
#               lint        a gosec finding in a program under scripts/
#               tidy-check  a direct requirement marked indirect
#               fuzz-smoke  a fuzz target whose seed fails
#               fuzz-smoke  a fuzz target in a file a build constraint
#               and         leaves out, which go test passes unfuzzed
#               fuzz-list
#               fuzz-smoke  a fuzz target whose seed fails, with a comment
#                           between func and its name, alone in its package
#               fuzz-smoke  a test file the search cannot read, alone in its
#                           package (an explicit SKIP for a user who reads it)
#   refused   every target refuses, through the module list, a tree whose
#             root holds no go.mod, a module directory named with a glob
#             (examples/n[x], beside an examples/nx a glob would match), and
#             a GO.MOD, which a case-insensitive file system makes a module
# The module list itself is compared with the expected one in a git work tree
# and in a tree with no .git, where repo_files falls back to find.
#
# govulncheck is not probed: proving that it reads a module needs a known
# vulnerability in that module's dependencies and the vulnerability database,
# which is a network fetch, and `make security` runs the secret and advisory
# scanners besides.
set -euo pipefail

_PROBE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
# shellcheck source=lib/repo-files.sh
. "${_PROBE_DIR}/lib/repo-files.sh"

die() {
  printf 'check-modules-probe: %s\n' "$*" >&2
  exit 1
}

root="$(repo_root)"
for tool in go golangci-lint git make; do
  command -v "${tool}" >/dev/null 2>&1 || die "${tool} is not on PATH, so the probe cannot run"
done

goversion="$(sed -n 's/^go \([0-9][0-9.]*\)$/\1/p' "${root}/go.mod")"
[[ -n "${goversion}" ]] || die "no go directive found in ${root}/go.mod"

copy="$(mktemp -d)"
trap 'rm -rf "${copy}"' EXIT
nested="examples/nested"

libs="$(repo_files 'scripts/lib/*.sh')"
[[ -n "${libs}" ]] || die "repo_files listed nothing under scripts/lib"
mkdir -p "${copy}/scripts/lib" "${copy}/${nested}/testdata/unused"
while IFS= read -r file; do
  cp "${root}/${file}" "${copy}/${file}"
done <<<"${libs}"
for file in Makefile .golangci.yml scripts/fuzz-smoke.sh; do
  cp "${root}/${file}" "${copy}/${file}"
done
# make test pipes go test -json through scripts/test-report.go, whose logic is
# internal/testreport; the staged root module carries both, under its own path,
# the list of expected skips, and a test of the package, which the reporter
# refuses to pass without one.
mkdir -p "${copy}/internal/testreport"
cp "${root}/internal/testreport/doc.go" "${root}/internal/testreport/report.go" \
  "${root}/internal/testreport/generated.go" "${root}/internal/testreport/expected.go" \
  "${copy}/internal/testreport/"
cp "${root}/scripts/expected-skips.txt" "${copy}/scripts/expected-skips.txt"
cat >"${copy}/internal/testreport/staged_test.go" <<'EOF'
package testreport

import (
	"io"
	"strings"
	"testing"
)

func TestStagedReporterRefusesAnEmptyStream(t *testing.T) {
	if _, err := Summarize(strings.NewReader(""), io.Discard, "", nil); err == nil {
		t.Fatal("the staged reporter passed an empty stream")
	}
}
EOF
sed 's#"github.com/guardana/control/internal/testreport"#"example.com/probe/internal/testreport"#' \
  "${root}/scripts/test-report.go" >"${copy}/scripts/test-report.go"
grep -q '"example.com/probe/internal/testreport"' "${copy}/scripts/test-report.go" ||
  die "scripts/test-report.go does not import internal/testreport by the path this probe rewrites"

# write <path in the copy>, the content on stdin.
write() {
  cat >"${copy}/$1"
}

write go.mod <<EOF
module example.com/probe

go ${goversion}
EOF
write go.work <<EOF
go ${goversion}

use .
EOF
write probe.go <<'EOF'
// Package probe is the root module of the staged tree.
package probe

// Answer returns a constant.
func Answer() int { return 42 }
EOF
write probe_test.go <<'EOF'
package probe

import "testing"

func TestAnswer(t *testing.T) {
	if Answer() != 42 {
		t.Fatal("Answer changed")
	}
}

func FuzzAnswer(f *testing.F) {
	f.Add(1)
	f.Fuzz(func(t *testing.T, n int) {
		if Answer()+n-n != 42 {
			t.Fatal("Answer changed")
		}
	})
}
EOF
write scripts/gen-probe.go <<'EOF'
//go:build ignore

// Command gen-probe is the generator the vet target compiles.
package main

func main() {}
EOF

# nested_gomod [indirect]
nested_gomod() {
  write "${nested}/go.mod" <<EOF
module example.com/nested

go ${goversion}

require example.com/probe v0.0.0${1:+ // indirect}

replace example.com/probe => ../..
EOF
}
nested_gomod
write "${nested}/nested.go" <<'EOF'
// Package nested is the nested module of the staged tree.
package nested

import "example.com/probe"

// Double returns twice the root module's answer.
func Double() int { return 2 * probe.Answer() }
EOF
write "${nested}/nested_test.go" <<'EOF'
package nested

import "testing"

func TestDouble(t *testing.T) {
	if Double() != 84 {
		t.Fatal("Double changed")
	}
}

func FuzzDouble(f *testing.F) {
	f.Add(1)
	f.Fuzz(func(t *testing.T, n int) {
		if Double()+n-n != 84 {
			t.Fatal("Double changed")
		}
	})
}
EOF
write "${nested}/testdata/unused/go.mod" <<EOF
module example.com/unused

go ${goversion}
EOF

git -C "${copy}" init -q || die "git init failed in the staged tree"

failures=0
expected=0
runs=0
passes=0
refusals=0
out=""
shown=""
label=""

# run <pass|fail> <make target>
# Runs the target with make in the staged tree and keeps its output for
# expect. An exit status other than the one asked for is a failure of the probe.
run() {
  local want="$1" rc=0
  label="$2 (${3:-clean})"
  runs=$((runs + 1))
  if [[ "${want}" == pass ]]; then
    passes=$((passes + 1))
  else
    refusals=$((refusals + 1))
  fi
  shown=""
  out="$(MAKEFLAGS='' MAKELEVEL='' make -C "${copy}" --no-print-directory "$2" FUZZTIME=1s 2>&1)" || rc=$?
  if [[ "${want}" == pass && ${rc} -ne 0 ]]; then
    printf 'check-modules-probe: make %s exited %d; it had to pass\n' "${label}" "${rc}" >&2
    failures=$((failures + 1))
    show
  elif [[ "${want}" == fail && ${rc} -eq 0 ]]; then
    printf 'check-modules-probe: make %s exited 0; it had to fail\n' "${label}" >&2
    failures=$((failures + 1))
    show
  fi
}

show() {
  [[ -z "${shown}" ]] || return 0
  shown=yes
  printf -- '--- the last 30 lines make %s printed:\n' "${label}" >&2
  tail -n 30 <<<"${out}" >&2
  printf -- '---\n' >&2
}

# expect <text a line must hold> [<more text the same line must hold>]
expect() {
  local lines
  expected=$((expected + 1))
  lines="$(grep -F -- "$1" <<<"${out}" || true)"
  if [[ -n "${lines}" ]] && grep -qF -- "${2:-$1}" <<<"${lines}"; then
    return 0
  fi
  printf 'check-modules-probe: make %s did not report: %s %s\n' "${label}" "$1" "${2:-}" >&2
  failures=$((failures + 1))
  show
}

# expect_start <text a line must begin with> [<more text the same line must hold>]
# A line of raw `go test -json` begins with "{", so only the reporter's own
# transcript can satisfy it.
expect_start() {
  local line
  expected=$((expected + 1))
  while IFS= read -r line; do
    if [[ "${line}" == "$1"* && "${line}" == *"${2:-$1}"* ]]; then
      return 0
    fi
  done <<<"${out}"
  printf 'check-modules-probe: make %s printed no line beginning: %s %s\n' "${label}" "$1" "${2:-}" >&2
  failures=$((failures + 1))
  show
}

# plant <file name in the nested module>, the content on stdin.
plant() {
  write "${nested}/$1"
}

for target in vet test test-race lint tidy-check; do
  run pass "${target}"
  expect "${target}: module ${nested}"
  expect "${target}: 2 module(s)"
  [[ "${target}" != lint ]] || expect "lint: 2 program(s) under scripts/ linted"
  if [[ "${target}" == test ]]; then
    expect_start "ok  "$'\t'"example.com/nested"
    expect_start "test: 0 skipped"
  fi
done
run pass fuzz-smoke
expect "fuzz-smoke: ./${nested} FuzzDouble for 1s"
expect "fuzz-smoke: 2 module(s)"
expect "fuzz-smoke: 2 target(s) run for 1s each"
run pass fuzz-list
expect "fuzz-smoke: 2 target(s) compiled on"

plant zz_vet.go <<'EOF'
package nested

import "fmt"

// Vet holds the planted vet finding.
func Vet() string { return fmt.Sprintf("%d", "probe-vet") }
EOF
run fail vet planted
expect "zz_vet.go" "format %d has arg"
expect "vet: FAIL in module ${nested}"
rm "${copy}/${nested}/zz_vet.go"

plant zz_vet_windows.go <<'EOF'
package nested

import "fmt"

// VetWindows holds the planted vet finding only GOOS=windows compiles.
func VetWindows() string { return fmt.Sprintf("%d", "probe-vet-windows") }
EOF
run fail vet "planted, windows only"
expect "zz_vet_windows.go" "format %d has arg"
expect "vet: FAIL in module ${nested}"
rm "${copy}/${nested}/zz_vet_windows.go"

plant zz_fail_test.go <<'EOF'
package nested

import "testing"

func TestProbePlanted(t *testing.T) {
	t.Fatal("probe-test-planted")
}
EOF
run fail test planted
expect_start "--- FAIL: TestProbePlanted"
expect_start "    zz_fail_test.go:" "probe-test-planted"
expect_start "FAIL"$'\t'"example.com/nested"
expect "test: FAIL in module ${nested}"
rm "${copy}/${nested}/zz_fail_test.go"

plant zz_skip_test.go <<'EOF'
package nested

import "testing"

func TestProbeSkipped(t *testing.T) {
	t.Skip("probe-skip-planted")
}
EOF
run fail test "planted skip, not listed"
expect_start "test: SKIP example.com/nested TestProbeSkipped: " "probe-skip-planted"
expect "the expected skips do not name: example.com/nested TestProbeSkipped"
expect "test: FAIL in module ${nested}"
printf 'example.com/nested TestProbeSkipped probe-skip-planted\n' >>"${copy}/scripts/expected-skips.txt"
run pass test "planted skip, listed"
expect_start "test: SKIP example.com/nested TestProbeSkipped: " "probe-skip-planted"
expect_start "test: 1 skipped"
rm "${copy}/${nested}/zz_skip_test.go"
cp "${root}/scripts/expected-skips.txt" "${copy}/scripts/expected-skips.txt"

plant zz_race_test.go <<'EOF'
package nested

import "testing"

func TestProbeRace(t *testing.T) {
	n := 0
	done := make(chan struct{})
	go func() {
		n++
		close(done)
	}()
	n++
	<-done
	if n == 0 {
		t.Fatal("unreachable")
	}
}
EOF
run fail test-race planted
expect "WARNING: DATA RACE"
expect "test-race: FAIL in module ${nested}"
rm "${copy}/${nested}/zz_race_test.go"

plant zz_racemain_test.go <<'EOF'
//go:build race

package nested

import "testing"

func TestMain(m *testing.M) {}
EOF
run fail test-race "planted, a race-only TestMain that runs no test"
expect "a package ran no test" "example.com/nested"
expect "test-race: FAIL in module ${nested}"
rm "${copy:?}/${nested:?}/zz_racemain_test.go"

plant .golangci.yml <<'EOF'
version: "2"
linters:
  default: none
  enable:
    - misspell
EOF
plant zz_lint.go <<'EOF'
package nested

import "crypto/md5"

// Sum holds the planted gosec finding.
func Sum(b []byte) [16]byte { return md5.Sum(b) }
EOF
run fail lint planted
expect "zz_lint.go" "(gosec)"
expect "lint: FAIL in module ${nested}"
rm "${copy}/${nested}/zz_lint.go" "${copy}/${nested}/.golangci.yml"
write scripts/gen-lint.go <<'EOF'
//go:build ignore

// Command gen-lint holds the planted gosec finding of a program.
package main

import "crypto/md5"

func main() { _ = md5.Sum(nil) }
EOF
run fail lint "planted in a program under scripts/"
expect "gen-lint.go" "(gosec)"
expect "lint: FAIL in scripts/gen-lint.go"
rm "${copy}/scripts/gen-lint.go"

nested_gomod indirect
run fail tidy-check planted
expect "-require example.com/probe v0.0.0 // indirect"
expect "tidy-check: FAIL in module ${nested}"
nested_gomod

plant zz_fuzz_test.go <<'EOF'
package nested

import "testing"

func FuzzProbePlanted(f *testing.F) {
	f.Add(1)
	f.Fuzz(func(t *testing.T, _ int) {
		t.Fatal("probe-fuzz-planted")
	})
}
EOF
run fail fuzz-smoke planted
expect "probe-fuzz-planted"
expect "fuzz-smoke: FuzzProbePlanted failed" "./${nested}/testdata/fuzz/FuzzProbePlanted/"
rm -rf "${copy}/${nested}/zz_fuzz_test.go" "${copy}/${nested}/testdata/fuzz"

plant zz_fuzz_constrained_test.go <<'EOF'
//go:build ignore

package nested

import "testing"

func FuzzProbeConstrained(f *testing.F) {
	f.Add(1)
	f.Fuzz(func(t *testing.T, _ int) {})
}
EOF
run fail fuzz-smoke "planted, left out by a build constraint"
expect "fuzz-smoke: ./${nested} FuzzProbeConstrained is not compiled on"
expect "fuzz-smoke: 1 of 3 target(s) not compiled on"
run fail fuzz-list "planted, left out by a build constraint"
expect "fuzz-smoke: 1 of 3 target(s) not compiled on"
rm -f "${copy:?}/${nested:?}/zz_fuzz_constrained_test.go"

mkdir -p "${copy}/${nested}/hidden"
plant hidden/hidden_test.go <<'EOF'
package hidden

import "testing"

func /* a comment before the name */ FuzzProbeHidden(f *testing.F) {
	f.Add(1)
	f.Fuzz(func(t *testing.T, _ int) {
		t.Fatal("probe-fuzz-hidden")
	})
}
EOF
run fail fuzz-smoke "planted, a comment before the name"
expect "probe-fuzz-hidden"
expect "fuzz-smoke: FuzzProbeHidden failed" "./${nested}/hidden/testdata/fuzz/FuzzProbeHidden/"
rm -rf "${copy:?}/${nested:?}/hidden"

mkdir -p "${copy}/${nested}/unread"
plant unread/unread_test.go <<'EOF'
package unread

import "testing"

func FuzzProbeUnread(f *testing.F) {
	f.Add(1)
	f.Fuzz(func(t *testing.T, _ int) {})
}
EOF
chmod 000 "${copy}/${nested}/unread/unread_test.go"
if [[ -r "${copy}/${nested}/unread/unread_test.go" ]]; then
  printf 'check-modules-probe: SKIP fuzz-smoke over a test file it cannot read: this user reads a file of mode 000\n'
else
  run fail fuzz-smoke "planted, a test file it cannot read"
  expect "fuzz-smoke: cannot read ${nested}/unread/unread_test.go"
fi
chmod 0644 "${copy}/${nested}/unread/unread_test.go"
rm -rf "${copy:?}/${nested:?}/unread"

gate=(vet test test-race lint tidy-check fuzz-list fuzz-smoke)

mv "${copy}/go.mod" "${copy}/go.mod.aside"
for target in "${gate[@]}"; do
  run fail "${target}" "no root go.mod"
  expect "go_modules: no go.mod at the repository root"
done
mv "${copy}/go.mod.aside" "${copy}/go.mod"

globbed="examples/n[x]"
mkdir -p "${copy}/examples/nx" "${copy}/${globbed}"
write examples/nx/README.txt <<'EOF'
A directory the name examples/n[x] matches as a glob.
EOF
write "${globbed}/go.mod" <<EOF
module example.com/globbed

go ${goversion}
EOF
write "${globbed}/globbed.go" <<'EOF'
// Package globbed holds a vet finding the loop must not skip.
package globbed

import "fmt"

// Vet holds the planted vet finding.
func Vet() string { return fmt.Sprintf("%d", "probe-globbed") }
EOF
for target in "${gate[@]}"; do
  run fail "${target}" "module named with a glob"
  expect "go_modules: refusing module directory ${globbed}"
done
rm -rf "${copy:?}/${globbed}" "${copy}/examples/nx"

mkdir -p "${copy}/examples/upper"
write examples/upper/GO.MOD <<EOF
module example.com/upper

go ${goversion}
EOF
for target in "${gate[@]}"; do
  run fail "${target}" "GO.MOD"
  expect "go_modules: examples/upper/GO.MOD is a go.mod in another case"
done
rm -rf "${copy}/examples/upper"

# check_list <mode>
# The module list the helper prints, against the one the staged tree holds.
check_list() {
  local got want
  want=".
${nested}"
  expected=$((expected + 1))
  got="$(bash -c '. "$1/scripts/lib/go-modules.sh"; go_modules' _ "${copy}" 2>&1)" || got="exit $?: ${got}"
  if [[ "${got}" != "${want}" ]]; then
    printf 'check-modules-probe: go_modules in %s printed:\n%s\ninstead of:\n%s\n' "$1" "${got}" "${want}" >&2
    failures=$((failures + 1))
  fi
}
check_list "a git work tree"
rm -rf "${copy}/.git"
check_list "a tree with no .git"

if [[ ${failures} -ne 0 ]]; then
  printf 'check-modules-probe: %d failure(s) against %d expectation(s) over %d make run(s); a gate target skipped a module or passed over a defect\n' \
    "${failures}" "${expected}" "${runs}" >&2
  exit 1
fi
printf 'check-modules-probe: %d run(s) passed over two clean modules or a planted skip and %d refused a planted defect or tree, each for its reason; all %d expectation(s) held over %d make run(s)\n' \
  "${passes}" "${refusals}" "${expected}" "${runs}"
