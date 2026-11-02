#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# The dependency rule, enforced independently of golangci-lint so that editing
# the lint config cannot quietly remove it. What the rule allows is written in
# lib/dependency-rule.sh.
#
# Every package of this module that a guarded tree reaches is examined, not
# only the tree's own packages; otherwise a helper package outside the guarded
# trees would be a way around the rule. A package outside the module is judged
# only as an import: the rule decides whether a guarded tree may use it at all.
# A package that is examined may also hold no file in the go list fields
# refused_files names, natively or as foreign_platform builds it. go list
# reports the build of one platform, so a file that only another platform
# compiles, or assembly that needs no import, would otherwise pass on every
# machine the gate runs on. No Go file of a guarded or reached tree, tests
# included, may carry a build constraint line either: that is read as text,
# because a constraint every listed platform satisfies leaves nothing out of a
# listing.
# And every Go file of a guarded tree must be one go list names, natively and
# for foreign_platform: a package whose only files a name suffix keeps to
# another platform is in no listing at all, and neither are its imports.
# Under adapters/, no non-test Go file, whatever its build constraints, may
# import a tree adapter_denied names; depguard's adapters rule holds the same
# list over the files it loads.
#
# This script and depguard (.golangci.yml) each cover a half the other misses:
#   - here: the in-module packages the non-test build reaches, which depguard
#     does not see because it reads only each guarded file's own imports, the
#     files of those packages that are not plain Go built on every platform,
#     the build constraint lines of the guarded and reached trees' Go files,
#     and the listings of the guarded trees' Go files;
#   - depguard: imports written in _test.go files, which `go list -deps`
#     leaves out of the package's dependency set.
set -euo pipefail

# The source= paths below resolve against this script's directory through the
# source-path directive on line 2. Placed anywhere after the first command, that
# directive covers one command only, and shellcheck -x stops following them.
_CHECK_IMPORTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
# shellcheck source=lib/repo-files.sh
. "${_CHECK_IMPORTS_DIR}/lib/repo-files.sh"
# shellcheck source=lib/dependency-rule.sh
. "${_CHECK_IMPORTS_DIR}/lib/dependency-rule.sh"

# Assigned first: `cd "$(repo_root)"` would swallow a repo_root failure, because
# cd with an empty argument succeeds and stays put.
root="$(repo_root)"
cd "${root}"

# Read, never hard-coded: renaming the module must not require touching this
# file. GOWORK=off because inside a go.work workspace `go list -m` prints one
# line per module, and a multi-line value here would turn every in-module path
# built from it into a string no package path can ever equal.
module="$(GOWORK=off go list -m)"
if [[ -z "${module}" || "${module}" == *[[:space:]]* ]]; then
  printf 'check-imports: go list -m did not return exactly one module path: %q\n' \
    "${module}" >&2
  exit 1
fi

# under <path> <prefix>
# True when path is prefix itself or a package below it. Whole segments, so
# net/httptest is not under net/http.
under() {
  [[ "$1" == "$2" || "$1" == "$2/"* ]]
}

# judge <import path>
# Sets `why` to the reason a guarded tree may not import the path, or to the
# empty string when it may. A variable rather than output, because this runs
# once per import and a command substitution would fork each time.
judge() {
  local imp="$1" entry
  why=""
  if under "${imp}" "${module}"; then
    for entry in "${denied[@]}"; do
      if under "${imp}" "${module}/${entry}"; then
        why="a tree the dependency rule denies"
        return 0
      fi
    done
    return 0
  fi
  for entry in "${modules[@]}"; do
    if under "${imp}" "${entry}"; then
      return 0
    fi
  done
  for entry in "${stdlib[@]}"; do
    if [[ "${imp}" == "${entry}" ]]; then
      return 0
    fi
  done
  why="which the dependency rule does not allow"
}

# file_reason <go list field>
# Sets `why` to the reason a package held to the rule may not hold a file that
# go list reports in the field. Only the fields refused_files names reach here.
file_reason() {
  case "$1" in
    IgnoredGoFiles | IgnoredOtherFiles) why="which build constraints leave out on this platform" ;;
    *) why="which is not plain Go ($1)" ;;
  esac
}

# in_name_scope <package>
# True when the package lies under a guarded or a reached tree, where
# .golangci.yml refuses clock, input and randomness reads by name.
in_name_scope() {
  local entry
  for entry in "${guarded[@]}" "${reached[@]}"; do
    if under "$1" "${module}/${entry}"; then
      return 0
    fi
  done
  return 1
}
outside_scope="is reached by a guarded tree and lies outside every tree in which the rule refuses clock, input and randomness reads by name"

# held <package>
# True when the package's own imports and files are held to the rule: it is in
# this module and not generated.
held() {
  local entry
  under "$1" "${module}" || return 1
  for entry in "${generated[@]}"; do
    if under "$1" "${module}/${entry}"; then
      return 1
    fi
  done
  return 0
}

# One line per package the non-test build reaches: its path, its direct
# imports, a lone "|", then each file it holds in a field refused_files names,
# written <field>:<file>. See the note at the top of the file for what depguard
# covers.
template='{{.ImportPath}}{{range .Imports}} {{.}}{{end}} |'
for field in "${refused_files[@]}"; do
  template+="{{range .${field}}} ${field}:{{.}}{{end}}"
done

foreign="${foreign_platform[0]}/${foreign_platform[1]}"
foreign_template='{{.ImportPath}}{{range .IgnoredGoFiles}} {{.}}{{end}}{{range .IgnoredOtherFiles}} {{.}}{{end}}'

# A line go/build would read as a build constraint: after an optional byte order
# mark and leading space, "//go:build", or "//" and "+build" with any space
# between. It is refused wherever it stands in the file, since a block comment
# can hide where the header go/build reads ends. internal/core/layering_test.go
# matches the same lines.
constraint_line="^($(printf '\357\273\277'))?[[:space:]]*//(go:build|[[:space:]]*[+]build)"
constrained="holds a build constraint, so it may not build from the same files on every platform"

# Every Go file of a package, the files it leaves out included, so that a file
# no field names is one go list never reached.
named_template='{{.ImportPath}}{{range .GoFiles}} {{.}}{{end}}{{range .CgoFiles}} {{.}}{{end}}{{range .TestGoFiles}} {{.}}{{end}}{{range .XTestGoFiles}} {{.}}{{end}}{{range .IgnoredGoFiles}} {{.}}{{end}}'

# refuse_unnamed <named_template listing> <platform>
# Adds a refusal for each file in `files` that the listing does not name. A
# file a listing leaves out is refused by the file checks; one it does not name
# is in a package no listing holds, or a file or directory go ignores.
refuse_unnamed() {
  local names=$'\n' file i
  local -a fields
  while read -r -a fields; do
    [[ ${#fields[@]} -gt 0 && "${fields[0]}" == "${module}/"* ]] || continue
    for ((i = 1; i < ${#fields[@]}; i++)); do
      names+="${fields[0]#"${module}/"}/${fields[i]}"$'\n'
    done
  done <<<"$1"
  for file in "${files[@]}"; do
    if [[ "${names}" != *$'\n'"${file}"$'\n'* ]]; then
      refusals+="FAIL ${file} is named by no go list listing on $2, so the rule never examines it"$'\n'
    fi
  done
}

# examine_sources <tree> <guarded or reached>
# Refuses each Go file of the tree outside testdata, tests included, that holds
# a build constraint line; in a guarded tree also each that a listing, native or
# foreign_platform, does not name: a reached package that no listing names
# makes go list -deps fail instead. Returns 1, the failure counted, when the
# tree is missing or holds no Go file.
examine_sources() {
  local dir="$1" kind="$2" pattern="./$1/..." gofiles matched rc file listing

  # Statted first, so the failure names the tree instead of git warning on
  # stderr about a directory it cannot walk for untracked files.
  if [[ ! -d "${dir}" ]]; then
    printf 'FAIL %s: the %s tree does not exist\n' "${pattern}" "${kind}" >&2
    failures=$((failures + 1))
    return 1
  fi

  # Tested in an if: a caller testing this function's status turns errexit off
  # inside it, so a failing repo_files would otherwise read as an empty tree.
  if ! gofiles="$(repo_files "${dir}/*.go")"; then
    printf 'FAIL %s: the Go files of the %s tree could not be listed\n' "${pattern}" "${kind}" >&2
    failures=$((failures + 1))
    return 1
  fi
  if [[ -z "${gofiles}" ]]; then
    printf 'FAIL %s: the %s tree holds no Go file\n' "${pattern}" "${kind}" >&2
    failures=$((failures + 1))
    return 1
  fi

  # Every Go file outside testdata, whether or not a listing names it: go list
  # drops a directory whose every file a constraint leaves out.
  files=()
  while read -r file; do
    if [[ "${file}" != */testdata/* ]]; then
      files+=("${file}")
    fi
  done <<<"${gofiles}"
  if [[ ${#files[@]} -eq 0 ]]; then
    printf 'FAIL %s: the %s tree holds no Go file outside testdata\n' "${pattern}" "${kind}" >&2
    failures=$((failures + 1))
    return 0
  fi
  sources=$((sources + ${#files[@]}))

  # grep exits 1 when no line matches and 2 when it could not read a file,
  # which is a failure, never a clean tree.
  rc=0
  matched="$(LC_ALL=C grep -lE -- "${constraint_line}" "${files[@]}")" || rc=$?
  if [[ ${rc} -gt 1 ]]; then
    printf 'FAIL %s: grep could not read the Go files for build constraints\n' "${pattern}" >&2
    failures=$((failures + 1))
  fi
  while read -r file; do
    if [[ -n "${file}" ]]; then
      refusals+="FAIL ${file} ${constrained}"$'\n'
    fi
  done <<<"${matched}"

  [[ "${kind}" == guarded ]] || return 0
  listed=$((listed + ${#files[@]}))

  # A pattern that matches no package prints a warning and exits 0; every
  # file is then unnamed and refused.
  if listing="$(go list -f "${named_template}" "${pattern}")"; then
    refuse_unnamed "${listing}" "this platform"
  else
    printf 'FAIL %s: go list failed\n' "${pattern}" >&2
    failures=$((failures + 1))
  fi
  if listing="$(GOOS="${foreign_platform[0]}" GOARCH="${foreign_platform[1]}" go list -f "${named_template}" "${pattern}")"; then
    refuse_unnamed "${listing}" "${foreign}"
  else
    printf 'FAIL %s: go list for %s failed\n' "${pattern}" "${foreign}" >&2
    failures=$((failures + 1))
  fi
}

checked=0
sources=0
listed=0
failures=0
packages=""
imports=""
refusals=""

for tree in "${reached[@]}"; do
  examine_sources "${tree}" reached || true
done

# Every guarded tree exists and holds packages. One that does not resolve is
# a failure, never a skip: a tree renamed or moved out from under its name
# would otherwise leave the rule with nothing to examine there and exit 0.
for dir in "${guarded[@]}"; do
  pattern="./${dir}/..."
  if ! examine_sources "${dir}" guarded; then
    continue
  fi

  if ! listing="$(go list -deps -f "${template}" "${pattern}")"; then
    printf 'FAIL %s: go list -deps failed\n' "${pattern}" >&2
    failures=$((failures + 1))
    continue
  fi
  if [[ -z "${listing}" ]]; then
    printf 'FAIL %s: go list -deps named no package\n' "${pattern}" >&2
    failures=$((failures + 1))
    continue
  fi
  checked=$((checked + 1))

  while read -r -a fields; do
    [[ ${#fields[@]} -gt 0 ]] || continue
    pkg="${fields[0]}"
    held "${pkg}" || continue
    packages+="${pkg}"$'\n'
    if ! in_name_scope "${pkg}"; then
      refusals+="FAIL ${pkg} ${outside_scope}"$'\n'
    fi
    in_files=0
    for ((i = 1; i < ${#fields[@]}; i++)); do
      token="${fields[i]}"
      if [[ ${in_files} -eq 1 ]]; then
        file_reason "${token%%:*}"
        refusals+="FAIL ${pkg} holds ${token#*:}, ${why}"$'\n'
      elif [[ "${token}" == "|" ]]; then
        in_files=1
      else
        imports+="${pkg} ${token}"$'\n'
        judge "${token}"
        if [[ -n "${why}" ]]; then
          refusals+="FAIL ${pkg} imports ${token}, ${why}"$'\n'
        fi
      fi
    done
    # A line that never reached the "|" means the template no longer lists the
    # files, and every file this script refuses would pass unexamined.
    if [[ ${in_files} -eq 0 ]]; then
      printf 'FAIL %s: go list printed no "|" before the files; the template no longer lists them\n' "${pkg}" >&2
      failures=$((failures + 1))
    fi
  done <<<"${listing}"

  # The same packages as the foreign platform builds them, for the files its
  # name suffixes leave out: those are the files this platform alone compiles.
  # A pattern that matches no package there prints a warning and exits 0.
  if ! listing="$(GOOS="${foreign_platform[0]}" GOARCH="${foreign_platform[1]}" go list -deps -f "${foreign_template}" "${pattern}")"; then
    printf 'FAIL %s: go list -deps for %s failed\n' "${pattern}" "${foreign}" >&2
    failures=$((failures + 1))
    continue
  fi
  if [[ -z "${listing}" ]]; then
    printf 'FAIL %s: go list -deps for %s named no package\n' "${pattern}" "${foreign}" >&2
    failures=$((failures + 1))
    continue
  fi
  while read -r -a fields; do
    [[ ${#fields[@]} -gt 0 ]] || continue
    held "${fields[0]}" || continue
    for ((i = 1; i < ${#fields[@]}; i++)); do
      refusals+="FAIL ${fields[0]} holds ${fields[i]}, which build constraints leave out on ${foreign}"$'\n'
    done
  done <<<"${listing}"
done

# Every non-test Go file under adapters/, read as text whatever its build
# constraints: a file no listing on the gate's machines builds still compiles
# for another platform. An import path stands quoted, by " or `, so a path of
# adapter_denied, or a package below it, between quotes is refused.
adapter_files=0
if ! adapter_list="$(repo_files 'adapters/*.go')"; then
  printf 'FAIL adapters/: the Go files could not be listed\n' >&2
  failures=$((failures + 1))
fi
while read -r file; do
  [[ -n "${file}" && "${file}" != *_test.go && "${file}" != */testdata/* ]] || continue
  adapter_files=$((adapter_files + 1))
  for entry in "${adapter_denied[@]}"; do
    rc=0
    LC_ALL=C grep -qE -- "[\"\`]${module//./\\.}/${entry//./\\.}[\"\`/]" "${file}" || rc=$?
    case "${rc}" in
      0) refusals+="FAIL ${file} imports ${module}/${entry}, which no adapter may import"$'\n' ;;
      1) ;;
      *)
        printf 'FAIL %s: grep could not read it\n' "${file}" >&2
        failures=$((failures + 1))
        ;;
    esac
  done
done <<<"${adapter_list:-}"
if [[ ${adapter_files} -eq 0 ]]; then
  printf 'FAIL adapters/: no production Go file, so the adapter rule examined nothing\n' >&2
  failures=$((failures + 1))
fi

# A reached tree no guarded tree reaches any more is a stale entry, which would
# keep the name refusals on a tree for no reason anyone can check.
if [[ ${checked} -eq ${#guarded[@]} ]]; then
  for tree in "${reached[@]}"; do
    if [[ $'\n'"${packages}" != *$'\n'"${module}/${tree}"$'\n'* && $'\n'"${packages}" != *$'\n'"${module}/${tree}/"* ]]; then
      refusals+="FAIL ${tree} is a reached tree that no guarded tree reaches"$'\n'
    fi
  done
fi

# Two trees can reach the same package; each package and each refusal counts
# once.
count() {
  printf '%s' "$1" | LC_ALL=C sort -u | grep -c . || true
}
npackages="$(count "${packages}")"
nimports="$(count "${imports}")"
nrefusals="$(count "${refusals}")"
if [[ ${nrefusals} -gt 0 ]]; then
  printf '%s' "${refusals}" | LC_ALL=C sort -u >&2
fi

printf 'check-imports: %d of %d tree(s) checked; %d package(s) of this module and %d import(s) examined; %d Go file(s) read for build constraints and %d of them sought in both listings; %d adapter file(s) read; %d violation(s)\n' \
  "${checked}" "${#guarded[@]}" "${npackages}" "${nimports}" "${sources}" "${listed}" "${adapter_files}" "$((nrefusals + failures))"

# A run that examined nothing reports that, never a pass.
if [[ ${checked} -eq 0 ]]; then
  printf 'check-imports: no guarded tree resolved to a package; the rule examined nothing\n' >&2
  exit 1
fi
if [[ ${nimports} -eq 0 ]]; then
  printf 'check-imports: %d package(s) listed and not one import among them; the go list template no longer yields imports\n' \
    "${npackages}" >&2
  exit 1
fi
if [[ $((nrefusals + failures)) -ne 0 ]]; then
  exit 1
fi
