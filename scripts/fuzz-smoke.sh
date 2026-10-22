#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Runs every fuzz target briefly, so a seed corpus that stops building is
# caught by the ordinary gate rather than by a long fuzzing session.
#
# Not read-only on failure: `go test -fuzz` writes the minimized failing input
# to <package>/testdata/fuzz/<FuzzName>/ inside the working tree, and the go
# command has no flag to send it elsewhere. This target is therefore the one
# step of `make quality` that can leave a new file behind. The failure message
# below names the directory so the file is not found later by surprise.
set -euo pipefail

_FUZZ_SMOKE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
# shellcheck source=lib/repo-files.sh
. "${_FUZZ_SMOKE_DIR}/lib/repo-files.sh"
# shellcheck source=lib/go-modules.sh
. "${_FUZZ_SMOKE_DIR}/lib/go-modules.sh"

# Assigned first: `cd "$(repo_root)"` would swallow a repo_root failure, because
# cd with an empty argument succeeds and stays put.
root="$(repo_root)"
cd "${root}"

# As in the Makefile: an untracked go.work must not change what is built.
export GOWORK=off

duration="${1:-10s}"

files="$(repo_files '*_test.go')"
listed="$(go_modules)"
if [[ -z "${listed}" ]]; then
  printf 'fuzz-smoke: no Go module listed; refusing to report a pass\n' >&2
  exit 1
fi
modules=()
while IFS= read -r dir; do
  modules+=("${dir}")
done <<<"${listed}"

# A package is searched when one of its test files holds "Fuzz" anywhere: a
# fuzz target's name starts with it, and a Go identifier is spelled out in the
# source, so no target escapes the search however its declaration is written.
# Each package is "<module directory> <package relative to it>": a package
# builds only from inside its own module, so each runs from the directory of
# the nearest go.mod above it. repo_files rejects paths with whitespace, so a
# space is a safe separator. Each declared entry adds the name a line-anchored
# search reads in the source.
packages=""
declared=()
while IFS= read -r file; do
  [[ -n "${file}" ]] || continue
  case "${file}" in
    api/gen/*|testdata/*|*/testdata/*) continue ;;
  esac
  # grep exits 1 for "no match" and 2 or more for "could not read"; folding the
  # two together would pass over a fuzz target nobody read.
  found=0
  grep -qF -- Fuzz "${file}" || found=$?
  case "${found}" in
    0) ;;
    1) continue ;;
    *)
      printf 'fuzz-smoke: cannot read %s (grep exit %d)\n' "${file}" "${found}" >&2
      exit 1
      ;;
  esac

  if [[ "${file}" == */* ]]; then
    filedir="${file%/*}"
  else
    filedir="."
  fi

  # The longest module directory that holds the file. "." holds every file.
  mod="."
  for dir in "${modules[@]}"; do
    if [[ "${dir}" != "." && ( "${filedir}" == "${dir}" || "${filedir}" == "${dir}/"* ) &&
      ${#dir} -gt ${#mod} ]]; then
      mod="${dir}"
    fi
  done
  if [[ "${mod}" == "." ]]; then
    rel="${filedir}"
  elif [[ "${filedir}" == "${mod}" ]]; then
    rel="."
  else
    rel="${filedir#"${mod}"/}"
  fi
  if [[ "${rel}" == "." ]]; then
    pkg="."
  else
    pkg="./${rel}"
  fi
  grep -Fxq -- "${mod} ${pkg}" <<<"${packages}" || packages+="${mod} ${pkg}"$'\n'

  names="$(sed -n 's/^func \(Fuzz[A-Za-z0-9_]*\)(.*/\1/p' "${file}")"
  while IFS= read -r name; do
    [[ -n "${name}" ]] || continue
    declared+=("${mod} ${pkg} ${name}")
  done <<<"${names}"
done <<<"${files}"

# shown_package <module directory> <package relative to it>
# The package as a path from the repository root.
shown_package() {
  if [[ "$1" == "." ]]; then
    printf '%s\n' "$2"
  elif [[ "$2" == "." ]]; then
    printf './%s\n' "$1"
  else
    printf './%s/%s\n' "$1" "${2#./}"
  fi
}

# The targets run are the ones each package's test binary lists on this
# platform, never the ones read from the source: a declaration that a
# line-anchored search misses would otherwise compile and never fuzz.
targets=()
compiled=""
while read -r mod pkg; do
  [[ -n "${mod}" ]] || continue
  if ! listing="$(go -C "${mod}" test "${pkg}" -list '^Fuzz')"; then
    printf 'fuzz-smoke: could not list the fuzz targets of %s\n%s\n' "$(shown_package "${mod}" "${pkg}")" "${listing}" >&2
    exit 1
  fi
  while IFS= read -r line; do
    case "${line}" in
      Fuzz*)
        targets+=("${mod} ${pkg} ${line}")
        compiled+="${mod} ${pkg} ${line}"$'\n'
        ;;
    esac
  done <<<"${listing}"
done <<<"${packages}"

# bash 3.2 raises "unbound variable" under `set -u` when "${targets[@]}" is
# expanded while empty, so return before the loop rather than inside it.
if [[ ${#targets[@]} -eq 0 ]]; then
  # A gate that reports a pass over none of its subject is what this project
  # calls a false green. This repository has fuzz targets, so finding none is
  # a regression in the gate, not an empty repository.
  printf 'fuzz-smoke: no fuzz targets found; this repository has them, so finding none means the search stopped working\n' >&2
  exit 1
fi

# The source search ignores build constraints, and go test passes a -fuzz
# pattern that matches no compiled target with a warning and exit status 0. So
# a target declared in the source and missing from the listing is refused, not
# left out quietly. Comparing with the compiled list does not depend on the
# wording of that warning.
platform="$(go env GOOS)/$(go env GOARCH)"
missing=0
for target in ${declared[@]+"${declared[@]}"}; do
  if ! grep -Fxq -- "${target}" <<<"${compiled}"; then
    read -r mod pkg name <<<"${target}"
    printf 'fuzz-smoke: %s %s is not compiled on %s, so it would not fuzz; a build constraint or a file name leaves it out\n' \
      "$(shown_package "${mod}" "${pkg}")" "${name}" "${platform}" >&2
    missing=$((missing + 1))
  fi
done
if [[ ${missing} -ne 0 ]]; then
  printf 'fuzz-smoke: %d of %d target(s) not compiled on %s; refusing to count them as run\n' "${missing}" "${#declared[@]}" "${platform}" >&2
  exit 1
fi

for target in "${targets[@]}"; do
  read -r mod pkg name <<<"${target}"
  shown="$(shown_package "${mod}" "${pkg}")"
  printf 'fuzz-smoke: %s %s for %s\n' "${shown}" "${name}" "${duration}"
  if ! go -C "${mod}" test "${pkg}" -run '^$' -fuzz "^${name}\$" -fuzztime "${duration}"; then
    printf 'fuzz-smoke: %s failed; the minimized input is now in the working tree at %s/testdata/fuzz/%s/ - keep it as a regression seed or delete it\n' \
      "${name}" "${shown}" "${name}" >&2
    exit 1
  fi
done

printf 'fuzz-smoke: %d module(s)\n' "${#modules[@]}"
printf 'fuzz-smoke: %d target(s) run for %s each\n' "${#targets[@]}" "${duration}"
