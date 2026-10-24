#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Size budget for hand-written Go, Python and shell. Above 350 non-blank lines
# warns, above 500 fails. A Go test file is exempt; a Python or shell file is
# judged whole, tests included. Generated code is exempt only where something
# holds it equal to its generator's output: under api/gen/, which proto-check
# compares, and at the one Python path named below; a generated-looking name
# anywhere else proves nothing.
set -euo pipefail

_CHECK_SIZES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
# shellcheck source=lib/repo-files.sh
. "${_CHECK_SIZES_DIR}/lib/repo-files.sh"

# Assigned first: `cd "$(repo_root)"` would swallow a repo_root failure, because
# cd with an empty argument succeeds and stays put.
root="$(repo_root)"
cd "${root}"

readonly WARN_LIMIT=350
readonly FAIL_LIMIT=500

# Captured before the loop so a failing enumeration aborts here instead of
# leaving the loop with nothing to read and a clean exit.
files="$(repo_files '*.go' '*.py' '*.sh')"

go_checked=0
python_checked=0
shell_checked=0
warnings=0
failures=0

while IFS= read -r file; do
  [[ -n "${file}" ]] || continue
  case "${file}" in
    api/gen/*|testdata/*|*/testdata/*|*_test.go) continue ;;
    # Written by scripts/gen-pyschema.go; internal/docscheck fails when it differs.
    clients/python/src/guardana_control/enforce/_schema.py) continue ;;
  esac

  case "${file}" in
    *.go) go_checked=$((go_checked + 1)) ;;
    *.py) python_checked=$((python_checked + 1)) ;;
    *.sh) shell_checked=$((shell_checked + 1)) ;;
    *)
      printf 'check-sizes: %s is listed but is neither Go, Python nor shell\n' "${file}" >&2
      exit 1
      ;;
  esac

  lines="$(awk 'NF { n++ } END { print n + 0 }' "${file}")"

  if (( lines > FAIL_LIMIT )); then
    printf 'FAIL %s: %d lines (limit %d)\n' "${file}" "${lines}" "${FAIL_LIMIT}" >&2
    failures=$((failures + 1))
  elif (( lines > WARN_LIMIT )); then
    printf 'warn %s: %d lines\n' "${file}" "${lines}"
    warnings=$((warnings + 1))
  fi
done <<<"${files}"

checked=$((go_checked + python_checked + shell_checked))
printf 'check-sizes: %d file(s) checked (%d Go, %d Python, %d shell), %d warning(s), %d failure(s)\n' \
  "${checked}" "${go_checked}" "${python_checked}" "${shell_checked}" "${warnings}" "${failures}"

# A kind that examined nothing is a broken enumeration, not a clean tree. The
# repository always holds hand-written Go outside api/gen/ and _test.go files,
# the Python client and the gate's own scripts.
for kind in Go:${go_checked} Python:${python_checked} shell:${shell_checked}; do
  if (( ${kind#*:} == 0 )); then
    printf 'check-sizes: no %s source found; refusing to report a pass\n' "${kind%%:*}" >&2
    exit 1
  fi
done

if (( failures > 0 )); then
  exit 1
fi
