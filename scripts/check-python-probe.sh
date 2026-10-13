#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# The negative control of scripts/check-python.sh. It stages the script, its
# pins and the Python project in a scratch tree, plants one thing at a time
# that would make the target examine something other than the commit, and
# each case must be refused and say why:
#   refused  a project file, a lock or a uv configuration above the project,
#            which would make uv read another lock; bytecode, a path file, a
#            start-up hook, a nested tool configuration, a second project
#            file or lock inside the project; a runner that exits 0 without
#            its verdict line, or with the verdict of another interpreter
# The two runner cases put a stand-in go first on PATH, which writes two
# empty commands, and install the locked tools as the target does.
set -euo pipefail

_PROBE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
# shellcheck source=lib/repo-files.sh
. "${_PROBE_DIR}/lib/repo-files.sh"

die() {
  printf 'check-python-probe: %s\n' "$*" >&2
  exit 1
}

root="$(repo_root)"
[[ -f "${root}/scripts/check-python.sh" && -d "${root}/clients/python" ]] ||
  die "the script or the project is missing"
command -v uv >/dev/null 2>&1 || die "uv is not on PATH; make bootstrap installs it"

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
mkdir "${tmp}/standin"
cat >"${tmp}/standin/go" <<'GO'
#!/usr/bin/env bash
# Stands in for `go build -o <dir>/ ./cmd/...`: two empty commands.
out=""
while [[ $# -gt 0 ]]; do
  if [[ "$1" == -o ]]; then
    out="$2"
  fi
  shift
done
[[ -n "${out}" ]] || exit 1
printf '#!/bin/sh\n' >"${out}one-gateway"
printf '#!/bin/sh\n' >"${out}one"
chmod +x "${out}one-gateway" "${out}one"
GO
chmod +x "${tmp}/standin/go"

# stage: a fresh copy of what the script reads, with no dot-directory and no
# bytecode a developer's own runs may have left in the work tree.
stage() {
  rm -rf "${tmp}/tree"
  mkdir -p "${tmp}/tree/scripts" "${tmp}/tree/clients"
  cp "${root}/scripts/check-python.sh" "${root}/scripts/tool-versions.env" "${tmp}/tree/scripts/"
  cp -R "${root}/scripts/lib" "${tmp}/tree/scripts/lib"
  cp -R "${root}/clients/python" "${tmp}/tree/clients/python"
  find "${tmp}/tree/clients/python" -mindepth 1 \( -name '.*' -o -name __pycache__ \) -prune \
    -exec rm -rf {} +
  tree="${tmp}/tree"
  project="${tree}/clients/python"
}

cases=0
failed=0
# refused <what the script must say> <name>: runs the staged script.
refused() {
  local needle="$1" name="$2" out rc=0
  out="$(PATH="${tmp}/standin:${PATH}" /bin/bash "${tree}/scripts/check-python.sh" 2>&1)" || rc=$?
  cases=$((cases + 1))
  if [[ ${rc} -ne 1 ]]; then
    printf 'FAIL %s: wanted a refusal, exit %d: %s\n' "${name}" "${rc}" "${out: -400}" >&2
    failed=$((failed + 1))
  elif [[ "${out}" != *"${needle}"* ]]; then
    printf 'FAIL %s: nothing said "%s": %s\n' "${name}" "${needle}" "${out: -400}" >&2
    failed=$((failed + 1))
  else
    printf 'ok   %s\n' "${name}"
  fi
}

for above in pyproject.toml uv.lock uv.toml clients/pyproject.toml clients/uv.lock clients/uv.toml; do
  stage
  printf '[tool.uv.workspace]\nmembers = ["python"]\n' >"${tree}/${above}"
  refused "${above} would stand in for" "${above} above the project"
done

plant() {
  stage
  mkdir -p "$(dirname "${project}/$1")"
  printf '%s\n' "${2-}" >"${project}/$1"
}
plant src/socketserver.pyc
refused "src/socketserver.pyc" "bytecode with no source beside it"
plant tests/__pycache__/test_wire.cpython-314.pyc
refused "tests/__pycache__" "a cache directory"
plant src/extra.pth "import os"
refused "src/extra.pth" "a path file"
plant sitecustomize.py "raise SystemExit(0)"
refused "sitecustomize.py" "a start-up hook"
plant src/ruff.toml "[lint]"
refused "src/ruff.toml" "a nested linter configuration"
plant tests/mypy.ini "[mypy]"
refused "tests/mypy.ini" "a nested type checker configuration"
plant tests/pyproject.toml "[project]"
refused "tests/pyproject.toml" "a second project file"
plant tests/uv.lock "version = 1"
refused "tests/uv.lock" "a second lock"

stage
printf 'raise SystemExit(0)\n' >"${project}/run_tests.py"
refused "the runner's last line is not its verdict" "a runner that exits 0 and says nothing"
stage
printf 'print("run_tests: python 0.0.0: 5 tests, 0 skipped, every required test ran")\n' \
  >"${project}/run_tests.py"
refused "the runner's last line is not its verdict" "a runner with another interpreter's verdict"
stage
printf 'import platform\nprint(f"run_tests: python {platform.python_version()}: 0 tests, 0 skipped, every required test ran")\n' \
  >"${project}/run_tests.py"
refused "the runner's last line is not its verdict" "a runner that claims no test and a pass"

[[ ${failed} -eq 0 ]] || die "${failed} of ${cases} cases did not go as named"
printf 'check-python-probe: %d cases, each refused as named\n' "${cases}"
