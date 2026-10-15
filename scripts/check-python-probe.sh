#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# The negative control of scripts/check-python.sh. It stages the script, its
# pins and the Python project in a scratch tree, plants one thing at a time
# that would make the target examine something other than the commit, and
# requires the script to stop where the case says:
#   lock      a workspace declared at the repository root or above it, a uv
#             configuration beside the project and a project file its lock
#             no longer matches: the first three are not obeyed, the last is
#             refused
#   stand-in  a symbolic link, bytecode, a stub, an extension module, a
#             dot-name below the top and a directory a checker skips by name
#   checks    a file an ignore file names or a directory name hides from the
#             linter, and a nearer or differently named configuration of the
#             linter, the formatter and the type checker
#   runner    a runner that exits 0 without its verdict as the last line
# A case that must get past the checks to the runner uses a stand-in runner
# that passes them and a stand-in go that writes two empty commands. Not
# controlled here: that a locked tool is never built from source, that Python
# runs isolated, and that nothing is written into the tree.
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
mkdir "${tmp}/standin" "${tmp}/elsewhere"
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

# stage: a fresh copy of what the script reads, without the dot-names and the
# bytecode a developer's own runs may have left in the work tree.
stage() {
  rm -rf "${tmp}/tree"
  mkdir -p "${tmp}/tree/scripts" "${tmp}/tree/clients"
  cp "${root}/scripts/check-python.sh" "${root}/scripts/build-python-dist.sh" \
    "${root}/scripts/tool-versions.env" "${tmp}/tree/scripts/"
  cp -R "${root}/scripts/lib" "${tmp}/tree/scripts/lib"
  cp -R "${root}/clients/python" "${tmp}/tree/clients/python"
  find "${tmp}/tree/clients/python" -mindepth 1 \( -name '.*' -o -name __pycache__ \) -prune \
    -exec rm -rf {} +
  tree="${tmp}/tree"
  project="${tree}/clients/python"
}

# plant <path in the project> [<content>]
plant() {
  mkdir -p "$(dirname "${project}/$1")"
  printf '%b' "${2-}" >"${project}/$1"
}

# runner <line>: a stand-in runner that passes the linter, the formatter and
# the type checker and writes <line>, {v} in it being the interpreter's own
# version. The tests of the real runner go, since they import its names.
runner() {
  rm -f "${project}/tests/test_gate.py"
  printf '"""Stands in for the runner."""\n\nimport platform\nimport sys\n\nLINE = "%s"\nsys.stdout.write(LINE.format(v=platform.python_version()))\n' \
    "$1" >"${project}/run_tests.py"
}

cases=0
failed=0
# stops <what the script must say> <name>: runs the staged script, which must
# exit 1 and say it.
stops() {
  local needle="$1" name="$2" out rc=0
  out="$(PATH="${tmp}/standin:${PATH}" /bin/bash "${tree}/scripts/check-python.sh" 2>&1)" || rc=$?
  cases=$((cases + 1))
  if [[ ${rc} -ne 1 ]]; then
    printf 'FAIL %s: wanted exit 1, got %d: %s\n' "${name}" "${rc}" "${out: -400}" >&2
    failed=$((failed + 1))
  elif [[ "${out}" != *"${needle}"* ]]; then
    printf 'FAIL %s: nothing said "%s": %s\n' "${name}" "${needle}" "${out: -400}" >&2
    failed=$((failed + 1))
  else
    printf 'ok   %s\n' "${name}"
  fi
}

silent="the runner's last line is not its verdict"
pass='5 tests, 0 skipped, every required test ran'

# The lock: each of the first three gets as far as the runner, which it would
# not if uv had obeyed what was planted, since no other lock exists.
stage
runner ""
printf '[tool.uv.workspace]\nmembers = ["clients/python"]\n' >"${tree}/pyproject.toml"
stops "${silent}" "a workspace at the repository root does not take the project's lock away"
stage
runner ""
printf '[tool.uv.workspace]\nmembers = ["tree/clients/python"]\n' >"${tmp}/pyproject.toml"
stops "${silent}" "a workspace above the repository does not either"
rm -f "${tmp}/pyproject.toml"
stage
runner ""
plant uv.toml 'required-version = "==0.0.1"\n'
stops "${silent}" "a uv configuration beside the project is not read"
stage
sed 's/^version = ".*"$/version = "9.9.9"/' "${root}/clients/python/pyproject.toml" >"${project}/pyproject.toml"
stops "the locked tools could not be installed" "a project file the lock does not match"

# What would stand in for a source, or hide from a check and still be imported.
stage
ln -s "${tmp}/elsewhere" "${project}/src/vendor"
stops "./src/vendor" "a symbolic link"
stage
plant src/socketserver.pyc
stops "./src/socketserver.pyc" "bytecode with no source beside it"
stage
plant tests/__pycache__/test_wire.cpython-314.pyc
stops "./tests/__pycache__/test_wire.cpython-314.pyc" "bytecode in a cache directory"
stage
plant tests/test_wire.pyi
stops "./tests/test_wire.pyi" "a stub beside a source"
stage
plant src/fast.abi3.so
stops "./src/fast.abi3.so" "an extension module"
stage
plant tests/.hidden/mod.py
stops "./tests/.hidden" "a dot-name below the top"
stage
plant src/node_modules/mod.py
stops "./src/node_modules" "a directory the type checker skips: node_modules"
stage
plant tests/site-packages/mod.py
stops "./tests/site-packages" "a directory the type checker skips: site-packages"

# The checks read every file, under the project file alone.
unused='"""Planted."""\n\nimport os\n'
stage
plant tests/planted.py "${unused}"
plant .ignore 'planted.py\n'
stops "ruff check found problems" "a file an ignore file names is linted"
stage
plant tests/dist/planted.py "${unused}"
stops "ruff check found problems" "a directory the linter skips by default is linted"
stage
plant tests/planted.py "${unused}"
plant .ruff.toml 'extend = "pyproject.toml"\n[lint]\nselect = ["E9"]\n'
stops "ruff check found problems" "a linter configuration of another name is not obeyed"
stage
plant tests/planted.py '"""Planted."""\n\nX = '"'a'"'\n'
plant .ruff.toml 'extend = "pyproject.toml"\n[format]\nexclude = ["planted.py"]\n'
stops "ruff format would change files" "a formatter configuration of another name is not obeyed"
stage
plant tests/planted.py '"""Planted."""\n\nBAD: int = "x"\n'
plant mypy.ini '[mypy]\nfiles = src, tests, run_tests.py, check_wheel.py\nmypy_path = src, .\nignore_errors = True\n'
stops "mypy found problems" "a type checker configuration of another name is not obeyed"

# The runner's verdict is its last line, whole, for the interpreter that ran.
stage
runner ""
stops "${silent}" "a runner that exits 0 and says nothing"
stage
runner "run_tests: python 0.0.0: ${pass}\\n"
stops "${silent}" "a runner with another interpreter's verdict"
stage
runner "run_tests: python {v}: 0 tests, 0 skipped, every required test ran\\n"
stops "${silent}" "a runner that claims no test and a pass"
stage
runner "run_tests: python {v}: 5 tests, 1 skipped, every required test ran\\n"
stops "${silent}" "a runner that reports a skip"
stage
runner "run_tests: python {v}: 5 tests, 0 skipped, 2 required test(s) did not run\\n"
stops "${silent}" "a runner whose line begins as a verdict and ends otherwise"
stage
runner "run_tests: python {v}: ${pass}\\nand more\\n"
stops "${silent}" "a runner that writes a line after its verdict"

[[ ${failed} -eq 0 ]] || die "${failed} of ${cases} cases did not go as named"
printf 'check-python-probe: %d cases, each stopped as named\n' "${cases}"
