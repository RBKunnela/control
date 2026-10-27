#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Runs the Python client's checks for make quality: its tests on the two
# pinned interpreters, the linter, the formatter and the type checker on the
# newer one, and a build of the wheel that is then inspected and imported on
# the older. The hook profile's qualification harness, standard library only,
# gets the same linter, formatter and type checker from the client's locked
# tools, under its own project file, and its tests on both interpreters.
#
# uv and Python run in an emptied environment with uv's configuration off,
# managed interpreters only, the lock enforced and no interpreter download, so
# the caller's environment, a user's uv.toml or a system Python cannot change
# what is examined. A missing uv, interpreter or locked tool fails; nothing is
# skipped. Virtual environments, bytecode and built files go to a scratch
# directory (uv's download cache stays in the user's home): nothing is written
# into the tree.
#
# What is examined is what the commit holds. The project file declares the
# project its own workspace root, so no project file above it names another
# lock; the linter and the type checker are given that file as their only
# configuration, and it tells the linter to obey no ignore file; and what
# would be loaded in place of a source, or skipped by a checker and still
# imported, is refused. scripts/check-python-probe.sh plants each.
#
#   scripts/check-python.sh
set -euo pipefail

_CHECK_PYTHON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
# shellcheck source=lib/repo-files.sh
. "${_CHECK_PYTHON_DIR}/lib/repo-files.sh"
# shellcheck source=tool-versions.env
. "${_CHECK_PYTHON_DIR}/tool-versions.env"
# shellcheck source=lib/python-env.sh
. "${_CHECK_PYTHON_DIR}/lib/python-env.sh"

die() {
  printf 'check-python: %s\n' "$*" >&2
  exit 1
}

root="$(repo_root)"
project="${root}/clients/python"
[[ -f "${project}/pyproject.toml" && -f "${project}/uv.lock" ]] || die "${project} holds no project and lock"
# The one built-in hook profile with a qualification harness; a second one
# is refused until this script loops over them.
set -- "${root}"/internal/hookbridge/profiles/*/qualification
[[ $# -eq 1 && -d "$1" ]] || die "want one qualification harness in internal/hookbridge/profiles, found: $*"
harness="$1"
harness_dir="${harness#"${root}/"}"
[[ -f "${harness}/pyproject.toml" && -f "${harness}/run_tests.py" ]] || die "${harness} holds no project file and runner"
# The harness's scripts without a .py suffix; the project file names them to
# the linter, and each is a type checker's run of its own.
harness_scripts=(record-hook stub-runtime controls/report-proposed)
for key in UV_VERSION CLIENT_PYTHON_FLOOR_VERSION CLIENT_PYTHON_VERSION; do
  [[ -n "${!key-}" ]] || die "${key} is empty or missing in tool-versions.env"
done
floor="${CLIENT_PYTHON_FLOOR_VERSION}"
newer="${CLIENT_PYTHON_VERSION}"
[[ "${floor}" != "${newer}" ]] || die "the two interpreter pins are one version: ${floor}"

# Inside the project nothing may stand in for a source or hide from a check:
# a symbolic link, bytecode (Python runs it with no source beside it), a stub
# (the type checker reads it in place of the source), an extension module
# (loaded before the source), and a directory the checkers skip by its name
# while Python imports from it. Dot-names at the top are a developer's own
# environment and caches, which no check reads.
for dir in "${project}" "${harness}"; do
  strays="$(cd "${dir}" && find . -mindepth 1 -path './.*' -prune -o \( \
    -name '.*' -o -type l -o -name '*.pyc' -o -name '*.pyi' -o -name '*.so' \
    -o -type d \( -name node_modules -o -name site-packages \) \
    \) -print)" || die "listing ${dir} failed"
  [[ -z "${strays}" ]] ||
    die "${dir#"${root}/"} holds what would stand in for a source or hide from a check; remove: ${strays//$'\n'/ }"
done

command -v go >/dev/null 2>&1 || die "go is not on PATH"
python_uv_pinned || die "uv is not the pinned one"

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
mkdir "${work}/bin"
# Whatever under the project is newer than this at the end was written by a check.
: >"${work}/before"

# The plane the end-to-end test drives, built from this tree.
(cd "${root}" && go build -o "${work}/bin/" ./cmd/...) || die "building the commands failed"

python_env "${work}" || die "no scratch directory for bytecode"

for version in "${floor}" "${newer}"; do
  venv="${work}/venv-${version}"
  # --no-build: a locked tool comes as a wheel or not at all, since building
  # one would run a build backend nothing here pins.
  "${clean[@]}" "UV_PROJECT_ENVIRONMENT=${venv}" uv sync --quiet --project "${project}" \
    --python "${version}" --locked --no-build --no-install-project --group dev ||
    die "python ${version}: the locked tools could not be installed; is the interpreter there (make bootstrap)?"
  ran="$("${clean[@]}" "${venv}/bin/python" "${isolated[@]}" -c 'import platform; print(platform.python_version())')" ||
    die "python ${version}: the interpreter does not run"
  [[ "${ran}" == "${version}" ]] || die "python ${version}: the environment runs ${ran}"
done

# Each tool is given the project file by name, which is then its only
# configuration: found by itself, it would obey one nearer a file or one of
# another name beside it.
venv="${work}/venv-${newer}"
(cd "${project}" && "${clean[@]}" "${venv}/bin/ruff" check --no-cache --config pyproject.toml .) ||
  die "ruff check found problems"
(cd "${project}" && "${clean[@]}" "${venv}/bin/ruff" format --check --no-cache --config pyproject.toml .) ||
  die "ruff format would change files"
(cd "${project}" && "${clean[@]}" "${venv}/bin/mypy" --cache-dir=/dev/null --config-file pyproject.toml) ||
  die "mypy found problems"
(cd "${harness}" && "${clean[@]}" "${venv}/bin/ruff" check --no-cache --config pyproject.toml .) ||
  die "ruff check found problems in the harness"
(cd "${harness}" && "${clean[@]}" "${venv}/bin/ruff" format --check --no-cache --config pyproject.toml .) ||
  die "ruff format would change files of the harness"
for target in "" "${harness_scripts[@]}"; do
  (cd "${harness}" && "${clean[@]}" "${venv}/bin/mypy" --cache-dir=/dev/null --config-file pyproject.toml ${target:+"${target}"}) ||
    die "mypy found problems in the harness${target:+ (${target})}"
done

for version in "${floor}" "${newer}"; do
  log="${work}/tests-${version}.log"
  "${clean[@]}" "${work}/venv-${version}/bin/python" "${isolated[@]}" "${project}/run_tests.py" \
    --bin "${work}/bin" 2>&1 | tee "${log}" || die "python ${version}: the tests failed"
  # An exit status of 0 is what a run that left early also has; the verdict
  # is the runner's last line.
  last="$(tail -n 1 "${log}")"
  verdict="^run_tests: python ${version//./\\.}: [1-9][0-9]* tests, 0 skipped, every required test ran\$"
  [[ "${last}" =~ ${verdict} ]] || die "python ${version}: the runner's last line is not its verdict: ${last}"
done

for version in "${floor}" "${newer}"; do
  log="${work}/harness-${version}.log"
  "${clean[@]}" "${work}/venv-${version}/bin/python" "${isolated[@]}" "${harness}/run_tests.py" 2>&1 |
    tee "${log}" || die "python ${version}: the harness's tests failed"
  last="$(tail -n 1 "${log}")"
  verdict="^harness_tests: python ${version//./\\.}: [1-9][0-9]* tests, 0 skipped, every required test ran\$"
  [[ "${last}" =~ ${verdict} ]] || die "python ${version}: the harness runner's last line is not its verdict: ${last}"
done

"${root}/scripts/build-python-dist.sh" "${work}/dist" || die "the client's release files do not build as they must"

written="$(cd "${root}" && find clients/python "${harness_dir}" -newer "${work}/before" -print)" ||
  die "listing the project failed"
[[ -z "${written}" ]] || die "something was written into the tree during the checks: ${written//$'\n'/ }"
[[ -z "$(ls -A "${work}/pycache")" ]] || die "bytecode was written although none should be"

printf 'check-python: green on python %s and %s\n' "${floor}" "${newer}"
