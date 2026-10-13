#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Runs the Python client's checks for make quality: its tests on the two
# pinned interpreters, the linter, the formatter and the type checker on the
# newer one, and a build of the wheel that is then inspected and imported on
# the older.
#
# uv and Python run in an emptied environment with uv's configuration off,
# managed interpreters only, the lock enforced and no interpreter download, so
# the caller's environment, a user's uv.toml or a system Python cannot change
# what is examined. A missing uv, interpreter or locked tool fails; nothing is
# skipped. Virtual environments, bytecode and built files go to a scratch
# directory (uv's download cache stays in the user's home): nothing is written
# into the tree. A project file or a lock above the project, a nested tool
# configuration and any bytecode in the project are refused, since uv, the
# linter or Python would obey or run them in place of what the commit holds.
#
#   scripts/check-python.sh
set -euo pipefail

_CHECK_PYTHON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
# shellcheck source=lib/repo-files.sh
. "${_CHECK_PYTHON_DIR}/lib/repo-files.sh"
# shellcheck source=tool-versions.env
. "${_CHECK_PYTHON_DIR}/tool-versions.env"

die() {
  printf 'check-python: %s\n' "$*" >&2
  exit 1
}

root="$(repo_root)"
project="${root}/clients/python"
[[ -f "${project}/pyproject.toml" && -f "${project}/uv.lock" ]] || die "${project} holds no project and lock"
for key in UV_VERSION CLIENT_PYTHON_FLOOR_VERSION CLIENT_PYTHON_VERSION; do
  [[ -n "${!key-}" ]] || die "${key} is empty or missing in tool-versions.env"
done
floor="${CLIENT_PYTHON_FLOOR_VERSION}"
newer="${CLIENT_PYTHON_VERSION}"
[[ "${floor}" != "${newer}" ]] || die "the two interpreter pins are one version: ${floor}"

# A project file, a lock or a uv configuration above the project makes it a
# member of that workspace, whose lock uv then reads in place of the one
# beside the project.
for above in pyproject.toml uv.lock uv.toml clients/pyproject.toml clients/uv.lock clients/uv.toml; do
  [[ ! -e "${root}/${above}" && ! -L "${root}/${above}" ]] ||
    die "${above} would stand in for the client's own project file and lock; remove it"
done
# Inside the project, outside its dot-directories, nothing may reconfigure a
# tool or stand in for a source: Python runs bytecode that has no source
# beside it, and loads a path file or a start-up hook it finds.
strays="$(cd "${project}" && find . -mindepth 1 -name '.*' -prune -o \( \
  -name __pycache__ -o -name '*.pyc' -o -name '*.pyo' -o -name '*.pth' \
  -o -name sitecustomize.py -o -name usercustomize.py \
  -o -name ruff.toml -o -name mypy.ini -o -name setup.cfg -o -name tox.ini -o -name uv.toml \
  -o \( -name pyproject.toml ! -path ./pyproject.toml \) -o \( -name uv.lock ! -path ./uv.lock \) \
  \) -print)" || die "listing ${project} failed"
[[ -z "${strays}" ]] ||
  die "clients/python holds what a check would obey or run in place of the sources; remove: ${strays//$'\n'/ }"

command -v go >/dev/null 2>&1 || die "go is not on PATH"
command -v uv >/dev/null 2>&1 || die "uv is not on PATH; make bootstrap installs it"
have="$(uv --version 2>&1)" || die "uv --version exited non-zero"
[[ "${have}" =~ ^uv\ ([0-9]+\.[0-9]+\.[0-9]+) ]] || die "no version in the output of uv --version: ${have}"
[[ "${BASH_REMATCH[1]}" == "${UV_VERSION#v}" ]] || die "uv: want ${UV_VERSION#v}, have ${BASH_REMATCH[1]}"

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
mkdir "${work}/bin" "${work}/dist"
# Whatever under the project is newer than this at the end was written by a check.
: >"${work}/before"

# The plane the end-to-end test drives, built from this tree.
(cd "${root}" && go build -o "${work}/bin/" ./cmd/...) || die "building the commands failed"

clean=(env -i)
for v in HOME PATH TMPDIR USER LOGNAME \
  HTTP_PROXY HTTPS_PROXY NO_PROXY http_proxy https_proxy no_proxy SSL_CERT_FILE SSL_CERT_DIR; do
  if [[ -n "${!v+x}" ]]; then
    clean+=("${v}=${!v}")
  fi
done
clean+=(UV_NO_CONFIG=1 UV_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never UV_NO_PROGRESS=1
  PYTHONDONTWRITEBYTECODE=1)
# Isolated, writing no bytecode, and looking for bytecode in an empty scratch
# directory instead of beside the sources: a stale or planted __pycache__ in
# the tree would otherwise run in place of the file the commit holds.
mkdir "${work}/pycache"
isolated=(-I -B -X "pycache_prefix=${work}/pycache")

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
  log="${work}/tests-${version}.log"
  "${clean[@]}" "${venv}/bin/python" "${isolated[@]}" "${project}/run_tests.py" --bin "${work}/bin" 2>&1 |
    tee "${log}" || die "python ${version}: the tests failed"
  # An exit status of 0 is what a run that left early also has; the verdict
  # is the runner's last line.
  last="$(tail -n 1 "${log}")"
  verdict="^run_tests: python ${version//./\\.}: [1-9][0-9]* tests, 0 skipped, every required test ran\$"
  [[ "${last}" =~ ${verdict} ]] || die "python ${version}: the runner's last line is not its verdict: ${last}"
done

# Each tool is given the project file by name, which is then its only
# configuration: found by itself, it would also obey one nearer a file.
venv="${work}/venv-${newer}"
(cd "${project}" && "${clean[@]}" "${venv}/bin/ruff" check --no-cache --config pyproject.toml .) ||
  die "ruff check found problems"
(cd "${project}" && "${clean[@]}" "${venv}/bin/ruff" format --check --no-cache --config pyproject.toml .) ||
  die "ruff format would change files"
(cd "${project}" && "${clean[@]}" "${venv}/bin/mypy" --cache-dir=/dev/null --config-file pyproject.toml) ||
  die "mypy found problems"

"${clean[@]}" uv build --quiet "${project}" --python "${newer}" \
  --build-constraints "${project}/build-constraints.txt" --require-hashes -o "${work}/dist" ||
  die "building the wheel failed"
"${clean[@]}" "${venv}/bin/python" "${isolated[@]}" "${project}/check_wheel.py" files \
  --dist "${work}/dist" --licence "${root}/LICENSE" --changelog "${root}/CHANGELOG.md" ||
  die "the built files are not what a release may hold"
"${clean[@]}" uv venv --quiet --python "${floor}" "${work}/venv-wheel" || die "no environment for the wheel"
"${clean[@]}" uv pip install --quiet --python "${work}/venv-wheel/bin/python" --no-deps --no-index \
  --no-build "${work}"/dist/*.whl || die "the wheel does not install"
"${clean[@]}" "${work}/venv-wheel/bin/python" "${isolated[@]}" "${project}/check_wheel.py" import ||
  die "the installed wheel does not import"

written="$(cd "${root}" && find clients/python -newer "${work}/before" -print)" ||
  die "listing the project failed"
[[ -z "${written}" ]] || die "something was written into the tree during the checks: ${written//$'\n'/ }"
[[ -z "$(ls -A "${work}/pycache")" ]] || die "bytecode was written although none should be"

printf 'check-python: green on python %s and %s\n' "${floor}" "${newer}"
