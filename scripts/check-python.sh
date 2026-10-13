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
# skipped. Virtual environments, caches and built files go to a scratch
# directory: nothing is written into the tree.
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

command -v go >/dev/null 2>&1 || die "go is not on PATH"
command -v uv >/dev/null 2>&1 || die "uv is not on PATH; make bootstrap installs it"
have="$(uv --version 2>&1)" || die "uv --version exited non-zero"
[[ "${have}" =~ ^uv\ ([0-9]+\.[0-9]+\.[0-9]+) ]] || die "no version in the output of uv --version: ${have}"
[[ "${BASH_REMATCH[1]}" == "${UV_VERSION#v}" ]] || die "uv: want ${UV_VERSION#v}, have ${BASH_REMATCH[1]}"

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
mkdir "${work}/bin" "${work}/dist"

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

for version in "${floor}" "${newer}"; do
  venv="${work}/venv-${version}"
  "${clean[@]}" "UV_PROJECT_ENVIRONMENT=${venv}" uv sync --quiet --project "${project}" \
    --python "${version}" --locked --no-install-project --group dev ||
    die "python ${version}: the locked tools could not be installed; is the interpreter there (make bootstrap)?"
  ran="$("${clean[@]}" "${venv}/bin/python" -I -B -c 'import platform; print(platform.python_version())')" ||
    die "python ${version}: the interpreter does not run"
  [[ "${ran}" == "${version}" ]] || die "python ${version}: the environment runs ${ran}"
  "${clean[@]}" "${venv}/bin/python" -I -B "${project}/run_tests.py" --bin "${work}/bin" ||
    die "python ${version}: the tests failed"
done

venv="${work}/venv-${newer}"
"${clean[@]}" "${venv}/bin/ruff" check --no-cache "${project}" || die "ruff check found problems"
"${clean[@]}" "${venv}/bin/ruff" format --check --no-cache "${project}" || die "ruff format would change files"
(cd "${project}" && "${clean[@]}" "${venv}/bin/mypy" --cache-dir=/dev/null) || die "mypy found problems"

"${clean[@]}" uv build --quiet "${project}" --python "${newer}" \
  --build-constraints "${project}/build-constraints.txt" --require-hashes -o "${work}/dist" ||
  die "building the wheel failed"
"${clean[@]}" "${venv}/bin/python" -I -B "${project}/check_wheel.py" files \
  --dist "${work}/dist" --licence "${root}/LICENSE" --changelog "${root}/CHANGELOG.md" ||
  die "the built files are not what a release may hold"
"${clean[@]}" uv venv --quiet --python "${floor}" "${work}/venv-wheel" || die "no environment for the wheel"
"${clean[@]}" uv pip install --quiet --python "${work}/venv-wheel/bin/python" --no-deps --no-index \
  "${work}"/dist/*.whl || die "the wheel does not install"
"${clean[@]}" "${work}/venv-wheel/bin/python" -I -B "${project}/check_wheel.py" import ||
  die "the installed wheel does not import"

dirty="$(cd "${root}" && find clients/python \( -name __pycache__ -o -name .venv -o -name dist \
  -o -name '*.egg-info' -o -name .mypy_cache -o -name .ruff_cache \) -print)" || die "listing the tree failed"
[[ -z "${dirty}" ]] || die "the checks wrote into the tree: ${dirty//$'\n'/ }"

printf 'check-python: green on python %s and %s\n' "${floor}" "${newer}"
