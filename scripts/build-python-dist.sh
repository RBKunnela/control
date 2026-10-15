#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Builds the Python client's wheel and source archive into a directory and
# checks them as a release may hold them: no declared requirement, the
# repository's licence, exactly the module's own files, and the version of
# the newest dated section of CHANGELOG.md, or the one given. The wheel is
# then installed on the floor interpreter and imported. make check-python
# and both jobs of the release workflow build through here, so the files the
# gate checked are built as the files a release uploads.
#
#   scripts/build-python-dist.sh <new directory> [<version>]
#
# Given a version, the project is copied to a scratch directory and built
# there under that version; the dry run builds a snapshot so. The tree is
# never written.
set -euo pipefail

_BUILD_PYTHON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
# shellcheck source=lib/repo-files.sh
. "${_BUILD_PYTHON_DIR}/lib/repo-files.sh"
# shellcheck source=tool-versions.env
. "${_BUILD_PYTHON_DIR}/tool-versions.env"
# shellcheck source=lib/python-env.sh
. "${_BUILD_PYTHON_DIR}/lib/python-env.sh"

die() {
  printf 'build-python-dist: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 1 || $# -eq 2 ]] || die "usage: scripts/build-python-dist.sh <new directory> [<version>]"
out="$1"
version="${2-}"
[[ ! -e "${out}" && ! -L "${out}" ]] || die "${out} exists; give a directory that does not"
root="$(repo_root)"
project="${root}/clients/python"
[[ -f "${project}/pyproject.toml" ]] || die "${project} holds no project"
python_uv_pinned || die "uv is not the pinned one"

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
python_env "${work}" || die "no scratch directory for bytecode"

source="${project}"
expect=()
if [[ -n "${version}" ]]; then
  # The forms a release and a snapshot are spelled in: 1.2.3, 1.2.3rc1,
  # 1.2.3.dev45, 1.2.3rc1.dev45.
  [[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+((a|b|rc)[0-9]+)?(\.dev[0-9]+)?$ ]] ||
    die "${version} is not a version this script builds"
  source="${work}/project"
  cp -R "${project}" "${source}"
  find "${source}" -mindepth 1 -maxdepth 1 -name '.*' -exec rm -rf {} +
  pattern='^version = "[^"]*"$'
  [[ "$(grep -c "${pattern}" "${source}/pyproject.toml")" == 1 ]] ||
    die "the project file does not hold exactly one version line"
  sed "s/${pattern}/version = \"${version}\"/" "${source}/pyproject.toml" >"${work}/pyproject.toml"
  mv "${work}/pyproject.toml" "${source}/pyproject.toml"
  grep -qx "version = \"${version}\"" "${source}/pyproject.toml" || die "the version was not set"
  expect=(--version "${version}")
fi

mkdir -p "${out}"
"${clean[@]}" uv build --quiet "${source}" --python "${CLIENT_PYTHON_VERSION}" \
  --build-constraints "${source}/build-constraints.txt" --require-hashes -o "${out}" ||
  die "building the wheel failed"
"${clean[@]}" uv venv --quiet --python "${CLIENT_PYTHON_FLOOR_VERSION}" "${work}/venv" ||
  die "no environment for the wheel"
"${clean[@]}" "${work}/venv/bin/python" "${isolated[@]}" "${source}/check_wheel.py" files \
  --dist "${out}" --licence "${root}/LICENSE" --changelog "${root}/CHANGELOG.md" ${expect[@]+"${expect[@]}"} ||
  die "the built files are not what a release may hold"
"${clean[@]}" uv pip install --quiet --python "${work}/venv/bin/python" --no-deps --no-index \
  --no-build "${out}"/*.whl || die "the wheel does not install"
"${clean[@]}" "${work}/venv/bin/python" "${isolated[@]}" "${source}/check_wheel.py" import ||
  die "the installed wheel does not import"
[[ -z "$(ls -A "${work}/pycache")" ]] || die "bytecode was written although none should be"
# uv leaves an ignore file beside what it builds; an upload takes the rest.
rm -f "${out}/.gitignore"
[[ "$(find "${out}" -mindepth 1 | wc -l | tr -d ' ')" == 2 ]] ||
  die "${out} holds more than one wheel and one source archive"

printf 'build-python-dist: %s\n' "$(find "${out}" -mindepth 1 -maxdepth 1 -exec basename {} \; | sort | tr '\n' ' ')"
