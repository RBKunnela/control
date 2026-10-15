#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Uploads the Python client's wheel and source archive to a package index by
# trusted publishing, then reads the index back until it lists exactly those
# files, digest for digest. Run by the release workflow only: the index
# accepts the job's identity in place of a token, and nothing else holds one.
#
#   scripts/publish-python-dist.sh <directory> pypi|testpypi <version>
#
# The version is the one the job that built the files gave them; files of
# any other are refused. A file the index already holds with the same digest
# is skipped, so a job that failed after an upload can be run again. An
# uploaded file is never replaced.
set -euo pipefail

_PUBLISH_PYTHON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
# shellcheck source=tool-versions.env
. "${_PUBLISH_PYTHON_DIR}/tool-versions.env"
# shellcheck source=lib/python-env.sh
. "${_PUBLISH_PYTHON_DIR}/lib/python-env.sh"

die() {
  printf 'publish-python-dist: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 3 ]] || die "usage: scripts/publish-python-dist.sh <directory> pypi|testpypi <version>"
dir="$1"
want="$3"
[[ "${want}" =~ ^[0-9]+\.[0-9]+\.[0-9]+((a|b|rc)[0-9]+)?(\.dev[0-9]+)?$ ]] ||
  die "${want} is not a version the build gives"
case "$2" in
  pypi) host=pypi.org upload=https://upload.pypi.org/legacy/ ;;
  testpypi) host=test.pypi.org upload=https://test.pypi.org/legacy/ ;;
  *) die "no index named $2" ;;
esac
python_uv_pinned || die "uv is not the pinned one"
command -v jq >/dev/null 2>&1 || die "jq is not on PATH"

wheels=("${dir}"/*.whl)
archives=("${dir}"/*.tar.gz)
[[ ${#wheels[@]} -eq 1 && -f "${wheels[0]}" && ${#archives[@]} -eq 1 && -f "${archives[0]}" ]] ||
  die "${dir} holds no single wheel and source archive"
[[ "$(find "${dir}" -mindepth 1 | wc -l | tr -d ' ')" == 2 ]] || die "${dir} holds more than the two files"
wheel="$(basename "${wheels[0]}")"
# A wheel's name is <name>-<version>-<tags>.whl, the name's dashes written
# as underscores; the index answers for either spelling.
[[ "${wheel}" =~ ^([A-Za-z0-9_]+)-([0-9][A-Za-z0-9.]*)-py3-none-any\.whl$ ]] ||
  die "${wheel} is not the pure wheel this project builds"
name="${BASH_REMATCH[1]}"
version="${BASH_REMATCH[2]}"
[[ "${version}" == "${want}" ]] || die "${wheel} is not of version ${want}"
[[ "$(basename "${archives[0]}")" == "${name}-${want}.tar.gz" ]] ||
  die "$(basename "${archives[0]}") is not the source archive of ${name} ${want}"

expected="$(cd "${dir}" && for f in "${wheel}" "$(basename "${archives[0]}")"; do
  printf '%s %s\n' "${f}" "$(sha256sum "${f}" | cut -d' ' -f1)"
done | sort)"

UV_NO_CONFIG=1 uv publish --trusted-publishing always --publish-url "${upload}" \
  --check-url "https://${host}/simple/" "${wheels[0]}" "${archives[0]}" ||
  die "the upload to ${host} failed"

# The index serves what it accepted after a short delay.
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  listed="$(curl -fsSL --retry 3 "https://${host}/pypi/${name}/${version}/json" |
    jq -r '.urls[] | "\(.filename) \(.digests.sha256)"' | sort)" || listed=""
  if [[ "${listed}" == "${expected}" ]]; then
    printf 'publish-python-dist: %s lists %s %s with the uploaded digests\n' "${host}" "${name}" "${version}"
    exit 0
  fi
  [[ ${attempt} -eq 10 ]] || sleep 15
done
printf 'want:\n%s\nlisted:\n%s\n' "${expected}" "${listed:-nothing}" >&2
die "${host} does not list exactly the uploaded files for ${name} ${version}"
