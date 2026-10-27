#!/usr/bin/env bash
# shellcheck disable=SC2034 # clean and isolated are read by a script that sources this file
# The environment the Python client is checked and built in. A script that
# sources this file has sourced tool-versions.env first.
#
#   python_env <scratch dir>  sets clean, a command prefix that runs under an
#                             emptied environment with uv's configuration off,
#                             managed interpreters only and no interpreter
#                             download, and isolated, the flags every Python
#                             gets: isolated, writing no bytecode and looking
#                             for it only in <scratch dir>/pycache, which it
#                             makes empty
#   python_uv_pinned          fails unless uv on PATH is the pinned version

python_env() {
  local v
  clean=(env -i)
  for v in HOME PATH TMPDIR USER LOGNAME \
    HTTP_PROXY HTTPS_PROXY NO_PROXY http_proxy https_proxy no_proxy SSL_CERT_FILE SSL_CERT_DIR; do
    if [[ -n "${!v+x}" ]]; then
      clean+=("${v}=${!v}")
    fi
  done
  clean+=(UV_NO_CONFIG=1 UV_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never UV_NO_PROGRESS=1
    PYTHONDONTWRITEBYTECODE=1)
  # A stale or planted __pycache__ beside a source would otherwise run in
  # place of the file the commit holds.
  mkdir "$1/pycache" || return 1
  isolated=(-I -B -X "pycache_prefix=$1/pycache")
}

# The version is uv's whole word after "uv ", up to the next white space, as
# scripts/bootstrap.sh reads its tools: a prerelease or build of the pinned
# release, such as 0.12.9-beta.1, is another version.
python_uv_pinned() {
  local have first
  command -v uv >/dev/null 2>&1 || { echo "uv is not on PATH; make bootstrap installs it" >&2; return 1; }
  have="$(uv --version 2>&1)" || { echo "uv --version exited non-zero" >&2; return 1; }
  first="${have%%$'\n'*}"
  if [[ ! "${first}" =~ ^uv\ ([^[:space:]]+) ]]; then
    echo "no version in the output of uv --version: ${have}" >&2
    return 1
  fi
  if [[ "${BASH_REMATCH[1]}" != "${UV_VERSION#v}" ]]; then
    echo "uv: want ${UV_VERSION#v}, have ${BASH_REMATCH[1]}" >&2
    return 1
  fi
}
