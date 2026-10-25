#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Checks the local toolchain and installs a missing binary tool with Homebrew.
# Two pin files, because they have different readers: go.mod holds the Go
# version and the Go tools, scripts/tool-versions.env holds the binary tools.
# Go tools are never installed here; `go mod download` fetches them. With
# --check it only compares: nothing is downloaded or installed, and a missing
# tool fails like a mismatched one. scripts/gate-commit.sh runs it that way.
#
#   scripts/bootstrap.sh [--check]
set -euo pipefail

_BOOTSTRAP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

# shellcheck source=lib/repo-files.sh
. "${_BOOTSTRAP_DIR}/lib/repo-files.sh"
# Read from the script's own directory, so the pins do not depend on $PWD.
# shellcheck source=tool-versions.env
. "${_BOOTSTRAP_DIR}/tool-versions.env"

ROOT="$(repo_root)"
GO_MOD="${ROOT}/go.mod"

# Every tool below must reach one of these two counters, so an early `exit 0`
# after a skipped comparison is impossible.
readonly TOOL_COUNT=13
checked=0
failures=0

fail() {
  printf 'FAIL %s\n' "$*" >&2
  failures=$((failures + 1))
}

die() {
  printf 'FAIL %s\n' "$*" >&2
  exit 1
}

check_only=0
case "$#:${1:-}" in
  0:) ;;
  1:--check) check_only=1 ;;
  *) die "usage: scripts/bootstrap.sh [--check]" ;;
esac

# semver_of <version output>
# Prints the first version token on the first line, without a leading "v": a
# word that starts x.y.z, whole up to the next white space, so a prerelease or
# build such as 2.14.0-rc.1, -dev or +dirty never matches a pin of the
# release. Each pinned tool prints its own version there, ahead of any
# compiler version it also reports.
semver_of() {
  local first="${1%%$'\n'*}"
  [[ "${first}" =~ (^|[[:space:]])v?([0-9]+\.[0-9]+\.[0-9]+[^[:space:]]*) ]] || return 1
  printf '%s\n' "${BASH_REMATCH[2]}"
}

# go_version_pin <go.mod>
# Prints the version from the `go` directive. go.mod puts that directive on its
# own line at top level, so anchoring at the start of the line cannot pick up
# `toolchain` or `godebug`. Exactly one match is required: zero or several mean
# the file is not what this script thinks it is, which is a failure and never a
# default.
go_version_pin() {
  local file="$1" matches line count=0 found=""
  [[ -f "${file}" ]] || {
    printf 'go: %s does not exist\n' "${file}" >&2
    return 1
  }
  matches="$(sed -n -E 's/^go[[:space:]]+([0-9]+\.[0-9]+(\.[0-9]+)?)[[:space:]]*$/\1/p' "${file}")"
  if [[ -z "${matches}" ]]; then
    printf 'go: no usable go directive in %s\n' "${file}" >&2
    return 1
  fi
  while IFS= read -r line; do
    count=$((count + 1))
    found="${line}"
  done <<<"${matches}"
  if [[ ${count} -ne 1 ]]; then
    printf 'go: %d go directives in %s, expected 1\n' "${count}" "${file}" >&2
    return 1
  fi
  printf '%s\n' "${found}"
}

require_go() {
  local want out have
  command -v go >/dev/null 2>&1 || die "go: not on PATH"
  want="$(go_version_pin "${GO_MOD}")" || die "go: cannot read the version pin"
  out="$(go version)"
  # Compare the whole token, not a substring: a pinned 1.27.1 must reject
  # go1.27.10, and a pinned 1.27 must reject go1.27.1. The pin is exact by
  # design, so a newer patch is a mismatch and not an upgrade.
  if [[ "${out}" =~ go([0-9]+\.[0-9]+(\.[0-9]+)?)([[:space:]]|$) ]]; then
    have="${BASH_REMATCH[1]}"
  else
    die "go: no version in the output of \`go version\`: ${out}"
  fi
  [[ "${have}" == "${want}" ]] || die "go: want ${want} (from go.mod), have ${have}"
  printf 'ok   go %s\n' "${have}"
}

# check_tool <binary> <brew formula> <pin key in tool-versions.env> [<line prefix>] [<version argument>]
# The pin is read through its key name, so an empty or missing key names itself
# instead of producing "want , have 8.30.1". The version is read from the first
# line of `--version`, or from the first line starting with the prefix when one
# is given: shellcheck names itself on its first line and its version on the
# second, goreleaser and cosign print a banner first. cosign takes `version`
# rather than `--version`, hence the last argument.
check_tool() {
  local bin="$1" formula="$2" key="$3" prefix="${4:-}" version_arg="${5:---version}" want out have
  want="${!key-}"
  if [[ -z "${want}" ]]; then
    fail "${bin}: ${key} is empty or missing in tool-versions.env"
    return
  fi
  # The pins carry a leading "v"; semver_of drops the one a tool reports.
  want="${want#v}"
  if ! command -v "${bin}" >/dev/null 2>&1; then
    if ((check_only)); then
      fail "${bin}: missing; --check installs nothing"
      return
    fi
    if ! command -v brew >/dev/null 2>&1; then
      fail "${bin}: missing, and Homebrew is not installed to provide it"
      return
    fi
    printf 'installing %s\n' "${formula}"
    if ! brew install "${formula}"; then
      fail "${bin}: brew install ${formula} failed"
      return
    fi
    hash -r
  fi
  if ! out="$("${bin}" "${version_arg}" 2>&1)"; then
    fail "${bin}: ${version_arg} exited non-zero"
    return
  fi
  if [[ -n "${prefix}" ]]; then
    out="$(printf '%s\n' "${out}" | grep -m1 -F -- "${prefix}" || true)"
    [[ "${out}" == "${prefix}"* ]] || out=""
  fi
  if ! have="$(semver_of "${out}")"; then
    fail "${bin}: no version number in the output of ${bin} ${version_arg}"
    return
  fi
  if [[ "${have}" != "${want}" ]]; then
    fail "${bin}: want ${want}, have ${have}"
    return
  fi
  printf 'ok   %s %s\n' "${bin}" "${have}"
  checked=$((checked + 1))
}

# check_python <pin key in tool-versions.env>
# The interpreter must be one uv manages: a system Python of the same version
# is another build. Installing puts no executable on PATH.
check_python() {
  local key="$1" want
  want="${!key-}"
  if [[ -z "${want}" ]]; then
    fail "python: ${key} is empty or missing in tool-versions.env"
    return
  fi
  if ! command -v uv >/dev/null 2>&1; then
    fail "python ${want}: uv is missing"
    return
  fi
  if ! uv python find --no-config --managed-python --no-python-downloads "${want}" >/dev/null 2>&1; then
    if ((check_only)); then
      fail "python ${want}: not installed by uv; --check installs nothing"
      return
    fi
    printf 'installing python %s\n' "${want}"
    if ! uv python install --no-config --no-bin "${want}"; then
      fail "python ${want}: uv python install failed"
      return
    fi
  fi
  printf 'ok   python %s\n' "${want}"
  checked=$((checked + 1))
}

require_go

if ((!check_only)) && ! (cd "${ROOT}" && go mod download); then
  die "go mod download failed in ${ROOT}"
fi

check_tool golangci-lint golangci-lint GOLANGCI_LINT_VERSION
check_tool buf buf BUF_VERSION
check_tool actionlint actionlint ACTIONLINT_VERSION
check_tool zizmor zizmor ZIZMOR_VERSION
check_tool gitleaks gitleaks GITLEAKS_VERSION
check_tool osv-scanner osv-scanner OSV_SCANNER_VERSION
check_tool syft syft SYFT_VERSION
check_tool shellcheck shellcheck SHELLCHECK_VERSION 'version:'
check_tool goreleaser goreleaser GORELEASER_VERSION 'GitVersion:'
check_tool cosign cosign COSIGN_VERSION 'GitVersion:' version
check_tool uv uv UV_VERSION
check_python CLIENT_PYTHON_FLOOR_VERSION
check_python CLIENT_PYTHON_VERSION

if [[ ${failures} -ne 0 ]]; then
  printf '%d of %d tools failed the version check\n' "${failures}" "${TOOL_COUNT}" >&2
  exit 1
fi
if [[ ${checked} -ne ${TOOL_COUNT} ]]; then
  die "compared ${checked} tools, expected ${TOOL_COUNT}"
fi

if ((check_only)); then
  printf 'bootstrap --check: go and %d tools match their pins; nothing installed\n' "${checked}"
else
  printf 'bootstrap ok\n'
fi
