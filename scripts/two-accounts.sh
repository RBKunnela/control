#!/usr/bin/env bash
# Runs the tests scripts/expected-runs.txt names as root beside two other
# accounts, for the "Two accounts" CI job (ADR-0081). Each package the list
# names is built with the twoaccounts tag into a directory every account may
# execute from, and only its listed tests run, under sudo, with
# GUARDANA_TEST_OTHER_UID and GUARDANA_TEST_THIRD_UID set; a test hands each
# account its part through a child process. Every run's go test -json events
# go to scripts/check-runs.go, which fails unless each listed test passed, so
# a skip, a missing test, a failed build or no events at all fail the job. A
# build or a run that fails still hands on what it wrote, and fails the
# script as well.
#
#   GUARDANA_TEST_OTHER_UID=<uid> GUARDANA_TEST_THIRD_UID=<uid> scripts/two-accounts.sh
#
# Run it as an account that may run sudo without a password; never as root,
# whose test binaries would then be built by root too.
set -euo pipefail

die() {
  printf 'two-accounts: %s\n' "$*" >&2
  exit 1
}

top="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)"
cd "${top}"

other="${GUARDANA_TEST_OTHER_UID:-}"
third="${GUARDANA_TEST_THIRD_UID:-}"
[[ "${other}" =~ ^[1-9][0-9]*$ ]] || die "GUARDANA_TEST_OTHER_UID is not an account other than root: '${other}'"
[[ "${third}" =~ ^[1-9][0-9]*$ ]] || die "GUARDANA_TEST_THIRD_UID is not an account other than root: '${third}'"
[[ "${other}" != "${third}" ]] || die "GUARDANA_TEST_OTHER_UID and GUARDANA_TEST_THIRD_UID name one account"
[[ "$(id -u)" != 0 ]] || die "run this as an account with sudo, not as root"
sudo -n true || die "sudo asks for a password or is refused"

list="scripts/expected-runs.txt"
[[ -r "${list}" ]] || die "cannot read ${list}"

work="$(mktemp -d /tmp/two-accounts.XXXXXX)"
trap 'rm -rf "${work}"' EXIT
chmod 0755 "${work}"
stream="${work}/events.jsonl"
: >"${stream}"

# The packages in the order the list first names them, one per line.
packages=""
while read -r pkg test rest; do
  case "${pkg}" in '' | '#'*) continue ;; esac
  [[ -n "${test}" && -z "${rest}" ]] || die "${list}: '${pkg} ${test} ${rest}' is not <import path> <test name>"
  case "${packages}" in *"<${pkg}>"*) ;; *) packages="${packages}<${pkg}>"$'\n' ;; esac
done <"${list}"
[[ -n "${packages}" ]] || die "${list} names no test"

status=0
while read -r entry <&3; do
  [[ -n "${entry}" ]] || continue
  pkg="${entry#<}"
  pkg="${pkg%>}"
  names=""
  while read -r p test _; do
    [[ "${p}" == "${pkg}" ]] && names="${names}${names:+|}${test}"
  done <"${list}"
  bin="${work}/$(printf '%s' "${pkg}" | tr '/.' '__').test"
  if ! go test -c -tags twoaccounts -o "${bin}" "${pkg}" </dev/null; then
    printf 'two-accounts: %s does not build\n' "${pkg}" >&2
    status=1
    continue
  fi
  # go test -c writes nothing for a package without test files.
  if [[ ! -x "${bin}" ]]; then
    printf 'two-accounts: %s built no test binary\n' "${pkg}" >&2
    status=1
    continue
  fi
  chmod 0755 "${bin}"
  dir="$(go list -f '{{.Dir}}' "${pkg}" </dev/null)"
  if ! (cd "${dir}" && go tool test2json -t -p "${pkg}" \
    sudo -n env "GUARDANA_TEST_OTHER_UID=${other}" "GUARDANA_TEST_THIRD_UID=${third}" \
    "${bin}" -test.v=test2json -test.count=1 -test.timeout=10m -test.run "^(${names})\$" \
    </dev/null >>"${stream}"); then
    printf 'two-accounts: a test of %s failed\n' "${pkg}" >&2
    status=1
  fi
done 3<<<"${packages}"

if ! go run scripts/check-runs.go <"${stream}"; then
  status=1
fi
exit "${status}"
