#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# The negative control of scripts/pre-push.sh. It builds a throwaway repository
# whose remote holds one commit, hands the hook the lines git would, and each
# case must pass or fail as named and say why:
#   pass     a branch push of a commit nobody gated, which a pull request's
#            checks judge; a push to main of a commit with a green stamp
#   refused  a push to main of a commit with no stamp, with a stamp of two
#            lines, with a stamp that is a symbolic link, from a local branch
#            of another name, and beside a branch push in the same push; a
#            line with no destination; and a push that names no remote
set -euo pipefail

_PROBE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
# shellcheck source=lib/repo-files.sh
. "${_PROBE_DIR}/lib/repo-files.sh"

die() {
  printf 'pre-push-probe: %s\n' "$*" >&2
  exit 1
}

root="$(repo_root)"
hook="${root}/scripts/pre-push.sh"
[[ -f "${hook}" ]] || die "${hook} is missing"
command -v git >/dev/null 2>&1 || die "git is not on PATH"

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

# The caller's git configuration could sign the commits or run hooks of its
# own, and a hook's environment would point git at the caller's repository.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
work="${tmp}/work"
g() {
  git -C "${work}" -c user.name=probe -c user.email=probe@example.invalid "$@"
}

git init -q --bare "${tmp}/remote.git"
git init -q -b main "${work}"
g commit -q --allow-empty -m base
g remote add origin "${tmp}/remote.git"
g push -q origin main
base="$(g rev-parse HEAD)"
g commit -q --allow-empty -m change
change="$(g rev-parse HEAD)"
stamps="${work}/.git/gate-green"
mkdir "${stamps}"
zero="0000000000000000000000000000000000000000"
to_main="refs/heads/main ${change} refs/heads/main ${base}"
to_topic="refs/heads/topic ${change} refs/heads/topic ${zero}"

cases=0
failed=0
# check <pass|refused> <what the hook must say> <name> <remote> <line>...
check() {
  local want="$1" needle="$2" name="$3" remote="$4" out rc=0
  shift 4
  out="$(cd "${work}" && printf '%s\n' "$@" | /bin/bash "${hook}" ${remote:+"${remote}"} 2>&1)" || rc=$?
  cases=$((cases + 1))
  if [[ "${want}" == pass && ${rc} -ne 0 ]] || [[ "${want}" == refused && ${rc} -ne 1 ]]; then
    printf 'FAIL %s: wanted %s, the hook exited %d: %s\n' "${name}" "${want}" "${rc}" "${out}" >&2
    failed=$((failed + 1))
  elif [[ "${out}" != *"${needle}"* ]]; then
    printf 'FAIL %s: the hook did not say "%s": %s\n' "${name}" "${needle}" "${out}" >&2
    failed=$((failed + 1))
  else
    printf 'ok   %s\n' "${name}"
  fi
}

check pass "nothing sent to main" "a branch push of an ungated commit" origin "${to_topic}"
check refused "${change} has no green gate" "a push to main with no stamp" origin "${to_main}"
check refused "${change} has no green gate" "a local branch pushed as main" origin \
  "refs/heads/topic ${change} refs/heads/main ${base}"
check refused "1 of 1 commit(s) ungated" "a push to main beside a branch push" origin "${to_topic}" "${to_main}"
check refused "names no destination" "a line with no destination" origin "refs/heads/main ${change}"
check refused "no destination remote" "a push that names no remote" "" "${to_main}"

printf '2026-01-01T00:00:00Z quality: green\nquality: green\n' >"${stamps}/${change}"
check refused "not the one line" "a stamp of two lines" origin "${to_main}"

rm "${stamps}/${change}"
printf '2026-01-01T00:00:00Z quality: green\n' >"${tmp}/elsewhere"
ln -s "${tmp}/elsewhere" "${stamps}/${change}"
check refused "not the one line" "a stamp that is a symbolic link" origin "${to_main}"

rm "${stamps}/${change}"
printf '2026-01-01T00:00:00Z quality: green\n' >"${stamps}/${change}"
check pass "1 commit(s), each gated green" "a push to main with a green stamp" origin "${to_main}"

[[ ${failed} -eq 0 ]] || die "${failed} of ${cases} cases did not go as named"
printf 'pre-push-probe: %d cases, each as named\n' "${cases}"
