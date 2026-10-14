#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# The negative control of scripts/pre-push.sh. It builds a throwaway repository
# two commits and a merge ahead of its remote's main, hands the hook the lines
# git would, then pushes for real through the installed hook, and each case
# must pass or be refused as named and say why:
#   pass     a branch push of commits nobody gated, which a pull request's
#            checks judge, to a remote named by a URL too; a deletion; a push
#            to main, a lightweight and an annotated release tag, of gated
#            commits
#   refused  a push to main with no stamp, with one commit of several
#            unstamped (the older, the newer, a merge's side, one a replace
#            ref hides), from a local branch of another name, from a source
#            that holds a space, beside a branch push in either order, before
#            or after a gated line, without a final newline, to a remote that
#            has no main but holds the commits on a branch, past a remote
#            commit this repository lacks, and of a tree; a stamp of two
#            lines, of the wrong words, with words before or after, with a
#            NUL byte, or that is a symbolic link; a release tag of any v
#            name, new or moved, on a commit nobody gated, or on a tree; a
#            line that lacks a field, or holds a destination or an object
#            name git would not write; a push that names no remote
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

# The caller's git configuration could sign the commits, run hooks of its own
# or name another repository, and a hook's environment carries all three.
while IFS= read -r name; do
  unset "${name}"
done < <(git rev-parse --local-env-vars)
unset GIT_TEMPLATE_DIR
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
work="${tmp}/work"
g() {
  git -C "${work}" -c user.name=probe -c user.email=probe@example.invalid "$@"
}

git init -q --template= --bare "${tmp}/origin.git"
git init -q --template= --bare "${tmp}/fresh.git"
git init -q --template= -b main "${work}"
g commit -q --allow-empty -m base
g remote add origin "${tmp}/origin.git"
g remote add fresh "${tmp}/fresh.git"
g push -q origin main
base="$(g rev-parse HEAD)"
g commit -q --allow-empty -m "change one"
one="$(g rev-parse HEAD)"
g commit -q --allow-empty -m "change two"
two="$(g rev-parse HEAD)"
tree="$(g rev-parse "${two}^{tree}")"
side="$(g commit-tree -p "${base}" -m "side" "${tree}")"
merged="$(g commit-tree -p "${two}" -p "${side}" -m "merge" "${tree}")"
g tag -a -m "a release" v8.8.8 "${two}"
annotated="$(g rev-parse refs/tags/v8.8.8)"
stamps="${work}/.git/gate-green"
mkdir "${stamps}"
zero="0000000000000000000000000000000000000000"
nl=$'\n'
to_main="refs/heads/main ${two} refs/heads/main ${base}"
to_topic="refs/heads/topic ${two} refs/heads/topic ${zero}"
green_line="2026-01-01T00:00:00Z quality: green"

stamp() {
  local sha
  for sha in "$@"; do
    printf '%s\n' "${green_line}" >"${stamps}/${sha}"
  done
}
unstamp() {
  rm -rf "${stamps:?}"
  mkdir "${stamps}"
}

cases=0
failed=0
# verdict <pass|refused> <what the hook must say> <name> <exit status> <output>
verdict() {
  local want="$1" needle="$2" name="$3" rc="$4" out="$5"
  cases=$((cases + 1))
  if [[ "${want}" == pass && ${rc} -ne 0 ]] || [[ "${want}" == refused && ${rc} -ne 1 ]]; then
    printf 'FAIL %s: wanted %s, exit %d: %s\n' "${name}" "${want}" "${rc}" "${out}" >&2
    failed=$((failed + 1))
  elif [[ "${out}" != *"${needle}"* ]]; then
    printf 'FAIL %s: nothing said "%s": %s\n' "${name}" "${needle}" "${out}" >&2
    failed=$((failed + 1))
  else
    printf 'ok   %s\n' "${name}"
  fi
}
# check <pass|refused> <needle> <name> <remote> <the hook's standard input>
check() {
  local out rc=0
  out="$(cd "${work}" && printf '%s' "$5" | /bin/bash "${hook}" ${4:+"$4"} 2>&1)" || rc=$?
  verdict "$1" "$2" "$3" "${rc}" "${out}"
}

check pass "no stamp required" "a branch push of ungated commits" origin "${to_topic}${nl}"
check pass "no stamp required" "a branch push to a remote named by a URL" 'ssh://git@[2001:db8::1]/r.git?x=1' "${to_topic}${nl}"
check pass "no stamp required" "a deletion of main, which sends no commit" origin "(delete) ${zero} refs/heads/main ${base}${nl}"
check refused "2 of 2 commit(s) ungated" "a push to main with no stamp" origin "${to_main}${nl}"
check refused "2 of 2 commit(s) ungated" "a local branch pushed as main" origin \
  "refs/heads/topic ${two} refs/heads/main ${base}${nl}"
check refused "2 of 2 commit(s) ungated" "a source that holds a space" origin \
  "HEAD^{/change two} ${two} refs/heads/main ${base}${nl}"
check refused "2 of 2 commit(s) ungated" "a branch push, then main" origin "${to_topic}${nl}${to_main}${nl}"
check refused "2 of 2 commit(s) ungated" "main, then a branch push" origin "${to_main}${nl}${to_topic}${nl}"
check refused "2 of 2 commit(s) ungated" "a last line without a newline" origin "${to_topic}${nl}${to_main}"
check refused "a line git did not write" "a line of two fields" origin "refs/heads/main ${two}${nl}"
check refused "a line git did not write" "a line with no remote commit" origin "refs/heads/main ${two} refs/heads/main${nl}"
check refused "a line git did not write" "a line with no source" origin "${two} refs/heads/main ${base}${nl}"
check refused "a line git did not write" "a destination that is no full ref" origin "refs/heads/main ${two} main ${base}${nl}"
check refused "a line git did not write" "a local commit that is no object name" origin "refs/heads/main 0 refs/heads/main ${base}${nl}"
check refused "no destination remote" "a push that names no remote" "" "${to_main}${nl}"
check refused "could not be listed" "a remote commit this repository lacks" origin \
  "refs/heads/main ${two} refs/heads/main 1111111111111111111111111111111111111111${nl}"
check refused "names no commit" "a local commit that begins with a zero" origin \
  "refs/heads/main 0123456789abcdef0123456789abcdef01234567 refs/heads/main ${base}${nl}"
check refused "names no commit" "a local commit that ends with a zero" origin \
  "refs/heads/main 123456789abcdef0123456789abcdef012345670 refs/heads/main ${base}${nl}"
check refused "names no commit" "a tree sent to main" origin "refs/heads/main ${tree} refs/heads/main ${base}${nl}"
check refused "5 of 5 commit(s) ungated" "a new main with a merge in it" fresh \
  "refs/heads/main ${merged} refs/heads/main ${zero}${nl}"
for name in v9.9.9 v0.11.0 v1.0.0-rc.1 vnext; do
  check refused "${two} has no green gate" "a release tag ${name} on an ungated commit" origin \
    "refs/tags/${name} ${two} refs/tags/${name} ${zero}${nl}"
done
check refused "${two} has no green gate" "a release tag moved onto an ungated commit" origin \
  "refs/tags/v9.9.9 ${two} refs/tags/v9.9.9 ${base}${nl}"
check refused "${two} has no green gate" "an annotated release tag on an ungated commit" origin \
  "refs/tags/v8.8.8 ${annotated} refs/tags/v8.8.8 ${zero}${nl}"
check refused "names no commit" "a release tag on a tree" origin "refs/tags/v9.9.9 ${tree} refs/tags/v9.9.9 ${zero}${nl}"

stamp "${two}"
check refused "1 of 2 commit(s) ungated" "only the newer commit gated" origin "${to_main}${nl}"
check refused "1 of 3 commit(s) ungated" "a gated line after an ungated one" origin \
  "${to_main}${nl}refs/tags/v9.9.9 ${two} refs/tags/v9.9.9 ${zero}${nl}"
g replace --graft "${two}" "${base}"
check refused "1 of 2 commit(s) ungated" "a commit a replace ref hides" origin "${to_main}${nl}"
g replace -d "${two}" >/dev/null
stamp "${one}" "${merged}"
check refused "1 of 4 commit(s) ungated" "a merge whose side nobody gated" origin \
  "refs/heads/main ${merged} refs/heads/main ${base}${nl}"
unstamp
stamp "${one}"
check refused "1 of 2 commit(s) ungated" "only the older commit gated" origin "${to_main}${nl}"
check refused "1 of 3 commit(s) ungated" "an ungated line after a gated one" origin \
  "refs/heads/main ${one} refs/heads/main ${base}${nl}${to_main}${nl}"

stamp "${one}" "${two}"
printf '%s\n%s\n' "${green_line}" "quality: green" >"${stamps}/${two}"
check refused "not the one line" "a stamp of two lines" origin "${to_main}${nl}"
printf '%s\n' "2026-01-01T00:00:00Z quality: red" >"${stamps}/${two}"
check refused "not the one line" "a stamp of the wrong words" origin "${to_main}${nl}"
printf '%s\n' "x ${green_line}" >"${stamps}/${two}"
check refused "not the one line" "a stamp with words before" origin "${to_main}${nl}"
printf '%s\n' "${green_line} x" >"${stamps}/${two}"
check refused "not the one line" "a stamp with words after" origin "${to_main}${nl}"
printf '%s\0\n' "${green_line}" >"${stamps}/${two}"
check refused "not the one line" "a stamp with a NUL byte" origin "${to_main}${nl}"
rm "${stamps}/${two}"
printf '%s\n' "${green_line}" >"${tmp}/elsewhere"
ln -s "${tmp}/elsewhere" "${stamps}/${two}"
check refused "not the one line" "a stamp that is a symbolic link" origin "${to_main}${nl}"
rm "${stamps}/${two}"

stamp "${two}"
check pass "2 commit(s), each gated green" "a push to main of gated commits" origin "${to_main}${nl}"
check pass "1 commit(s), each gated green" "a release tag on a gated commit" origin \
  "refs/tags/v9.9.9 ${two} refs/tags/v9.9.9 ${zero}${nl}"
check pass "1 commit(s), each gated green" "an annotated release tag on a gated commit" origin \
  "refs/tags/v8.8.8 ${annotated} refs/tags/v8.8.8 ${zero}${nl}"
stamp "${base}"
check refused "a line git did not write" "a remote commit that is no object name" origin \
  "refs/heads/main ${two} refs/heads/main 0${nl}"

# From here git writes the lines: the hook is installed and the pushes are real.
unstamp
mkdir -p "${work}/.git/hooks"
ln -s "${hook}" "${work}/.git/hooks/pre-push"
push() {
  local want="$1" needle="$2" name="$3" out rc=0
  shift 3
  out="$(g push "$@" 2>&1)" || rc=$?
  verdict "${want}" "${needle}" "${name}" "${rc}" "${out}"
}
remote_ref() {
  git --git-dir="$1" rev-parse --verify --quiet "$2" || true
}
push pass "no stamp required" "a real branch push" fresh HEAD:refs/heads/topic
[[ "$(remote_ref "${tmp}/fresh.git" refs/heads/topic)" == "${two}" ]] || die "the branch push did not land"
push refused "3 of 3 commit(s) ungated" "a new main on a remote that holds the commits" fresh HEAD:main
push refused "2 of 2 commit(s) ungated" "a real push from a source with a space" origin "HEAD^{/change two}:main"
push refused "${two} has no green gate" "a real release tag push" origin "HEAD:refs/tags/v9.9.9"
[[ -z "$(remote_ref "${tmp}/fresh.git" refs/heads/main)" ]] || die "fresh has a main no gate saw"
[[ "$(remote_ref "${tmp}/origin.git" refs/heads/main)" == "${base}" ]] || die "origin's main moved past its gate"
[[ -z "$(remote_ref "${tmp}/origin.git" refs/tags/v9.9.9)" ]] || die "origin holds a tag no gate saw"
stamp "${one}" "${two}"
push pass "2 commit(s), each gated green" "a real push to main of gated commits" origin HEAD:main
push pass "1 commit(s), each gated green" "a real release tag push of a gated commit" origin HEAD:refs/tags/v9.9.9
[[ "$(remote_ref "${tmp}/origin.git" refs/heads/main)" == "${two}" ]] || die "the gated push to main did not land"
[[ "$(remote_ref "${tmp}/origin.git" refs/tags/v9.9.9)" == "${two}" ]] || die "the gated tag push did not land"

[[ ${failed} -eq 0 ]] || die "${failed} of ${cases} cases did not go as named"
printf 'pre-push-probe: %d cases, each as named\n' "${cases}"
