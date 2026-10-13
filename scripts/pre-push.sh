#!/usr/bin/env bash
# A git pre-push hook: refuses a push to main unless every commit it would
# send has a green stamp from scripts/gate-commit.sh, which ran the whole gate
# on that commit's own archive. A push to any other ref needs no stamp: what
# it sends reaches main only through a pull request, whose checks run the gate.
# The destination decides, so a branch pushed under the name main is a push to
# main.
#
# A commit counts as sent unless the destination remote already holds it: on
# an existing branch, what lies past the remote's tip; on a new one, what no
# tracking ref of that remote reaches, whatever other remotes hold. A commit
# list git cannot give refuses the push.
#
#   ln -s ../../scripts/pre-push.sh .git/hooks/pre-push
set -euo pipefail

# git names the destination remote in $1, or repeats its URL there when the
# push names no remote; a URL matches no tracking ref, so every commit counts.
remote="${1:-}"
if [[ -z "${remote}" || "${remote}" == *[\*\?\[]* ]]; then
  printf 'pre-push: no destination remote named, or one git would read as a pattern: %q; nothing pushed\n' "${remote}" >&2
  exit 1
fi

stamps="$(git rev-parse --git-common-dir)/gate-green"
zero="0000000000000000000000000000000000000000"

# green says whether the stamp at $1 is the one line scripts/gate-commit.sh
# writes, in a regular file and nothing after it. The byte count catches what
# read cannot see, such as a NUL byte the shell drops.
stamp_shape='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z quality: green$'
green() {
  local line="" rest="" bytes
  [[ -f "$1" && ! -L "$1" ]] || return 1
  { IFS= read -r line && ! IFS= read -r rest && [[ -z "${rest}" ]]; } <"$1" || return 1
  [[ "${line}" =~ ${stamp_shape} ]] || return 1
  bytes="$(wc -c <"$1")" || return 1
  [[ "${bytes//[[:space:]]/}" == "$((${#line} + 1))" ]]
}
missing=0
checked=0
to_main=0

# git hands the hook one line per ref: <local ref> <local sha> <remote ref> <remote sha>.
while read -r local_ref local_sha remote_ref remote_sha; do
  [[ -n "${local_ref}" ]] || continue
  if [[ -z "${remote_ref}" || -z "${remote_sha}" ]]; then
    printf 'pre-push: a line that names no destination ref and commit: %q; nothing pushed\n' "${local_ref} ${local_sha}" >&2
    exit 1
  fi
  [[ "${remote_ref}" == "refs/heads/main" ]] || continue
  [[ "${local_sha}" != "${zero}" ]] || continue # a deletion sends no commit
  to_main=1
  if [[ "${remote_sha}" == "${zero}" ]]; then
    range=("${local_sha}" --not "--remotes=${remote}")
  else
    range=("${remote_sha}..${local_sha}")
  fi
  # The exit status, not an empty list, tells "nothing to send" from a list
  # git could not give.
  if ! sent="$(git rev-list "${range[@]}")"; then
    printf 'pre-push: the commits %s would send to %s could not be listed; nothing pushed\n' "${local_ref}" "${remote}" >&2
    exit 1
  fi
  while read -r sha; do
    [[ -n "${sha}" ]] || continue
    checked=$((checked + 1))
    if [[ ! -e "${stamps}/${sha}" && ! -L "${stamps}/${sha}" ]]; then
      printf 'pre-push: %s has no green gate; run scripts/gate-commit.sh %s\n' "${sha}" "${sha}" >&2
      missing=$((missing + 1))
    elif ! green "${stamps}/${sha}"; then
      printf 'pre-push: %s has a stamp that is not the one line gate-commit.sh writes; run scripts/gate-commit.sh %s\n' "${sha}" "${sha}" >&2
      missing=$((missing + 1))
    fi
  done <<<"${sent}"
done

if [[ ${to_main} -eq 0 ]]; then
  printf 'pre-push: nothing sent to main; no stamp required\n' >&2
  exit 0
fi
if [[ ${missing} -ne 0 ]]; then
  printf 'pre-push: %d of %d commit(s) ungated; nothing pushed\n' "${missing}" "${checked}" >&2
  exit 1
fi
printf 'pre-push: %d commit(s), each gated green on its own archive\n' "${checked}" >&2
