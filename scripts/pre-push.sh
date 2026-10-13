#!/usr/bin/env bash
# A git pre-push hook: refuses a push to main, and a push of a release tag,
# unless every commit it counts has a green stamp from scripts/gate-commit.sh,
# which ran the whole gate on that commit's own archive. A push to any other
# ref needs no stamp: what it sends reaches main only through a pull request,
# whose checks run the gate. The destination decides, so a branch pushed under
# the name main is a push to main.
#
# For main the commits counted are those past the remote's tip. For a main the
# remote does not hold yet it is every commit, since what the remote holds on
# other branches was never gated. For a v* tag it is the commit the tag names:
# a release is cut from a commit that was gated cold. A line git did not write,
# or a commit list git cannot give, refuses the push.
#
#   ln -s ../../scripts/pre-push.sh .git/hooks/pre-push
set -euo pipefail

refuse() {
  printf 'pre-push: %s; nothing pushed\n' "$*" >&2
  exit 1
}

# git names the destination remote in $1, or repeats its URL there when the
# push names no remote.
remote="${1:-}"
if [[ -z "${remote}" || "${remote}" == *[\*\?\[]* ]]; then
  refuse "no destination remote named, or one git would read as a pattern: $(printf '%q' "${remote}")"
fi

stamps="$(git rev-parse --git-common-dir)/gate-green"
sha_shape='^([0-9a-f]{40}|[0-9a-f]{64})$'
zero_shape='^0+$'

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
judged=0

# git hands the hook one line per ref: <local ref> <local sha> <remote ref>
# <remote sha>. The local ref is the source as it was typed and may hold
# spaces; the other three cannot, so a line is read from its end.
while IFS= read -r line || [[ -n "${line}" ]]; do
  [[ -n "${line}" ]] || continue
  remote_sha="${line##* }"
  rest="${line% *}"
  remote_ref="${rest##* }"
  rest="${rest% *}"
  local_sha="${rest##* }"
  if [[ "${rest}" != *" "* || "${remote_ref}" != refs/* ||
    ! "${local_sha}" =~ ${sha_shape} || ! "${remote_sha}" =~ ${sha_shape} ]]; then
    refuse "a line git did not write: $(printf '%q' "${line}")"
  fi
  local_ref="${rest% *}"

  case "${remote_ref}" in
    refs/heads/main | refs/tags/v*) ;;
    *) continue ;;
  esac
  [[ ! "${local_sha}" =~ ${zero_shape} ]] || continue # a deletion sends no commit
  judged=$((judged + 1))

  # The exit status, not an empty list, tells "nothing to send" from a list
  # git could not give.
  if [[ "${remote_ref}" == refs/tags/* ]]; then
    sent="$(git rev-parse --verify --quiet "${local_sha}^{commit}")" ||
      refuse "${local_ref} names no commit for ${remote_ref}"
  elif [[ "${remote_sha}" =~ ${zero_shape} ]]; then
    sent="$(git rev-list "${local_sha}")" ||
      refuse "the commits ${local_ref} would send to ${remote} could not be listed"
  else
    sent="$(git rev-list "${remote_sha}..${local_sha}")" ||
      refuse "the commits ${local_ref} would send to ${remote} could not be listed"
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

if [[ ${judged} -eq 0 ]]; then
  printf 'pre-push: nothing sent to main and no release tag; no stamp required\n' >&2
  exit 0
fi
if [[ ${missing} -ne 0 ]]; then
  refuse "${missing} of ${checked} commit(s) ungated"
fi
printf 'pre-push: %d commit(s), each gated green on its own archive\n' "${checked}" >&2
