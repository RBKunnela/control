#!/usr/bin/env bash
# Makes the draft release the release workflow uploads into, before anything
# is built, and proves both GitHub hosts serve it: the release list, where
# goreleaser looks for it, and the upload host, with a probe asset that is
# removed again. goreleaser takes the draft as its own (.goreleaser.yaml:
# use_existing_draft) by its name alone, so <name> is what goreleaser's
# name_template renders. Run by the release workflow only.
#
#   scripts/draft-release.sh <tag> <commit> <name>
#
# Prints the draft's id. A release for the tag, or a draft of that name for
# any tag, refuses the script: goreleaser would take the first draft of the
# name, and Publish publishes only the one draft this run made. Whatever the
# script leaves after a refusal is a draft at most; RELEASING.md says what to
# do with it.
set -euo pipefail

die() {
  printf 'draft-release: %s\n' "$*" >&2
  exit 1
}

# How often, and how long apart, each host is asked before the draft is given
# up: a minute in all.
tries=12
pause=5

[[ $# -eq 3 ]] || die "usage: scripts/draft-release.sh <tag> <commit> <name>"
tag="$1"
commit="$2"
name="$3"
[[ "${tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || die "${tag} is not a release tag"
[[ "${commit}" =~ ^[0-9a-f]{40}$ ]] || die "${commit} is not a commit"
[[ -n "${name}" && "${name}" != *$'\n'* ]] || die "the name is empty or holds a newline"
[[ -n "${GITHUB_REPOSITORY:-}" ]] || die "GITHUB_REPOSITORY is not set"
repo="${GITHUB_REPOSITORY}"
command -v jq >/dev/null 2>&1 || die "jq is not on PATH"

# A tag with a hyphen is a pre-release, as goreleaser's prerelease: auto reads it.
prerelease=false
[[ "${tag}" == *-* ]] && prerelease=true

# list_releases prints every release of the repository as one JSON array.
list_releases() {
  gh api "repos/${repo}/releases?per_page=100" --paginate | jq -s 'add // []'
}

releases="$(list_releases)" || die "the releases of ${repo} could not be listed"
existing="$(jq -r --arg tag "${tag}" --arg name "${name}" \
  '.[] | select(.tag_name == $tag or (.draft and .name == $name)) | "\(.id) (\(.tag_name), draft: \(.draft))"' <<<"${releases}")"
[[ -z "${existing}" ]] ||
  die "a release for ${tag} or a draft named ${name} exists already: ${existing//$'\n'/, }"

id="$(gh api --method POST "repos/${repo}/releases" \
  -f "tag_name=${tag}" -f "target_commitish=${commit}" -f "name=${name}" \
  -F draft=true -F "prerelease=${prerelease}" --jq .id)" || die "the draft for ${tag} could not be made"
[[ "${id}" =~ ^[0-9]+$ ]] || die "the draft's id is not a number: ${id}"

# The list, not the release by its id, is what goreleaser reads, so the draft
# counts as served only once the list names it, and it alone, under the name.
served=false
for _ in $(seq "${tries}"); do
  ids="$(list_releases 2>/dev/null | jq -r --arg name "${name}" \
    '[.[] | select(.draft and .name == $name) | .id] | map(tostring) | join(",")' 2>/dev/null || true)"
  if [[ "${ids}" == "${id}" ]]; then
    served=true
    break
  fi
  sleep "${pause}"
done
[[ "${served}" == true ]] ||
  die "the release list does not name draft ${id} alone under ${name}; delete the draft by hand"

probe="$(mktemp)"
printf 'probe\n' >"${probe}"
asset=""
for _ in $(seq "${tries}"); do
  if asset="$(gh api --method POST "https://uploads.github.com/repos/${repo}/releases/${id}/assets?name=draft-probe.txt" \
    -H 'Content-Type: text/plain' --input "${probe}" --jq .id 2>/dev/null)"; then
    break
  fi
  asset=""
  sleep "${pause}"
done
rm -f "${probe}"
[[ "${asset}" =~ ^[0-9]+$ ]] ||
  die "the upload host does not serve draft ${id} for ${tag}; delete the draft by hand"
gh api --method DELETE "repos/${repo}/releases/assets/${asset}" >/dev/null ||
  die "the probe asset ${asset} on draft ${id} could not be removed; delete the draft by hand"
left="$(gh api "repos/${repo}/releases/${id}/assets?per_page=100" --paginate --jq '.[].name' | paste -sd, -)" ||
  die "the assets of draft ${id} could not be listed; delete the draft by hand"
[[ -z "${left}" ]] || die "draft ${id} holds assets before the build: ${left}; delete the draft by hand"
printf '%s\n' "${id}"
