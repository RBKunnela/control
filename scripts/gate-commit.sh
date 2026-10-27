#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Runs the whole gate, cold, over exactly what a commit holds: `git archive` of
# the commit into a scratch directory, never the working tree or the index,
# which can differ from the commit by a file staged, deleted or left out. After
# make quality it fuzzes every target, which pull requests leave to the nightly
# run (ADR-0062), so a release commit is fuzzed before it is tagged. A
# green run leaves a stamp under the repository's git directory that
# scripts/pre-push.sh requires before the commit is pushed to main or tagged as
# a release.
#
# Before the gate it refuses an archive that is not the commit: every path,
# mode and blob `git ls-tree` names must be extracted as it is, since an
# export-ignore or export-subst attribute changes what `git archive` writes.
# The gate's file scans then read the commit's own file list (REPO_FILES_LIST
# in scripts/lib/repo-files.sh), not a find over the export. The installed
# tools are compared with the commit's own pins by its scripts/bootstrap.sh
# --check, which installs nothing; a mismatch means no stamp. It compares the
# commit's api/proto with the latest v* tag before the commit under the tag's
# own buf.yaml, as CI's proto-breaking job does for a push, so the commit cannot
# choose the rules it is judged by; a break, or no tag to compare with, means no
# stamp. Replace refs are ignored: push sends the commit's own objects, so the
# gate reads those. make runs in an emptied environment that keeps only the
# locations and the network settings listed below, with GO=go, GOFLAGS empty,
# GOENV=off and no MAKEFLAGS, so the caller's environment and go env cannot
# narrow what the gate runs. PATH is kept and trusted: it picks git, buf, make,
# go and the tools make calls.
#
#   scripts/gate-commit.sh [<commit>]    # HEAD by default
set -euo pipefail
export GIT_NO_REPLACE_OBJECTS=1

die() {
  printf 'gate-commit: %s\n' "$*" >&2
  exit 1
}

[[ $# -le 1 ]] || die "name at most one commit"
# git archive run in a subdirectory holds only that subdirectory.
top="$(git rev-parse --show-toplevel)" || die "not inside a work tree"
cd "${top}"
sha="$(git rev-parse --verify --quiet "${1:-HEAD}^{commit}")" || die "${1:-HEAD} names no commit"
gitdir="$(git rev-parse --path-format=absolute --git-common-dir)"
stamps="${gitdir}/gate-green"
mkdir -p "${stamps}"
rm -f "${stamps:?}/${sha:?}"
log="${stamps}/${sha}.log"
: >"${log}"

work="$(mktemp -d)"
trap 'rm -rf "${work:?}"' EXIT
tree="${work}/tree"
mkdir "${tree}"
tree="$(cd "${tree}" && pwd -P)"
git archive "${sha}" | tar -x -C "${tree}"

clean=(env -i)
for v in HOME PATH TMPDIR USER LOGNAME LANG TERM \
  GOPATH GOMODCACHE GOCACHE GOLANGCI_LINT_CACHE \
  HTTP_PROXY HTTPS_PROXY NO_PROXY http_proxy https_proxy no_proxy SSL_CERT_FILE SSL_CERT_DIR; do
  if [[ -n "${!v+x}" ]]; then
    clean+=("${v}=${!v}")
  fi
done
clean+=(GIT_NO_REPLACE_OBJECTS=1 GOENV=off GOFLAGS= "REPO_FILES_LIST=${work}/files" "REPO_FILES_LIST_ROOT=${tree}")

# The commit as git holds it, one "<mode> <object> <path>" line per entry, and
# its NUL-delimited file list for repo_files.
git ls-tree -r -z --full-tree "${sha}" >"${work}/ls-tree"
: >"${work}/files"
: >"${work}/want"
while IFS= read -r -d '' entry; do
  meta="${entry%%$'\t'*}"
  path="${entry#*$'\t'}"
  [[ "${path}" != *$'\n'* ]] || die "${sha} holds a path with a newline, which this gate cannot compare"
  read -r mode _ object <<<"${meta}"
  printf '%s %s %s\n' "${mode}" "${object}" "${path}" >>"${work}/want"
  printf '%s\0' "${path}" >>"${work}/files"
done <"${work}/ls-tree"
[[ -s "${work}/want" ]] || die "${sha} lists no file"

# The archive as extracted, in the same shape. A submodule is an empty
# directory in an archive, so it is taken as git names it when it is one.
: >"${work}/got"
: >"${work}/blobs"
(cd "${tree}" && find . \( -type f -o -type l \) -print0) >"${work}/extracted" ||
  die "listing the archive of ${sha} failed; nothing stamped"
while IFS= read -r -d '' path; do
  path="${path#./}"
  [[ "${path}" != *$'\n'* ]] || die "the archive of ${sha} holds a path with a newline"
  if [[ -L "${tree}/${path}" ]]; then
    object="$(printf '%s' "$(readlink "${tree}/${path}")" | git hash-object --stdin)"
    printf '120000 %s %s\n' "${object}" "${path}" >>"${work}/got"
  elif [[ -x "${tree}/${path}" ]]; then
    printf '100755 %s\n' "${path}" >>"${work}/blobs"
  else
    printf '100644 %s\n' "${path}" >>"${work}/blobs"
  fi
done <"${work}/extracted"
cut -d ' ' -f 2- "${work}/blobs" >"${work}/blob-paths"
# Each path goes in as ./path: --stdin-paths C-unquotes a line that starts with ".
sed 's|^|./|' "${work}/blob-paths" |
  (cd "${tree}" && git --git-dir="${gitdir}" hash-object --no-filters --stdin-paths) >"${work}/blob-objects"
[[ "$(wc -l <"${work}/blob-objects")" == "$(wc -l <"${work}/blobs")" ]] ||
  die "hashing the archive of ${sha} did not return one object per file"
paste -d ' ' <(cut -d ' ' -f 1 "${work}/blobs") "${work}/blob-objects" "${work}/blob-paths" >>"${work}/got"
while read -r mode object path; do
  if [[ "${mode}" == 160000 && -d "${tree}/${path}" && -z "$(ls -A "${tree}/${path}")" ]]; then
    printf '%s %s %s\n' "${mode}" "${object}" "${path}" >>"${work}/got"
  fi
done <"${work}/want"
LC_ALL=C sort -t ' ' -k 3 -o "${work}/want" "${work}/want"
LC_ALL=C sort -t ' ' -k 3 -o "${work}/got" "${work}/got"
rc=0
diff "${work}/want" "${work}/got" >"${work}/archive.diff" || rc=$?
[[ ${rc} -le 1 ]] || die "comparing the archive of ${sha} with the commit failed (diff exit ${rc}); nothing stamped"
if [[ ${rc} -eq 1 ]]; then
  cat "${work}/archive.diff" >>"${log}"
  head -n 20 "${work}/archive.diff" >&2
  die "the archive of ${sha} is not the commit (< in the commit, > in the archive); an attribute changed it; nothing stamped"
fi
printf 'gate-commit: %s: the archive holds all %s entries of the commit\n' \
  "${sha}" "$(wc -l <"${work}/want" | tr -d ' ')" | tee -a "${log}"

# The list repo_files will read in the archive must be the commit's own.
if ! listed="$(cd "${tree}" && "${clean[@]}" /bin/bash -c '. scripts/lib/repo-files.sh && repo_files' 2>&1)"; then
  printf '%s\n' "${listed}" >&2
  die "repo_files failed in the archive of ${sha}; nothing stamped"
fi
tr '\0' '\n' <"${work}/files" | LC_ALL=C sort >"${work}/files.sorted"
printf '%s\n' "${listed}" >"${work}/listed"
rc=0
diff "${work}/files.sorted" "${work}/listed" >"${work}/list.diff" || rc=$?
[[ ${rc} -le 1 ]] || die "comparing repo_files with the commit's file list failed (diff exit ${rc}); nothing stamped"
if [[ ${rc} -eq 1 ]]; then
  head -n 20 "${work}/list.diff" >&2
  die "repo_files in the archive of ${sha} does not list the commit's files; nothing stamped"
fi

printf 'gate-commit: %s: the installed tools against its pins\n' "${sha}" | tee -a "${log}"
rc=0
(cd "${tree}" && "${clean[@]}" /bin/bash scripts/bootstrap.sh --check) >>"${log}" 2>&1 || rc=$?
if [[ ${rc} -ne 0 ]]; then
  grep '^FAIL' "${log}" | tail -n 20 >&2 || true
  die "the installed tools do not match ${sha}'s pins (bootstrap --check exit ${rc}); nothing stamped"
fi

tag="$(git describe --tags --abbrev=0 --match 'v*' "${sha}^" 2>/dev/null)" ||
  die "UNKNOWN wire compatibility: no v* tag is reachable from ${sha}'s parent; nothing compared, nothing stamped"
[[ "${tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] ||
  die "UNKNOWN wire compatibility: the latest tag is not a version: ${tag}; nothing stamped"
command -v buf >/dev/null 2>&1 ||
  die "UNKNOWN wire compatibility: buf is not on PATH; nothing compared, nothing stamped"
rules="$(git show "refs/tags/${tag}:buf.yaml")" && [[ -n "${rules}" ]] ||
  die "UNKNOWN wire compatibility: ${tag} holds no buf.yaml to take the breaking rules from; nothing stamped"
printf 'gate-commit: %s: buf breaking of api/proto against %s under its buf.yaml\n' "${sha}" "${tag}" | tee -a "${log}"
rc=0
(cd "${tree}" && "${clean[@]}" buf breaking --config "${rules}" --against "${gitdir}#tag=${tag}") >>"${log}" 2>&1 || rc=$?
if [[ ${rc} -ne 0 ]]; then
  tail -n 20 "${log}" >&2
  die "${sha} breaks, or could not be compared with, the wire contract of ${tag} (buf exit ${rc}); nothing stamped"
fi

printf 'gate-commit: %s: cold make quality on its archive; log %s\n' "${sha}" "${log}"
rc=0
(cd "${tree}" && "${clean[@]}" go clean -testcache && "${clean[@]}" make GO=go quality) >>"${log}" 2>&1 || rc=$?
last="$(tail -n 1 "${log}")"
if [[ ${rc} -ne 0 || "${last}" != "quality: green" ]]; then
  grep -nE '^(FAIL|--- FAIL)|Error [0-9]|panic:|^test-report:' "${log}" | head -n 20 >&2 || true
  die "${sha} is not green (exit ${rc}, last line: ${last}); nothing stamped"
fi

printf 'gate-commit: %s: every fuzz target fuzzed on its archive\n' "${sha}" | tee -a "${log}"
rc=0
(cd "${tree}" && "${clean[@]}" make GO=go fuzz-smoke) >>"${log}" 2>&1 || rc=$?
fuzzed="$(tail -n 1 "${log}")"
if [[ ${rc} -ne 0 || ! "${fuzzed}" =~ ^fuzz-smoke:\ [1-9][0-9]*\ target\(s\)\ run\ for\  ]]; then
  tail -n 20 "${log}" >&2
  die "${sha}: the fuzz run is not green (exit ${rc}, last line: ${fuzzed}); nothing stamped"
fi
printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${last}" >"${stamps}/${sha}"
printf 'gate-commit: %s green; stamped\n' "${sha}"
