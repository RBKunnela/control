#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# The secret scan and the dependency scan, over the files the repository holds
# and nothing else. Both tools walk whatever directory they are given, ignored
# and excluded directories included, so they read a staged copy, and the first
# line says how many files it holds: in a git work tree, what repo_files lists;
# in a tree with no .git, which is an export and holds only tracked files,
# every file.
#
# Neither takes a setting from the tree it scans. Each discovers files there
# that would decide its result without anyone who owns the scan seeing them:
#   gitleaks     reads scripts/gitleaks.toml rather than a .gitleaks.toml or
#                the environment, honours no gitleaks:allow comment and reads
#                no ignore list. It reads a .gitleaksignore at the root of the
#                tree it scans whatever --gitleaks-ignore-path says, so that
#                file is refused.
#   osv-scanner  reads an empty configuration rather than any osv-scanner.toml,
#                and the files .gitignore names as well.
#
# osv-scanner passes over a lockfile it cannot parse or does not recognise, so
# its output must hold a "Scanned" line for each go.mod, uv.lock and
# package-lock.json repo_files lists, and no such file at all fails the scan.
# scripts/scan-repo-files-probe.sh is the negative control.
set -euo pipefail

_SCAN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
# shellcheck source=lib/repo-files.sh
. "${_SCAN_DIR}/lib/repo-files.sh"

die() {
  printf 'scan-repo-files: %s\n' "$*" >&2
  exit 1
}

for tool in gitleaks osv-scanner; do
  command -v "${tool}" >/dev/null 2>&1 || die "${tool} is not on PATH, so the scan cannot run"
done

lockfiles="$(repo_files go.mod '*/go.mod' uv.lock '*/uv.lock' package-lock.json '*/package-lock.json')" ||
  die "repo_files could not list the lockfiles"
[[ -n "${lockfiles}" ]] ||
  die "repo_files lists no go.mod, uv.lock or package-lock.json, so the dependency scan would read nothing"

copy="$(mktemp -d)"
no_ignore_list="$(mktemp -d)"
osv_log="$(mktemp)"
trap 'rm -rf "${copy}" "${no_ignore_list}" "${osv_log}"' EXIT
staged="$(repo_stage "${copy}")"
[[ "${staged}" -gt 0 ]] || die "repo_stage copied no files"
if repo_is_work_tree; then
  from="repo_files"
else
  from="every file of this tree, which has no .git"
fi
printf 'scan-repo-files: %s file(s) staged from %s; scanning that copy only\n' "${staged}" "${from}"

if [[ -e "${copy}/.gitleaksignore" ]]; then
  die "the repository holds .gitleaksignore, and the secret scan takes no ignore list from the tree it scans; except a finding that is not a secret in scripts/gitleaks.toml"
fi

gitleaks dir --no-banner --redact --config "${_SCAN_DIR}/gitleaks.toml" \
  --ignore-gitleaks-allow --gitleaks-ignore-path "${no_ignore_list}" "${copy}"
rc=0
osv-scanner scan source -r --no-ignore --config /dev/null "${copy}" 2>&1 | tee "${osv_log}" || rc=$?
[[ ${rc} -eq 0 ]] || die "osv-scanner exited ${rc}"

unread=""
count=0
while IFS= read -r file; do
  count=$((count + 1))
  grep -qF -- "Scanned ${copy}/${file} file " "${osv_log}" || unread+="${unread:+, }${file}"
done <<<"${lockfiles}"
[[ -z "${unread}" ]] ||
  die "osv-scanner printed no 'Scanned' line for ${unread}, so it did not read every lockfile repo_files lists"
# A file read as holding no package was not understood, listed above or not:
# every advisory against what it pins would go unreported.
empty="$(grep -E '^Scanned .* file and found 0 packages?$' "${osv_log}" |
  sed -e "s|^Scanned ${copy}/||" -e 's| file and found 0 packages*$||' | LC_ALL=C sort | tr '\n' ' ')" || true
[[ -z "${empty}" ]] ||
  die "osv-scanner found no package in ${empty% }, so it read none of what that file pins"
printf 'scan-repo-files: osv-scanner read each of the %d lockfile(s) repo_files lists: %s\n' \
  "${count}" "$(printf '%s' "${lockfiles}" | tr '\n' ' ')"
