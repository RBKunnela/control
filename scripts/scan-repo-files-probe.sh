#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# The negative control of scripts/scan-repo-files.sh. It stages the script,
# its gitleaks.toml and scripts/lib/repo-files.sh in a tree with no .git, so
# the scan reads every file of that tree, and each case must pass or fail as
# named and say why:
#   pass     a tree holding one go.mod, both real scanners run, the go.mod
#            named as read; four lockfiles of the three kinds, nested ones
#            among them, each named by a stand-in scanner
#   refused  a planted secret, which the real gitleaks finds; a lockfile the
#            real osv-scanner read whose "Scanned" line a stand-in drops or
#            renames; each of the four lockfiles left unread in turn; a tree
#            with no lockfile; a scanner that fails; a .gitleaksignore; and
#            gitleaks or osv-scanner missing from PATH
# The real scanners need gitleaks and osv-scanner on PATH, and osv-scanner
# asks the advisory database over the network, as `make security` does.
set -euo pipefail

_PROBE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
# shellcheck source=lib/repo-files.sh
. "${_PROBE_DIR}/lib/repo-files.sh"

die() {
  printf 'scan-repo-files-probe: %s\n' "$*" >&2
  exit 1
}

root="$(repo_root)"
script="${root}/scripts/scan-repo-files.sh"
for file in "${script}" "${root}/scripts/gitleaks.toml" "${root}/scripts/lib/repo-files.sh"; do
  [[ -f "${file}" ]] || die "${file} is missing"
done
for tool in gitleaks osv-scanner; do
  command -v "${tool}" >/dev/null 2>&1 || die "${tool} is not on PATH, so the probe cannot run; make bootstrap installs it"
done
real_gitleaks="$(command -v gitleaks)"
real_osv="$(command -v osv-scanner)"
# The go line of the root module, whose standard library the real scan of
# this repository already reads.
goline="$(grep -m 1 '^go [0-9]' "${root}/go.mod")" || die "no go directive in ${root}/go.mod"

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
tree="${tmp}/tree"
mkdir -p "${tmp}/standin" "${tmp}/only-gitleaks" "${tmp}/only-osv"
ln -s "${real_gitleaks}" "${tmp}/only-gitleaks/gitleaks"
ln -s "${real_osv}" "${tmp}/only-osv/osv-scanner"

# The stand-in scanner: STUB_OSV=drop or rename runs the real one and drops or
# renames the "Scanned" line of STUB_FILE; list prints one "Scanned" line for
# each of STUB_SCANNED, of no package for those also in STUB_EMPTY, and reads
# nothing; fail exits 1.
cat >"${tmp}/standin/osv-scanner" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
dir="${!#}"
case "${STUB_OSV}" in
  drop) "${REAL_OSV}" "$@" | grep -vF -- "/${STUB_FILE} file" ;;
  rename) "${REAL_OSV}" "$@" | sed "s|/${STUB_FILE} file|/elsewhere/${STUB_FILE} file|" ;;
  list)
    printf 'Scanning dir %s\n' "${dir}"
    for f in ${STUB_SCANNED}; do
      found="1 package"
      [[ " ${STUB_EMPTY:-} " != *" ${f} "* ]] || found="0 packages"
      printf 'Scanned %s/%s file and found %s\n' "${dir}" "${f}" "${found}"
    done
    printf 'No issues found\n'
    ;;
  fail) echo "stand-in osv-scanner: the advisory database could not be reached" >&2; exit 1 ;;
  *) exit 64 ;;
esac
EOF
chmod 0755 "${tmp}/standin/osv-scanner"

# stage: a fresh tree holding the scan and nothing else.
stage() {
  rm -rf "${tree}"
  mkdir -p "${tree}/scripts/lib"
  cp "${script}" "${root}/scripts/gitleaks.toml" "${tree}/scripts/"
  cp "${root}/scripts/lib/repo-files.sh" "${tree}/scripts/lib/"
}

# plant <path in the tree>, the content on stdin.
plant() {
  mkdir -p "$(dirname "${tree}/$1")"
  cat >"${tree}/$1"
}

gomod() {
  printf 'module example.com/probe\n\n%s\n' "${goline}" | plant "$1"
}

cases=0
out=""
# check <name> <pass|fail> <text the output must hold> [VAR=value...]
# Runs the staged scan with the variables given; GIT_CEILING_DIRECTORIES keeps
# git from finding a repository above the scratch tree.
check() {
  local name="$1" want="$2" text="$3" rc=0
  shift 3
  out="$(env -u GIT_DIR -u GIT_WORK_TREE GIT_CEILING_DIRECTORIES="${tmp}" REAL_OSV="${real_osv}" "$@" \
    "${BASH}" "${tree}/scripts/scan-repo-files.sh" 2>&1)" || rc=$?
  if [[ "${want}" == pass && ${rc} -ne 0 ]]; then
    die "${name}: refused (exit ${rc}), want a pass:"$'\n'"${out}"
  fi
  if [[ "${want}" == fail && ${rc} -eq 0 ]]; then
    die "${name}: passed, want a refusal:"$'\n'"${out}"
  fi
  holds "${name}" "${text}"
  cases=$((cases + 1))
}

# holds <name> <text>: the last run's output holds the text.
holds() {
  [[ "${out}" == *"$2"* ]] || die "$1: the output does not say \"$2\":"$'\n'"${out}"
}

standin="PATH=${tmp}/standin:${PATH}"

stage
gomod go.mod
check "a clean tree" pass "osv-scanner read each of the 1 lockfile(s) repo_files lists: go.mod"
holds "a clean tree" "staged from every file of this tree, which has no .git"
holds "a clean tree" "no leaks found"

# Split, so that no tracked file holds the token the scan must find.
printf 'deploy with %s%s%s\n' AK IA QYLPMN5HXKRZ4VWB | plant notes/deploy.txt
check "a planted secret" fail "leaks found: 1"
rm "${tree}/notes/deploy.txt"

check "a go.mod whose line is dropped" fail "osv-scanner printed no 'Scanned' line for go.mod" \
  "${standin}" STUB_OSV=drop STUB_FILE=go.mod
check "a go.mod whose line names another file" fail "osv-scanner printed no 'Scanned' line for go.mod" \
  "${standin}" STUB_OSV=rename STUB_FILE=go.mod
check "a scanner that fails" fail "osv-scanner exited 1" "${standin}" STUB_OSV=fail

printf '' | plant .gitleaksignore
check "an ignore list in the tree" fail "the repository holds .gitleaksignore"
rm "${tree}/.gitleaksignore"

lockfiles="go.mod nested/go.mod py/uv.lock web/package-lock.json"
gomod nested/go.mod
printf 'version = 1\n' | plant py/uv.lock
printf '{"lockfileVersion": 3}\n' | plant web/package-lock.json
check "four lockfiles, each read" pass \
  "osv-scanner read each of the 4 lockfile(s) repo_files lists: go.mod nested/go.mod py/uv.lock web/package-lock.json" \
  "${standin}" STUB_OSV=list "STUB_SCANNED=${lockfiles}"
for unread in ${lockfiles}; do
  scanned=""
  for f in ${lockfiles}; do
    [[ "${f}" == "${unread}" ]] || scanned+="${f} "
  done
  check "${unread} left unread" fail "osv-scanner printed no 'Scanned' line for ${unread}," \
    "${standin}" STUB_OSV=list "STUB_SCANNED=${scanned}"
done

check "a lockfile read as holding no package" fail "osv-scanner found no package in py/uv.lock" \
  "${standin}" STUB_OSV=list "STUB_SCANNED=${lockfiles}" STUB_EMPTY=py/uv.lock
check "two empty lockfiles named in sorted order" fail "osv-scanner found no package in py/uv.lock web/package-lock.json," \
  "${standin}" STUB_OSV=list "STUB_SCANNED=web/package-lock.json py/uv.lock nested/go.mod go.mod" \
  "STUB_EMPTY=web/package-lock.json py/uv.lock"
check "a lockfile the real scanner reads as empty" fail "osv-scanner found no package in py/uv.lock web/package-lock.json,"

stage
printf 'readme\n' | plant README.md
check "a tree with no lockfile" fail "repo_files lists no go.mod, uv.lock or package-lock.json"

stage
gomod go.mod
for missing in gitleaks osv-scanner; do
  PATH=/usr/bin:/bin command -v "${missing}" >/dev/null 2>&1 &&
    die "${missing} is in /usr/bin or /bin, so the probe cannot take it off PATH"
done
check "no gitleaks" fail "gitleaks is not on PATH" "PATH=${tmp}/only-osv:/usr/bin:/bin"
check "no osv-scanner" fail "osv-scanner is not on PATH" "PATH=${tmp}/only-gitleaks:/usr/bin:/bin"

printf 'scan-repo-files-probe: %d case(s), each passed or refused as named\n' "${cases}"
