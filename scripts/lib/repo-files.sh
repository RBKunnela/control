#!/usr/bin/env bash
# Shared file enumeration: `git ls-files` in a git work tree; in an export
# scripts/gate-commit.sh made, the commit's own file list it names in
# REPO_FILES_LIST; anywhere else a find that mirrors .gitignore by hand. The
# fallback is what lets the gate run in a staged copy with no .git, so it is
# kept and has to be kept in step with .gitignore.
#
# A script that sources this file puts `# shellcheck source-path=SCRIPTDIR` on
# line 2, before its first command. Only there does the directive cover the
# whole file, so that `shellcheck -x` resolves `source=lib/repo-files.sh`
# against the script's directory; anywhere later it covers one command, and
# `make check-shell` fails with SC1091.

# Resolved once at source time (not inside a function), so a caller that
# sources this file and then `cd`s elsewhere still resolves the same root.
# BASH_SOURCE is bash-only: a shell that tolerates this file's syntax without
# actually being bash (zsh, notably) leaves it empty, which would otherwise
# make repo_root silently resolve two directories above an arbitrary cwd
# instead of the repository root. Detect that with $BASH_VERSION, which only
# bash sets, and leave _REPO_FILES_SH_DIR empty rather than guess; repo_root
# below checks it and fails loudly instead of proceeding on a guess.
if [ -n "${BASH_VERSION:-}" ]; then
  _REPO_FILES_SH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
else
  _REPO_FILES_SH_DIR=""
fi

repo_root() {
  if [ -z "${_REPO_FILES_SH_DIR:-}" ]; then
    printf 'repo_files: source this file from bash; refusing to guess the repository root\n' >&2
    return 1
  fi
  # scripts/lib -> scripts -> repository root: two levels up from this file.
  (cd "${_REPO_FILES_SH_DIR}/../.." >/dev/null 2>&1 && pwd)
}

# repo_is_work_tree
# True when the repository root is a git work tree, where repo_files asks git;
# false in a tree with no .git, where it falls back to find.
repo_is_work_tree() {
  local root
  root="$(repo_root)" || return 1
  git -C "${root}" rev-parse --is-inside-work-tree >/dev/null 2>&1
}

# _repo_files_export root
# Succeeds for a tree with no .git, the one kind of tree the non-git listings
# describe. A root holding .git that git cannot read as a work tree, git being
# missing or the repository broken, fails rather than falling back to them.
_repo_files_export() {
  if [[ -e "$1/.git" ]]; then
    printf 'repo_files: %s holds .git, but git cannot list it as a work tree\n' "$1" >&2
    return 1
  fi
}

# _repo_files_find root
# Walks the tree with find for the no-git-yet fallback. The exclusions mirror
# .gitignore by hand; keep the two in sync when either changes. Local material
# is ignored through .git/info/exclude, which only a work tree has, so this
# walk names none of it. Fails, having printed nothing, when find does: a walk
# that stopped part way is no listing.
_repo_files_find() {
  local root="$1" raw path
  raw="$(mktemp)" || return 1
  # Dot-directories are pruned generically rather than by name, so this
  # file does not have to name the harness tooling directory to exclude
  # it. .github is a project directory and is the one named exception.
  # -mindepth 1 keeps the rule from matching the start point itself (its
  # own basename is a single dot, which would otherwise prune the whole
  # walk before it begins).
  if ! (
    cd "${root}" &&
      find . -mindepth 1 \( \
          \( -type d -name '.*' ! -name '.github' \) -o \
          -path ./bin -o -path ./dist -o -path ./coverage -o \
          -path ./node_modules \
        \) -prune -o -type f \
          ! -name '.DS_Store' \
          ! -name '*.out' \
          ! -name '*.test' \
          ! -name '*.pyc' \
          ! -name '.env' \
          ! \( -name '.env.*' ! -name '.env.example' \) \
          ! -name 'go.work' \
          ! -name 'go.work.sum' \
          ! -path ./AGENTS.local.md \
          ! \( -path './bench/results/*' ! -path ./bench/results/.keep \
            ! \( -name '[0-9]*T[0-9]*Z-*-*.txt' ! -path './bench/results/*/*' \) \) \
          -print0
  ) >"${raw}"; then
    rm -f "${raw}"
    printf 'repo_files: walking %s with find failed\n' "${root}" >&2
    return 1
  fi
  while IFS= read -r -d '' path; do
    printf '%s\0' "${path#./}"
  done <"${raw}"
  rm -f "${raw}"
}

# _repo_files_every root
# Every file and link under root but .git, NUL-delimited, with no .gitignore
# mirror: what repo_stage copies from a tree with no .git. Fails, having
# printed nothing, when find does.
_repo_files_every() {
  local root="$1" raw path
  raw="$(mktemp)" || return 1
  if ! (cd "${root}" && find . -mindepth 1 -name .git -prune -o \( -type f -o -type l \) -print0) >"${raw}"; then
    rm -f "${raw}"
    printf 'repo_files: walking %s with find failed\n' "${root}" >&2
    return 1
  fi
  while IFS= read -r -d '' path; do
    printf '%s\0' "${path#./}"
  done <"${raw}"
  rm -f "${raw}"
}

# _repo_files_commit_list root
# Succeeds when REPO_FILES_LIST names the list of files of the commit exported
# at root, which scripts/gate-commit.sh writes from `git ls-tree` and pairs with
# REPO_FILES_LIST_ROOT, the export's physical path. A tree staged elsewhere from
# that export does not match the root and keeps the find fallback.
_repo_files_commit_list() {
  local root="$1"
  [[ -n "${REPO_FILES_LIST:-}" && -n "${REPO_FILES_LIST_ROOT:-}" ]] || return 1
  [[ "$(cd "${root}" >/dev/null 2>&1 && pwd -P)" == "${REPO_FILES_LIST_ROOT}" ]]
}

# _repo_files_filter pattern ...
# Reads NUL-delimited paths on stdin, writes the NUL-delimited matches on
# stdout: same pathspec rule as `git ls-files -- <pattern>`. A pattern
# containing "/" matches the whole relative path. A pattern with no "/" but
# with a glob metacharacter (*, ?, [) matches the basename. A plain literal
# with no "/" and no metacharacter matches the whole relative path exactly -
# it does not search every directory for a file of that name.
_repo_files_filter() {
  local path base pattern matched target
  while IFS= read -r -d '' path; do
    matched=0
    base="${path##*/}"
    for pattern in "$@"; do
      case "${pattern}" in
        */*)      target="${path}" ;;
        *[*?\[]*) target="${base}" ;;
        *)        target="${path}" ;;
      esac
      # Unquoted on purpose: pattern is matched as a glob, not literally.
      # shellcheck disable=SC2254
      case "${target}" in
        ${pattern}) matched=1 ;;
      esac
      [[ ${matched} -eq 1 ]] && break
    done
    [[ ${matched} -eq 1 ]] && printf '%s\0' "${path}"
  done
}

# repo_files [pattern ...]
# Prints repository-relative paths, one per line, sorted. No arguments prints
# every file; patterns filter as described in _repo_files_filter above.
# shellcheck disable=SC2120 # the patterns are optional; repo_stage passes none
repo_files() {
  local root
  root="$(repo_root)" || return 1

  local -a paths=()
  local path raw listed src

  # Each listing goes to a file first and its status is checked before a path
  # is read: a listing that fails part way would otherwise read as a shorter,
  # successful one, since a loop over a process substitution never sees the
  # command's exit status.
  raw="$(mktemp)" || return 1
  listed="$(mktemp)" || { rm -f "${raw}"; return 1; }
  src="${listed}"
  if repo_is_work_tree; then
    # --cached on its own lists tracked files only, which would make every file
    # a change adds invisible to check-brand, check-sizes and fmt-check until
    # someone commits it: three gates reporting green over a file they never
    # opened. --others --exclude-standard adds the untracked files git would not
    # ignore, so the gates see the working tree a reviewer sees. The two sets
    # are disjoint, so nothing is listed twice.
    if ! git -C "${root}" ls-files -z --cached --others --exclude-standard -- "$@" >"${listed}"; then
      rm -f "${raw}" "${listed}"
      printf 'repo_files: git ls-files failed in %s\n' "${root}" >&2
      return 1
    fi
  else
    _repo_files_export "${root}" || { rm -f "${raw}" "${listed}"; return 1; }
    if _repo_files_commit_list "${root}"; then
      if [[ ! -f "${REPO_FILES_LIST}" ]] || ! cat "${REPO_FILES_LIST}" >"${raw}"; then
        rm -f "${raw}" "${listed}"
        printf 'repo_files: the commit file list %s cannot be read\n' "${REPO_FILES_LIST}" >&2
        return 1
      fi
    elif ! _repo_files_find "${root}" >"${raw}"; then
      rm -f "${raw}" "${listed}"
      return 1
    fi
    if [[ $# -gt 0 ]]; then
      _repo_files_filter "$@" <"${raw}" >"${listed}"
    else
      src="${raw}"
    fi
  fi
  while IFS= read -r -d '' path; do
    paths+=("${path}")
  done <"${src}"
  rm -f "${raw}" "${listed}"

  # bash 3.2 (macOS default /bin/bash) raises "unbound variable" on
  # "${paths[@]}" for a truly empty array under `set -u`; return before
  # expanding it rather than assume a caller's shell has the bash 4.4 fix.
  if [[ ${#paths[@]} -eq 0 ]]; then
    return 0
  fi

  for path in "${paths[@]}"; do
    if [[ "${path}" == *[[:space:]]* ]]; then
      printf 'repo_files: path contains whitespace or a newline, refusing: %q\n' "${path}" >&2
      return 1
    fi
    # git ls-files --cached still lists a tracked file that has been deleted
    # from the work tree. Handing that path to a gate produces a confusing
    # "no such file" from whichever tool ran; refuse here and name it, rather
    # than dropping it and shortening the list a gate believes it checked.
    if [[ ! -e "${root}/${path}" ]]; then
      printf 'repo_files: listed path is not on disk: %s\n' "${path}" >&2
      return 1
    fi
  done

  printf '%s\n' "${paths[@]}" | LC_ALL=C sort
}

# repo_stage <destination>
# Copies the files the repository holds into <destination>, an existing
# directory, keeping their relative paths, and prints how many it copied. In a
# git work tree those are what repo_files lists. In a tree with no .git they are
# every file but .git: such a tree is an export, which holds only what the
# repository tracks, and repo_files' .gitignore mirror would drop a tracked file
# whose name it matches. A force-added .env is such a file, and the one a secret
# scan exists to read. A gate that must judge the repository rather than the
# directory around it runs over this copy.
repo_stage() {
  local dest="${1:-}" root list="" path work count
  if [[ -z "${dest}" || ! -d "${dest}" ]]; then
    printf 'repo_stage: destination %q is not a directory\n' "${dest}" >&2
    return 1
  fi
  root="$(repo_root)" || return 1
  if repo_is_work_tree; then
    list="$(repo_files)" || return 1
  else
    _repo_files_export "${root}" || return 1
    local every
    every="$(mktemp)" || return 1
    if ! _repo_files_every "${root}" >"${every}"; then
      rm -f "${every}"
      return 1
    fi
    local spaced=""
    while IFS= read -r -d '' path; do
      if [[ "${path}" == *[[:space:]]* ]]; then
        spaced="${path}"
        break
      fi
      list+="${path}"$'\n'
    done <"${every}"
    rm -f "${every}"
    if [[ -n "${spaced}" ]]; then
      printf 'repo_stage: path contains whitespace or a newline, refusing: %q\n' "${spaced}" >&2
      return 1
    fi
    list="${list%$'\n'}"
  fi
  if [[ -z "${list}" ]]; then
    printf 'repo_stage: no file to stage\n' >&2
    return 1
  fi
  work="$(mktemp -d)" || return 1
  # "./" in front of every path, so tar never reads a name beginning with "-"
  # as an option. COPYFILE_DISABLE stops macOS tar from adding "._" files for
  # extended attributes, which would be files the repository does not hold.
  printf '%s\n' "${list}" | sed 's|^|./|' >"${work}/list"
  count="$(wc -l <"${work}/list" | tr -d ' ')"
  if ! COPYFILE_DISABLE=1 tar -cf "${work}/files.tar" -C "${root}" -T "${work}/list" ||
    ! tar -xf "${work}/files.tar" -C "${dest}"; then
    rm -rf "${work}"
    printf 'repo_stage: copying %s file(s) into %s failed\n' "${count}" "${dest}" >&2
    return 1
  fi
  rm -rf "${work}"
  printf '%s\n' "${count}"
}
