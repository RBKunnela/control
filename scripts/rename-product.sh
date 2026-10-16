#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Renames the product across the whole tree in one pass. The old values are
# read from internal/brand/brand.go at run time, so this script carries no
# brand literal and never has to rewrite itself: a self-modifying rename is one
# bad sed away from being unrunnable, and it is unreviewable.
#
# Two invariants make the pass trustworthy:
#   1. substitution goes through per-pair sentinels, so no replacement can be
#      re-read by a later one;
#   2. every check that can be made from the arguments and the tree is made
#      before the first byte is written, because the pass rewrites the working
#      tree in place and has no rollback.
set -euo pipefail

_RENAME_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
# shellcheck source=lib/repo-files.sh
. "${_RENAME_DIR}/lib/repo-files.sh"
# shellcheck source=lib/cmd-names.sh
. "${_RENAME_DIR}/lib/cmd-names.sh"

ROOT="$(repo_root)"
BRAND_GO="${ROOT}/internal/brand/brand.go"

die() {
  printf 'rename-product: %s\n' "$*" >&2
  exit 1
}

# The placeholders are angle-bracketed and there is no worked example, because
# this file is not on the brand allowlist. A concrete example would be five
# brand literals, and the guard would flag this file the day the product is
# renamed to something that spells one of them.
usage() {
  cat >&2 <<'USAGE'
usage: scripts/rename-product.sh "<name>" <slug> <module-path> <proto-package> <image-ref>

  <name>           letters, digits, spaces and . _ + -
  <slug>           lowercase kebab-case
  <module-path>    host/owner/repo, as in the go.mod module directive
  <proto-package>  dotted, ending in a version segment
  <image-ref>      registry/owner/repo, without a tag

Derived rather than given: the environment prefix (from the slug), the
telemetry namespace (the proto package without its version segment), the proto
import path (the proto package with slashes), the command name (the slug) and
the proxy binary (from the slug's first segment).
USAGE
}

# brand_const <name>
# Prints the string literal assigned to <name> in internal/brand/brand.go.
# An unparsable constant is fatal and never defaulted: renaming from a guessed
# old value would silently corrupt the tree.
brand_const() {
  local name="$1" value
  local re="s/^[[:space:]]*${name}[[:space:]]*=[[:space:]]*\"([^\"]*)\".*\$/\1/p"
  value="$(sed -n -E "${re}" "${BRAND_GO}")"
  value="${value%%$'\n'*}"
  [[ -n "${value}" ]] || die "cannot parse ${name} from ${BRAND_GO}"
  printf '%s\n' "${value}"
}

# sed_lhs <string> / sed_rhs <string>
# Escape a literal for a sed substitution delimited by "|". The dot is the one
# that bites: unescaped, the dot in the OTel namespace also matches the hyphen
# in the slug. In both bracket sets "]" must come first to stay literal, and
# "." must not follow "[" or the bracket opens a POSIX collating symbol instead
# of a character set.
sed_lhs() {
  printf '%s' "$1" | sed -e 's/[]^$*.[|\\]/\\&/g'
}

sed_rhs() {
  printf '%s' "$1" | sed -e 's/[|\\&]/\\&/g'
}

# gateway_of <slug>
# The gateway binary is named after the slug's first segment, which is how the
# current pair of constants is built. The derivation is checked against the old
# values below rather than assumed.
gateway_of() {
  printf '%s-gateway\n' "${1%%-*}"
}

# go_pkg_of <proto-package>
# The Go package buf generates is named after the proto package's last two
# segments joined, and every hand-written import aliases it by that name. The
# proto pairs rename the package and nothing else renames the alias, so a tree
# importing the new package under the old name would compile and read wrong.
go_pkg_of() {
  local rest="${1%.*}"
  printf '%s%s\n' "${rest##*.}" "${1##*.}"
}

[[ $# -eq 5 ]] || { usage; exit 2; }

new_name="$1"
new_slug="$2"
new_module="$3"
new_proto_pkg="$4"
new_image="$5"

[[ -f "${BRAND_GO}" ]] || die "missing ${BRAND_GO}"

# The name ends up inside a Go string literal, a YAML scalar and Markdown. A
# quote or a backslash there produces a file that no longer parses, and the
# rest of the pass would still report success.
[[ "${new_name}" =~ ^[A-Za-z0-9][A-Za-z0-9\ ._+-]*$ ]] ||
  die "name may hold letters, digits, spaces and . _ + - only: ${new_name}"
[[ "${new_slug}" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]] ||
  die "slug must be lowercase kebab-case: ${new_slug}"
[[ "${new_module}" =~ ^[A-Za-z0-9._~-]+(/[A-Za-z0-9._~-]+)+$ ]] ||
  die "module path must look like host/owner/name: ${new_module}"
[[ "${new_proto_pkg}" =~ ^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*\.v[0-9]+$ ]] ||
  die "proto package must be dotted and end in .v<N>: ${new_proto_pkg}"
[[ "${new_image}" =~ ^[A-Za-z0-9._~:-]+(/[A-Za-z0-9._~:-]+)+$ ]] ||
  die "image reference must look like registry/owner/name: ${new_image}"

old_name="$(brand_const Name)"
old_slug="$(brand_const Slug)"
old_cli="$(brand_const CLI)"
old_python="$(brand_const PythonPackage)"
old_gateway="$(brand_const Gateway)"
old_env_prefix="$(brand_const EnvPrefix)"
old_otel="$(brand_const OTelNamespace)"
old_proto_pkg="$(brand_const ProtoPackage)"
old_module="$(brand_const ModulePath)"
old_image="$(brand_const Image)"

# Derived, so the caller cannot desynchronise them from the five arguments.
new_env_prefix="$(printf '%s' "${new_slug}" | tr 'a-z-' 'A-Z_')_"
new_otel="${new_proto_pkg%.*}"
new_proto_path="$(printf '%s' "${new_proto_pkg}" | tr '.' '/')"
old_proto_path="$(printf '%s' "${old_proto_pkg}" | tr '.' '/')"
new_gateway="$(gateway_of "${new_slug}")"
new_cli="${new_slug}"
new_python="$(printf '%s' "${new_slug}" | tr '-' '_')"
[[ "${new_python}" =~ ^[a-z][a-z0-9_]*$ ]] ||
  die "the slug gives the Python package name ${new_python}, which must start with a letter"
old_go_pkg="$(go_pkg_of "${old_proto_pkg}")"
new_go_pkg="$(go_pkg_of "${new_proto_pkg}")"

# Two constants are derived rather than given, so the derivation is checked
# against the values in the file. Guessing either would leave the old name in
# the tree, which is exactly the failure this script exists to prevent.
[[ "${old_gateway}" == "$(gateway_of "${old_slug}")" ]] ||
  die "Gateway is ${old_gateway}, not $(gateway_of "${old_slug}"); rename it by hand first"
[[ "${old_cli}" == "${old_slug}" ]] ||
  die "CLI is ${old_cli} and Slug is ${old_slug}; rename CLI by hand first"
[[ "${old_python}" == "$(printf '%s' "${old_slug}" | tr '-' '_')" ]] ||
  die "PythonPackage is ${old_python}, not ${old_slug} with underscores; rename it by hand first"

# gomod_module
# Prints the path of go.mod's one module directive. go.mod is what the
# toolchain reads, and ModulePath only mirrors it: were the two to disagree, the
# module pair below would match nothing in go.mod or in any import, the pass
# would rewrite everything else, and the summary would still print the module
# as renamed.
gomod_module() {
  local found
  found="$(sed -n -E 's/^module[[:space:]]+"?([^"[:space:]]+)"?[[:space:]]*(\/\/.*)?$/\1/p' "${ROOT}/go.mod")"
  [[ -n "${found}" && "${found}" != *$'\n'* ]] ||
    die "go.mod does not hold exactly one module directive"
  printf '%s\n' "${found}"
}
current_module="$(gomod_module)"
[[ "${current_module}" == "${old_module}" ]] ||
  die "go.mod declares module ${current_module} and brand.go says ${old_module}; make them agree first"

# Each pair's search string is replaced by a sentinel first and the sentinel by
# the replacement second, so no expression ever reads another's output. Without
# it, renaming to a proto package that contains the old OTel namespace made the
# OTel pair fire on the proto pair's result and wrote a doubled segment, while
# the summary below still printed the requested value.
# The stem is what the tree is scanned for, so a document that merely explains
# this mechanism is caught; the PID makes the sentinel itself unique per run.
sentinel_stem='@@rename-product-'
sentinel_prefix="${sentinel_stem}$$-"
pair_from=()
pair_to=()

add_pair() {
  local from="$1" to="$2"
  if [[ "${from}" == "${to}" ]]; then
    return 0
  fi
  pair_from+=("${from}")
  pair_to+=("${to}")
}

# Longest and most specific first: within the sentinel pass, an earlier pair
# consumes text that a later, shorter pair would otherwise match.
# The module and image pairs match the full old value, so an image that moves
# between registries (ghcr.io to quay.io, say) is renamed only if the whole
# reference is given as the argument. That is the intended behaviour.
add_pair "${old_module}" "${new_module}"
add_pair "${old_proto_pkg}" "${new_proto_pkg}"
# The slashed form matters on its own: .proto files import each other by path,
# and missing it leaves a tree that does not generate.
add_pair "${old_proto_path}" "${new_proto_path}"
# The Go package alias, for the reason given at go_pkg_of.
add_pair "${old_go_pkg}" "${new_go_pkg}"
add_pair "${old_image}" "${new_image}"
add_pair "${old_env_prefix}" "${new_env_prefix}"
add_pair "${old_otel}" "${new_otel}"
# Before the slug pair, not after it: a single-segment slug is a prefix of the
# proxy binary name, so the slug pair would consume it first and phase two
# would then expand it to the wrong binary name.
add_pair "${old_gateway}" "${new_gateway}"
add_pair "${old_name}" "${new_name}"
add_pair "${old_slug}" "${new_slug}"
add_pair "${old_python}" "${new_python}"

[[ ${#pair_from[@]} -gt 0 ]] || die "new values match the current brand, nothing to do"

sed_args=()
idx=0
while [[ ${idx} -lt ${#pair_from[@]} ]]; do
  # The sentinel alphabet is @, -, digits: none is a sed metacharacter and none
  # is the "|" delimiter, so it needs no escaping on either side.
  sentinel="${sentinel_prefix}${idx}@@"
  # Against every search string, not only this pair's: a search string shaped
  # like another index's sentinel tail would let a later phase-one expression
  # eat an earlier one's sentinel.
  other=0
  while [[ ${other} -lt ${#pair_from[@]} ]]; do
    case "${sentinel}" in
      *"${pair_from[${other}]}"*) die "sentinel ${sentinel} contains the search string ${pair_from[${other}]}" ;;
    esac
    other=$((other + 1))
  done
  case "${pair_to[${idx}]}" in
    *"${sentinel_stem}"*) die "replacement contains the sentinel stem" ;;
  esac
  sed_args+=(-e "s|$(sed_lhs "${pair_from[${idx}]}")|${sentinel}|g")
  idx=$((idx + 1))
done
idx=0
while [[ ${idx} -lt ${#pair_from[@]} ]]; do
  sed_args+=(-e "s|${sentinel_prefix}${idx}@@|$(sed_rhs "${pair_to[${idx}]}")|g")
  idx=$((idx + 1))
done

# Snapshot the listing before editing, so a *.bak written mid-pass can never
# enter the list and so a lane adding files alongside cannot extend it.
files="$(repo_files)"

# Everything below this line up to the pass is a pre-flight check. All of it is
# decidable from the arguments and the current tree, and none of it has written
# anything yet.
# The files the pass will edit, built once so the sentinel scan below and the
# pass itself cannot disagree about what is in scope. api/gen is regenerated
# and LICENSE is never edited.
editable=""
while IFS= read -r rel; do
  [[ -n "${rel}" ]] || continue
  case "${rel}" in
    api/gen/* | LICENSE) continue ;;
  esac
  editable="${editable}${rel}"$'\n'
done <<< "${files}"
[[ -n "${editable}" ]] || die "repo_files listed no editable files"

# This script holds the stem in its own source and is the only file allowed to.
# Anywhere else in scope it is a real collision: phase two would rewrite it.
self_rel="${_RENAME_DIR#"${ROOT}/"}/${BASH_SOURCE[0]##*/}"
present="$(cd "${ROOT}" && printf '%s' "${editable}" | grep -vxF -- "${self_rel}" |
  tr '\n' '\0' | xargs -0 grep -lF -- "${sentinel_stem}" 2>/dev/null || true)"
[[ -z "${present}" ]] || die "sentinel stem already in the tree: ${present}"

if [[ "${old_proto_path}" != "${new_proto_path}" ]]; then
  # A path nested inside the other cannot be reached by mv, and mv would only
  # say so after the whole tree had been rewritten. Both are decidable here.
  case "${new_proto_path}/" in
    "${old_proto_path}/"*)
      die "new proto path ${new_proto_path} nests inside the old one ${old_proto_path}" ;;
  esac
  case "${old_proto_path}/" in
    "${new_proto_path}/"*)
      die "old proto path ${old_proto_path} nests inside the new one ${new_proto_path}" ;;
  esac
  if [[ -d "${ROOT}/api/proto/${old_proto_path}" && -e "${ROOT}/api/proto/${new_proto_path}" ]]; then
    die "api/proto/${new_proto_path} already exists; move it aside first"
  fi
fi

python_src="${ROOT}/clients/python/src"
if [[ "${old_python}" != "${new_python}" && -d "${python_src}/${old_python}" &&
  -e "${python_src}/${new_python}" ]]; then
  die "clients/python/src/${new_python} already exists; move it aside first"
fi

cmd_renames=()
if [[ -d "${ROOT}/cmd" ]]; then
  for dir in "${ROOT}"/cmd/*; do
    [[ -d "${dir}" ]] || continue
    base="${dir##*/}"
    renamed="$(renamed_cmd "${base}" "${old_slug}" "${new_slug}" "${old_gateway}" "${new_gateway}")"
    if [[ "${renamed}" == "${base}" ]]; then
      continue
    fi
    if [[ -e "${ROOT}/cmd/${renamed}" ]]; then
      die "cmd/${renamed} already exists; move it aside first"
    fi
    cmd_renames+=("${base}|${renamed}")
  done
fi

scanned=0
changed=()

while IFS= read -r rel; do
  [[ -n "${rel}" ]] || continue
  abs="${ROOT}/${rel}"
  # grep -I reports no match for a binary or empty file; sed over either is at
  # best pointless and at worst corrupting.
  grep -Iq . "${abs}" 2>/dev/null || continue
  scanned=$((scanned + 1))
  # -i.bak works on both BSD and GNU sed, and both write through a temp file
  # and rename, so rewriting a script while it runs is safe. The backup is the
  # before-image used to detect a real change, then deleted immediately.
  sed -i.bak "${sed_args[@]}" "${abs}" || die "sed failed on ${rel}"
  if ! cmp -s "${abs}" "${abs}.bak"; then
    changed+=("${rel}")
  fi
  rm -f "${abs}.bak" || die "cannot remove the backup of ${rel}"
done <<< "${editable}"

[[ ${scanned} -gt 0 ]] || die "every listed file was binary or empty"

# Post-condition. The brand test cannot catch a corrupted rename, because the
# same pass rewrote the test's own expected values, so the check has to compare
# the file against the arguments instead. It runs before anything is moved or
# deleted, so a failure here leaves the least damage.
post_failures=0
assert_brand() {
  local const="$1" want="$2" got
  got="$(brand_const "${const}")"
  if [[ "${got}" == "${want}" ]]; then
    return 0
  fi
  printf 'rename-product: %s is %s after the rewrite, expected %s\n' \
    "${const}" "${got}" "${want}" >&2
  return 1
}

assert_brand Name "${new_name}" || post_failures=$((post_failures + 1))
assert_brand Slug "${new_slug}" || post_failures=$((post_failures + 1))
assert_brand CLI "${new_cli}" || post_failures=$((post_failures + 1))
assert_brand Gateway "${new_gateway}" || post_failures=$((post_failures + 1))
assert_brand EnvPrefix "${new_env_prefix}" || post_failures=$((post_failures + 1))
assert_brand OTelNamespace "${new_otel}" || post_failures=$((post_failures + 1))
assert_brand ProtoPackage "${new_proto_pkg}" || post_failures=$((post_failures + 1))
assert_brand ModulePath "${new_module}" || post_failures=$((post_failures + 1))
assert_brand Image "${new_image}" || post_failures=$((post_failures + 1))
assert_brand PythonPackage "${new_python}" || post_failures=$((post_failures + 1))
# brand.go agreeing with the arguments says nothing about go.mod, which is the
# file the toolchain reads, so the module directive is compared as well.
renamed_module="$(gomod_module)"
if [[ "${renamed_module}" != "${new_module}" ]]; then
  printf 'rename-product: go.mod declares module %s after the rewrite, expected %s\n' \
    "${renamed_module}" "${new_module}" >&2
  post_failures=$((post_failures + 1))
fi
[[ ${post_failures} -eq 0 ]] ||
  die "the rewrite did not produce the requested brand; the tree is half-renamed"

# The destructive phase. Every step below reports through die(), so a failure
# here is never a bare tool error: the pre-flight has already ruled out the
# collisions that are decidable from the arguments, and anything left is an
# environment problem the reader has to be told about in this script's voice.
moves=()

old_proto_dir="${ROOT}/api/proto/${old_proto_path}"
new_proto_dir="${ROOT}/api/proto/${new_proto_path}"
if [[ "${old_proto_path}" != "${new_proto_path}" && -d "${old_proto_dir}" ]]; then
  mkdir -p "$(dirname "${new_proto_dir}")" ||
    die "cannot create the parent of api/proto/${new_proto_path}"
  mv "${old_proto_dir}" "${new_proto_dir}" ||
    die "cannot move api/proto/${old_proto_path} to api/proto/${new_proto_path}"
  moves+=("api/proto/${old_proto_path} -> api/proto/${new_proto_path}")
  # Drop the old parents that the move emptied, never api/proto itself.
  parent="$(dirname "${old_proto_dir}")"
  while [[ "${parent}" != "${ROOT}/api/proto" && "${parent}" != "/" ]]; do
    rmdir "${parent}" 2>/dev/null || break
    parent="$(dirname "${parent}")"
  done
fi

for entry in ${cmd_renames[@]+"${cmd_renames[@]}"}; do
  mv "${ROOT}/cmd/${entry%%|*}" "${ROOT}/cmd/${entry##*|}" ||
    die "cannot move cmd/${entry%%|*} to cmd/${entry##*|}"
  moves+=("cmd/${entry%%|*} -> cmd/${entry##*|}")
done

if [[ "${old_python}" != "${new_python}" && -d "${python_src}/${old_python}" ]]; then
  mv "${python_src}/${old_python}" "${python_src}/${new_python}" ||
    die "cannot move clients/python/src/${old_python} to clients/python/src/${new_python}"
  moves+=("clients/python/src/${old_python} -> clients/python/src/${new_python}")
fi

if [[ -f "${ROOT}/buf.gen.yaml" ]]; then
  command -v buf >/dev/null 2>&1 || die "buf.gen.yaml exists but buf is not on PATH"
  # Generated into a scratch directory first. Deleting api/gen before knowing
  # that generation succeeds leaves the tree with no generated code at all when
  # a .proto does not compile.
  gen_tmp="$(mktemp -d)" || die "cannot create a scratch directory for buf generate"
  if ! ( cd "${ROOT}" && buf generate --output "${gen_tmp}" ); then
    rm -rf "${gen_tmp}"
    die "buf generate failed; api/gen left untouched"
  fi
  if [[ ! -d "${gen_tmp}/api/gen" ]]; then
    rm -rf "${gen_tmp}"
    die "buf generate wrote no api/gen; api/gen left untouched"
  fi
  rm -rf "${ROOT}/api/gen" || die "cannot remove the old api/gen"
  mv "${gen_tmp}/api/gen" "${ROOT}/api/gen" || die "cannot install the regenerated api/gen"
  rm -rf "${gen_tmp}" || die "cannot remove the scratch directory ${gen_tmp}"
  gen_note='api/gen regenerated with buf generate'
else
  gen_note='no buf.gen.yaml: api/gen left alone'
fi

command -v go >/dev/null 2>&1 || die "go is not on PATH"
( cd "${ROOT}" && go mod tidy ) || die "go mod tidy failed"

printf '\n'
printf 'name          %s -> %s\n' "${old_name}" "${new_name}"
printf 'slug          %s -> %s\n' "${old_slug}" "${new_slug}"
printf 'cli           %s -> %s\n' "${old_cli}" "${new_cli}"
printf 'gateway       %s -> %s\n' "${old_gateway}" "${new_gateway}"
printf 'module        %s -> %s\n' "${old_module}" "${new_module}"
printf 'proto package %s -> %s\n' "${old_proto_pkg}" "${new_proto_pkg}"
printf 'proto path    %s -> %s\n' "${old_proto_path}" "${new_proto_path}"
printf 'go package    %s -> %s\n' "${old_go_pkg}" "${new_go_pkg}"
printf 'image         %s -> %s\n' "${old_image}" "${new_image}"
printf 'env prefix    %s -> %s\n' "${old_env_prefix}" "${new_env_prefix}"
printf 'otel          %s -> %s\n' "${old_otel}" "${new_otel}"
printf 'python        %s -> %s\n' "${old_python}" "${new_python}"
printf '\nbrand.go and go.mod re-read after the pass: every constant and the module directive match the above\n'
printf '\n%d of %d scanned files rewritten:\n' "${#changed[@]}" "${scanned}"
if [[ ${#changed[@]} -gt 0 ]]; then
  printf '  %s\n' "${changed[@]}"
fi
if [[ ${#moves[@]} -gt 0 ]]; then
  printf '\npaths moved:\n'
  printf '  %s\n' "${moves[@]}"
else
  printf '\npaths moved: none\n'
fi
printf '\n%s\n' "${gen_note}"
printf 'go mod tidy: done\n'
printf '\nnext: run make quality\n'
