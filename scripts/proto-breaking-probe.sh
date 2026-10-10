#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# The negative control of buf.yaml's breaking rules. buf.yaml, its comment
# lines and blank lines aside, has to be exactly the text pinned below: one
# module, the STANDARD lint rules with ignore comments in the protos refused,
# the breaking rules `use: [FILE]` and `ignore: [the observation package, the
# finding package, the enforcement package]`, no other rule, exception or
# per-module override in any YAML spelling. The rules buf itself reads for the
# module have to be the pinned list of the FILE category, so a spelling the
# text check missed still fails and a buf upgrade that changes the category is
# noticed. Then, in scratch copies of buf.yaml and api/proto, one field of
# every file of the frozen v1 package is renumbered, one file per copy, and
# buf breaking against the unchanged copy has to fail naming that field; a
# copy that does not compile, or a failure that names something else, is not a
# detected break. A field of every file of the unstable observation, finding
# and enforcement packages, which buf.yaml ignores (ADR-0040, ADR-0045,
# ADR-0051), renumbered the same way has to pass, and has to fail naming that
# field once that package's ignore line is dropped from the copy's buf.yaml. A
# buf that is missing, or a file holding no field this script can find to
# renumber, fails it.
set -euo pipefail

_PROBE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
# shellcheck source=lib/repo-files.sh
. "${_PROBE_DIR}/lib/repo-files.sh"

root="$(repo_root)"
cd "${root}"

die() {
  printf 'proto-breaking-probe: %s\n' "$*" >&2
  exit 1
}

command -v buf >/dev/null 2>&1 || die "buf is not on PATH; nothing was probed"

v1=guardana/control/v1
observe=guardana/control/observe/v1alpha1
finding=guardana/control/finding/v1alpha1
enforce=guardana/control/enforce/v1alpha1
moved=4000

want_config="version: v2
modules:
  - path: api/proto
lint:
  use:
    - STANDARD
  disallow_comment_ignores: true
breaking:
  use:
    - FILE
  ignore:
    - api/proto/${observe}
    - api/proto/${finding}
    - api/proto/${enforce}"
# Only whole comment lines are dropped: with every other line pinned, none of
# them can sit inside a scalar, and a trailing comment fails the comparison.
got_config="$(sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' buf.yaml)"
if [[ "${got_config}" != "${want_config}" ]]; then
  diff <(printf '%s\n' "${want_config}") <(printf '%s\n' "${got_config}") >&2 || true
  die "buf.yaml is not exactly the pinned module with lint ignore comments refused, the FILE rule and the observation, finding and enforcement packages ignored (< pinned, > buf.yaml)"
fi

want_rules="ENUM_NO_DELETE ENUM_SAME_JSON_FORMAT ENUM_SAME_TYPE ENUM_VALUE_NO_DELETE
ENUM_VALUE_SAME_NAME EXTENSION_MESSAGE_NO_DELETE EXTENSION_NO_DELETE
FIELD_NO_DELETE FIELD_SAME_CARDINALITY FIELD_SAME_CPP_STRING_TYPE
FIELD_SAME_DEFAULT FIELD_SAME_JAVA_UTF8_VALIDATION FIELD_SAME_JSON_NAME
FIELD_SAME_JSTYPE FIELD_SAME_NAME FIELD_SAME_ONEOF FIELD_SAME_TYPE
FIELD_SAME_UTF8_VALIDATION FILE_NO_DELETE FILE_SAME_CC_ENABLE_ARENAS
FILE_SAME_CC_GENERIC_SERVICES FILE_SAME_CSHARP_NAMESPACE
FILE_SAME_GO_PACKAGE FILE_SAME_JAVA_GENERIC_SERVICES
FILE_SAME_JAVA_MULTIPLE_FILES FILE_SAME_JAVA_OUTER_CLASSNAME
FILE_SAME_JAVA_PACKAGE FILE_SAME_OBJC_CLASS_PREFIX FILE_SAME_OPTIMIZE_FOR
FILE_SAME_PACKAGE FILE_SAME_PHP_CLASS_PREFIX
FILE_SAME_PHP_METADATA_NAMESPACE FILE_SAME_PHP_NAMESPACE
FILE_SAME_PY_GENERIC_SERVICES FILE_SAME_RUBY_PACKAGE
FILE_SAME_SWIFT_PREFIX FILE_SAME_SYNTAX MESSAGE_NO_DELETE
MESSAGE_NO_REMOVE_STANDARD_DESCRIPTOR_ACCESSOR MESSAGE_SAME_JSON_FORMAT
MESSAGE_SAME_REQUIRED_FIELDS ONEOF_NO_DELETE RESERVED_ENUM_NO_DELETE
RESERVED_MESSAGE_NO_DELETE RPC_NO_DELETE RPC_SAME_CLIENT_STREAMING
RPC_SAME_IDEMPOTENCY_LEVEL RPC_SAME_REQUEST_TYPE RPC_SAME_RESPONSE_TYPE
RPC_SAME_SERVER_STREAMING SERVICE_NO_DELETE"
if ! listed="$(buf config ls-breaking-rules --configured-only --module-path api/proto --format json 2>&1)"; then
  printf '%s\n' "${listed}" >&2
  die "buf could not list the breaking rules configured for api/proto; nothing was judged"
fi
got_rules="$(sed -n 's/^{"id":"\([A-Z0-9_]*\)",.*/\1/p' <<<"${listed}" | LC_ALL=C sort)"
[[ "$(grep -c . <<<"${listed}")" == "$(grep -c . <<<"${got_rules}")" ]] ||
  die "buf listed a breaking rule this script cannot read; nothing was judged"
if [[ "${got_rules}" != "$(tr -s ' \n' '\n' <<<"${want_rules}" | LC_ALL=C sort)" ]]; then
  diff <(tr -s ' \n' '\n' <<<"${want_rules}" | LC_ALL=C sort) <(printf '%s\n' "${got_rules}") >&2 || true
  die "the breaking rules buf reads for api/proto are not the pinned FILE rules (< pinned, > configured)"
fi

work="$(mktemp -d)"
trap 'rm -rf "${work:?}"' EXIT

mkdir -p "${work}/base"
cp buf.yaml "${work}/base/"
cp -R api "${work}/base/"

# first_field prints "<line> <message|enum> <name> <number>" for the first
# field of a top-level message, or the first non-zero value of a top-level
# enum, in proto file $1; nothing when it holds neither. With $2, message or
# enum, only that kind is looked for.
first_field() {
  awk -v want="${2:-}" '
    /^(message|enum) [A-Za-z_][A-Za-z0-9_]* *\{/ { kind = $1; name = $2; sub(/\{.*/, "", name); next }
    /^\}/ { kind = "" }
    (want == "" || want == kind) && kind == "message" && /^  (optional |repeated )?[A-Za-z_][A-Za-z0-9_.]* [a-z_][a-z0-9_]* = [0-9]+;/ {
      n = $0; sub(/^.*= /, "", n); sub(/;.*$/, "", n)
      print NR, kind, name, n; exit
    }
    (want == "" || want == kind) && kind == "enum" && /^  [A-Z_][A-Z0-9_]* = [1-9][0-9]*;/ {
      n = $0; sub(/^.*= /, "", n); sub(/;.*$/, "", n)
      print NR, kind, name, n; exit
    }
  ' "$1"
}

# renumbered copies the module into $1 and moves the field on line $3 of
# api/proto/$2 from number $4 to ${moved}.
renumbered() {
  local dir="$1" file="$2" line="$3" number="$4"
  mkdir -p "${dir}"
  cp buf.yaml "${dir}/"
  cp -R api "${dir}/"
  ! grep -qF "= ${moved};" "${dir}/api/proto/${file}" || die "${file} already uses number ${moved}"
  sed -i.orig "${line}s/= ${number};/= ${moved};/" "${dir}/api/proto/${file}"
  rm -f "${dir}/api/proto/${file}.orig"
  ! cmp -s "api/proto/${file}" "${dir}/api/proto/${file}" || die "${file} was not changed"
}

files=0
for path in "api/proto/${v1}"/*.proto; do
  [[ -f "${path}" ]] || die "no proto file under api/proto/${v1}"
  file="${path#api/proto/}"
  read -r line kind name number <<<"$(first_field "${path}")" || true
  [[ -n "${number:-}" ]] || die "${file} holds no message field or enum value to renumber"
  dir="${work}/v1-${files}"
  renumbered "${dir}" "${file}" "${line}" "${number}"
  if ! out="$(cd "${dir}" && buf build 2>&1)"; then
    printf '%s\n' "${out}" >&2
    die "${file} with ${kind} ${name} field ${number} renumbered does not compile; nothing was compared"
  fi
  rc=0
  out="$(cd "${dir}" && buf breaking --against "${work}/base" 2>&1)" || rc=$?
  if [[ ${rc} -eq 0 ]]; then
    die "${file}: ${kind} ${name} field ${number} renumbered passed buf breaking: the frozen package is not compared"
  fi
  if ! grep -E "^api/proto/${file}:" <<<"${out}" | grep -F "\"${number}\"" | grep -qF "${kind} \"${name}\""; then
    printf '%s\n' "${out}" >&2
    die "${file}: buf breaking failed (exit ${rc}) without naming ${kind} ${name} field ${number}; nothing shows the change was compared"
  fi
  files=$((files + 1))
  unset line kind name number
done

# ignored checks every file of the unstable package $1, which buf.yaml ignores:
# its first message field and its first enum value, each renumbered in a copy
# of its own, have to pass buf breaking, and have to fail naming that field
# with the package's ignore line dropped, so the pass is the ignore's. It sets
# ignored_files to the number of files checked.
ignored() {
  local pkg="$1" path file want line kind name number dir out rc found messages=0 copies=0
  ignored_files=0
  for path in "api/proto/${pkg}"/*.proto; do
    [[ -f "${path}" ]] || die "no proto file under api/proto/${pkg}"
    file="${path#api/proto/}"
    found=0
    for want in message enum; do
      line="" number=""
      read -r line kind name number <<<"$(first_field "${path}" "${want}")" || true
      [[ -n "${number}" ]] || continue
      found=$((found + 1))
      [[ "${kind}" != message ]] || messages=$((messages + 1))
      dir="${work}/ignored-${pkg//\//-}-${copies}"
      copies=$((copies + 1))
      renumbered "${dir}" "${file}" "${line}" "${number}"
      if ! out="$(cd "${dir}" && buf build 2>&1 && buf breaking --against "${work}/base" 2>&1)"; then
        printf '%s\n' "${out}" >&2
        die "${file}: ${kind} ${name} field ${number} renumbered failed buf breaking: the unstable package is compared"
      fi
      grep -qxF "    - api/proto/${pkg}" "${dir}/buf.yaml" || die "the copy's buf.yaml has no ignore line for ${pkg}"
      grep -vxF "    - api/proto/${pkg}" "${dir}/buf.yaml" >"${dir}/buf.yaml.kept" || die "the copy's buf.yaml could not be rewritten"
      mv "${dir}/buf.yaml.kept" "${dir}/buf.yaml"
      rc=0
      out="$(cd "${dir}" && buf breaking --against "${work}/base" 2>&1)" || rc=$?
      if [[ ${rc} -eq 0 ]]; then
        die "${file}: ${kind} ${name} field ${number} renumbered passed buf breaking without its ignore line: the ignore is not what lets it pass"
      fi
      if ! grep -E "^api/proto/${file}:" <<<"${out}" | grep -F "\"${number}\"" | grep -qF "${kind} \"${name}\""; then
        printf '%s\n' "${out}" >&2
        die "${file}: buf breaking without its ignore line failed (exit ${rc}) without naming ${kind} ${name} field ${number}"
      fi
    done
    [[ ${found} -gt 0 ]] || die "${file} holds no message field or enum value to renumber"
    ignored_files=$((ignored_files + 1))
  done
  [[ ${messages} -gt 0 ]] || die "no file under api/proto/${pkg} holds a message field to renumber"
}

ignored "${observe}"
observed="${ignored_files}"
ignored "${finding}"
findings="${ignored_files}"
ignored "${enforce}"
enforced="${ignored_files}"

printf 'proto-breaking-probe: v1 compared in %d file(s); observe/v1alpha1 ignored in %d file(s), finding/v1alpha1 in %d file(s), enforce/v1alpha1 in %d file(s)\n' "${files}" "${observed}" "${findings}" "${enforced}"
