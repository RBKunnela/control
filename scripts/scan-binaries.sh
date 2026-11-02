#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Scans every Go binary a release ships with govulncheck in binary mode, and
# fails on any known vulnerability, on a binary it could not scan and on a
# scan that examined nothing. Binary mode reads the module versions and
# symbols a binary holds and runs nothing, so a binary built for another
# system or architecture scans on this one.
#
#   archives  every .tar.gz goreleaser wrote into the dist directory, each
#             extracted apart, and every Go binary inside it, which must be
#             built for the platform the archive's _<os>_<arch>.tar.gz suffix
#             names; an archive with no such suffix, one that holds no Go
#             binary, a name holding a newline or a tab, and an ELF or
#             Mach-O file go cannot read all fail
#   image     for each platform named, the binary the image's entrypoint
#             names, copied out of a container created and never started; a
#             reference by digest must name an index whose platforms are
#             exactly those named, and is pulled for each; any other
#             reference must already be in the local Docker daemon
#
# Each binary gets one line of what its build information says, then its
# verdict. The vulnerability database's time and the scanner's version are
# read once, from the scanner's JSON output, and named in the summary.
#
#   scripts/scan-binaries.sh archives dist
#   scripts/scan-binaries.sh image <reference> <os/arch>...
set -euo pipefail

_SCAN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
# shellcheck source=lib/repo-files.sh
. "${_SCAN_DIR}/lib/repo-files.sh"

die() {
  printf 'scan-binaries: %s\n' "$*" >&2
  exit 1
}

usage="usage: scripts/scan-binaries.sh archives <dist directory> | image <reference> <os/arch>..."
[[ $# -ge 2 ]] || die "${usage}"
mode="$1"
shift

# govulncheck is a tool of the root module, so it runs from the root.
root="$(repo_root)"
command -v go >/dev/null 2>&1 || die "go is not on PATH, so nothing can be scanned"

work="$(mktemp -d)"
containers=()
cleanup() {
  local c
  for c in ${containers[@]+"${containers[@]}"}; do
    docker rm -f "${c}" >/dev/null 2>&1 || true
  done
  rm -rf "${work}"
}
trap cleanup EXIT

# One line per binary: label, path, and the platform it must be built for.
list="${work}/binaries.tsv"
: >"${list}"

case "${mode}" in
  archives)
    [[ $# -eq 1 ]] || die "${usage}"
    dist="$1"
    [[ -d "${dist}" ]] || die "${dist} is not a directory"
    archives=0
    for archive in "${dist}"/*.tar.gz; do
      [[ -f "${archive}" ]] || continue
      archives=$((archives + 1))
      name="$(basename "${archive}")"
      # The list below is split on tabs and newlines, so a name holding one
      # would hide a binary from the scan.
      [[ "${name}" != *$'\n'* && "${name}" != *$'\t'* ]] || die "an archive's name holds a newline or a tab"
      re='_([a-z0-9]+)_([a-z0-9]+)\.tar\.gz$'
      [[ "${name}" =~ ${re} ]] || die "${name} names no platform as _<os>_<arch>.tar.gz"
      want="${BASH_REMATCH[1]}/${BASH_REMATCH[2]}"
      dir="${work}/archive-${archives}"
      mkdir -p "${dir}"
      tar -xzf "${archive}" -C "${dir}" || die "${name} could not be extracted"
      odd="$(find "${dir}" -name "*"$'\n'"*" -o -name "*"$'\t'"*")" || die "the files of ${name} could not be listed"
      [[ -z "${odd}" ]] || die "${name} holds a file whose name holds a newline or a tab"
      # The extracted archive, not the repository, so repo_files has no say.
      files="$(find "${dir}" -type f | LC_ALL=C sort)" || die "the files of ${name} could not be listed"
      found=0
      while IFS= read -r file <&3; do
        [[ -n "${file}" ]] || continue
        if ! go version -m "${file}" >/dev/null 2>&1; then
          # A README or a script holds no Go build information; an executable
          # go cannot read might be a Go binary that would go unscanned, and so
          # might a file whose first bytes cannot be read.
          magic="$(head -c 4 "${file}" | od -An -tx1 | tr -d ' \n')" ||
            die "${name}/${file#"${dir}"/}: its first bytes could not be read, so it may be a Go binary left unscanned"
          case "${magic}" in
            7f454c46 | feedface | feedfacf | cefaedfe | cffaedfe | cafebabe)
              die "${name}/${file#"${dir}"/} is an ELF or Mach-O file whose Go build information cannot be read"
              ;;
          esac
          continue
        fi
        found=$((found + 1))
        printf '%s/%s\t%s\t%s\n' "${name}" "${file#"${dir}"/}" "${file}" "${want}" >>"${list}"
      done 3<<<"${files}"
      [[ ${found} -gt 0 ]] || die "${name} holds no Go binary"
    done
    [[ ${archives} -gt 0 ]] || die "${dist} holds no .tar.gz archive"
    source_text="${archives} archives"
    [[ ${archives} -eq 1 ]] && source_text="1 archive"
    ;;
  image)
    ref="$1"
    shift
    [[ $# -ge 1 ]] || die "${usage}"
    [[ "${ref}" =~ ^[^[:space:]]+$ ]] || die "the image reference holds white space"
    command -v docker >/dev/null 2>&1 || die "docker is not on PATH, so the image cannot be read"
    for platform in "$@"; do
      [[ "${platform}" =~ ^[a-z0-9]+/[a-z0-9]+$ ]] || die "${platform} is not os/arch"
    done
    pull=never
    if [[ "${ref}" == *@sha256:* ]]; then
      pull=always
      # A platform the index holds and nobody named would ship unscanned. A
      # variant is not compared, so two variants of one architecture refuse.
      command -v jq >/dev/null 2>&1 || die "jq is not on PATH, so the index of ${ref} cannot be read"
      # Each platform is pulled by its own manifest's digest: the image store
      # Docker uses by default keeps one platform per reference, and pulling a
      # second platform by the index's digest is refused.
      pairs="$(docker buildx imagetools inspect --raw "${ref}" | jq -r '
        if (.mediaType != "application/vnd.oci.image.index.v1+json"
          and .mediaType != "application/vnd.docker.distribution.manifest.list.v2+json")
          or (.manifests | type) != "array"
        then error("not an index")
        else .manifests[] | if (.platform.os | type) != "string" or (.platform.architecture | type) != "string"
          then error("a manifest names no platform")
          elif (.digest | type) != "string" or (.digest | test("^sha256:[0-9a-f]{64}$") | not)
          then error("a manifest names no digest")
          else "\(.platform.os)/\(.platform.architecture) \(.digest)" end
        end' | LC_ALL=C sort)" || die "the index of ${ref} could not be read as an image index"
      held="$(cut -d ' ' -f 1 <<<"${pairs}")"
      named="$(printf '%s\n' "$@" | LC_ALL=C sort)"
      [[ -n "${held}" && "${held}" == "${named}" ]] ||
        die "${ref} holds images for ${held//$'\n'/ }, and the scan names $*; every platform the index holds must be scanned, and only those"
    fi
    n=0
    for platform in "$@"; do
      n=$((n + 1))
      target="${ref}"
      if [[ "${pull}" == always ]]; then
        target="${ref%@*}@$(awk -v p="${platform}" '$1 == p { print $2 }' <<<"${pairs}")"
        [[ "${target}" =~ @sha256:[0-9a-f]{64}$ ]] || die "the index of ${ref} names no single manifest for ${platform}"
      fi
      cid="$(docker create --pull "${pull}" --platform "${platform}" "${target}")" ||
        die "no container could be created from ${ref} for ${platform}"
      [[ "${cid}" =~ ^[0-9a-f]{12,64}$ ]] || die "docker create answered '${cid}' for ${ref} on ${platform}"
      containers+=("${cid}")
      # The container's entrypoint is the one its image declares, for the
      # platform the image was resolved to.
      entry="$(docker container inspect --format '{{json .Config.Entrypoint}}' "${cid}")" ||
        die "the entrypoint of ${ref} for ${platform} could not be read"
      re='^\["(/[^"\\]+)"(,.*)?\]$'
      [[ "${entry}" =~ ${re} ]] || die "${ref} for ${platform} names no absolute entrypoint: ${entry}"
      entry="${BASH_REMATCH[1]}"
      dest="${work}/image-${n}"
      mkdir -p "${dest}"
      # -L copies the file a symbolic link names, not the link.
      docker cp -L "${cid}:${entry}" "${dest}/$(basename "${entry}")" >/dev/null ||
        die "${entry} could not be copied out of ${ref} for ${platform}"
      printf '%s %s:%s\t%s\t%s\n' "${ref}" "${platform}" "${entry}" "${dest}/$(basename "${entry}")" "${platform}" >>"${list}"
    done
    source_text="${ref} for $*"
    ;;
  *) die "${usage}" ;;
esac

# Never empty: every archive and every platform has added a binary or died.
binaries="$(grep -c . "${list}")"

# The config message of the JSON output names the database and the scanner.
# Each field must appear once, as a plain string.
first="$(head -n 1 "${list}" | cut -f 2)"
json="$(cd "${root}" && go tool govulncheck -mode=binary -format json "${first}" 2>&1)" || {
  printf '%s\n' "${json}" >&2
  die "govulncheck could not read the vulnerability database"
}
field() {
  local re="^[[:space:]]*\"$1\":[[:space:]]*\"([^\"\\\\]*)\",?$" line value="" seen=0
  while IFS= read -r line; do
    if [[ "${line}" =~ ${re} ]]; then
      value="${BASH_REMATCH[1]}"
      seen=$((seen + 1))
    fi
  done <<<"${json}"
  [[ ${seen} -eq 1 ]] || die "govulncheck's JSON output names $1 ${seen} times, want once"
  printf '%s' "${value}"
}
db="$(field db_last_modified)" || exit 1
scanner="$(field scanner_version)" || exit 1
[[ "${db}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z$ ]] || die "govulncheck names the database's time as '${db}'"
[[ "${scanner}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+ ]] || die "govulncheck names its version as '${scanner}'"

failed=0
gos=""
# The list is read from fd 3, so a command in the loop that reads its standard
# input cannot swallow the binaries after it.
while IFS=$'\t' read -r label path want <&3; do
  facts="$(go version -m "${path}")" || die "${label}: the build information could not be read"
  gover="${facts%%$'\n'*}"
  gover="${gover##*: }"
  goos="" goarch="" mod="" rev=""
  # A tab is whitespace to read, so the line's leading tab is dropped.
  while IFS=$'\t' read -r kind a b _; do
    case "${kind}" in
      mod) mod="${a} ${b}" ;;
      build)
        case "${a}" in
          GOOS=*) goos="${a#GOOS=}" ;;
          GOARCH=*) goarch="${a#GOARCH=}" ;;
          vcs.revision=*) rev="${a#vcs.revision=}" ;;
        esac
        ;;
    esac
  done <<<"${facts}"
  platform="${goos:-unknown}/${goarch:-unknown}"
  printf 'scan-binaries: %s: %s, %s, %s, vcs.revision %s\n' \
    "${label}" "${platform}" "${gover}" "${mod:-no main module}" "${rev:-none}"
  if [[ "${platform}" != "${want}" ]]; then
    printf 'scan-binaries: %s: built for %s, not %s\n' "${label}" "${platform}" "${want}" >&2
    failed=$((failed + 1))
    continue
  fi
  [[ " ${gos} " == *" ${gover} "* ]] || gos="${gos:+${gos} }${gover}"

  rc=0
  out="$(cd "${root}" && go tool govulncheck -mode=binary "${path}" 2>&1)" || rc=$?
  if [[ ${rc} -ne 0 ]]; then
    printf '%s\n' "${out}" >&2
    printf 'scan-binaries: %s: govulncheck exited %d\n' "${label}" "${rc}" >&2
    failed=$((failed + 1))
  fi
done 3<"${list}"

[[ ${failed} -eq 0 ]] ||
  die "${failed} of ${binaries} binaries from ${source_text} have a known vulnerability or could not be scanned (vulnerability database of ${db}, govulncheck@${scanner})"
noun=binaries
[[ ${binaries} -eq 1 ]] && noun=binary
printf 'scan-binaries: %d %s from %s, %s, vulnerability database of %s, govulncheck@%s, no known vulnerability\n' \
  "${binaries}" "${noun}" "${source_text}" "${gos// /, }" "${db}" "${scanner}"
