#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# The negative control of scripts/scan-binaries.sh. It runs the script with a
# stand-in go and docker first on PATH, so no network and no image are needed,
# and each case must pass or fail as named and say why:
#   pass     a product-shaped and a demo-shaped archive, every binary clean,
#            each of the five binaries scanned and the summary naming the
#            database time and scanner version the stand-in reported; an
#            image by digest for the two platforms its index holds, each
#            pulled
#   refused  a dist with no archive, an archive holding no Go binary, an
#            archive that cannot be extracted, an archive whose name names no
#            platform, a binary built for another platform than its
#            archive's name says, an ELF or a Mach-O file go cannot read
#            beside a good binary, a file whose first bytes cannot be read
#            beside a good binary, a file named with a newline or a tab, one
#            vulnerable binary among
#            five (every binary still scanned), a binary the scanner cannot
#            read, a database time absent or malformed, a JSON scan that
#            fails, an image binary built for another platform, an image
#            with no entrypoint, a container that cannot be created, a
#            vulnerable image binary, a platform that is not os/arch, a
#            reference holding white space, and an index that holds a
#            platform more or one fewer than those named, is no index, or
#            cannot be read
set -euo pipefail

_PROBE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
# shellcheck source=lib/repo-files.sh
. "${_PROBE_DIR}/lib/repo-files.sh"

die() {
  printf 'scan-binaries-probe: %s\n' "$*" >&2
  exit 1
}

root="$(repo_root)"
script="${root}/scripts/scan-binaries.sh"
[[ -f "${script}" ]] || die "${script} is missing"

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
mkdir -p "${tmp}/bin"

# A stand-in binary is one line: a marker, its platform and how the stand-in
# scanner answers for it (clean, vulnerable or unreadable).
cat >"${tmp}/bin/go" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  version)
    [[ "$2" == -m && $# -eq 3 ]] || { echo "stand-in go: unexpected arguments: $*" >&2; exit 64; }
    read -r marker goos goarch _ <"$3" 2>/dev/null || exit 1
    [[ "${marker}" == STAND-IN-GO-BINARY ]] || exit 1
    printf '%s: go1.99.0\n\tpath\texample.com/probe\n\tmod\texample.com/probe\tv1.2.3\t\n\tbuild\tGOOS=%s\n\tbuild\tGOARCH=%s\n\tbuild\tvcs.revision=%s\n' \
      "$3" "${goos}" "${goarch}" 0123456789abcdef0123456789abcdef01234567
    ;;
  tool)
    [[ "$2" == govulncheck && "$3" == -mode=binary ]] || { echo "stand-in go: unexpected arguments: $*" >&2; exit 64; }
    if [[ "$4" == -format ]]; then
      [[ "$5" == json && $# -eq 6 ]] || exit 64
      case "${STUB_JSON:-ok}" in
        fail) echo "stand-in govulncheck: fetching the database failed" >&2; exit 1 ;;
        nodb) printf '{\n  "config": {\n    "scanner_version": "v9.8.7"\n  }\n}\n' ;;
        badtime) printf '{\n  "config": {\n    "scanner_version": "v9.8.7",\n    "db_last_modified": "yesterday"\n  }\n}\n' ;;
        ok) printf '{\n  "config": {\n    "scanner_version": "v9.8.7",\n    "db_last_modified": "2001-02-03T04:05:06Z",\n    "scan_mode": "binary"\n  }\n}\n' ;;
      esac
      exit 0
    fi
    [[ $# -eq 4 ]] || exit 64
    printf '%s\n' "$4" >>"${STUB_DIR}/scanned"
    read -r _ _ _ verdict <"$4"
    case "${verdict}" in
      clean) echo "No vulnerabilities found." ;;
      vulnerable) echo "Vulnerability #1: GO-0000-0001"; exit 3 ;;
      *) echo "govulncheck: unrecognized binary format" >&2; exit 1 ;;
    esac
    ;;
  *) echo "stand-in go: unexpected arguments: $*" >&2; exit 64 ;;
esac
EOF

cat >"${tmp}/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${STUB_DIR}/docker"
cid=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
case "$1" in
  create)
    [[ "$2" == --pull && "$4" == --platform && $# -eq 6 ]] || exit 64
    [[ "${STUB_CREATE:-ok}" == ok ]] || { echo "stand-in docker: no such image" >&2; exit 1; }
    # As the default image store does, refuse a second platform by the index's digest.
    [[ "$6" != *"@sha256:$(printf '%064d' 0)" ]] || { echo "cannot overwrite digest" >&2; exit 1; }
    printf '%s\n' "$5" >"${STUB_DIR}/platform"
    echo "${cid}"
    ;;
  container)
    [[ "$2" == inspect && "$5" == "${cid}" ]] || exit 64
    printf '%s\n' "${STUB_ENTRYPOINT:-[\"/ko-app/gateway\"]}"
    ;;
  cp)
    [[ "$2" == -L && "$3" == "${cid}:/ko-app/gateway" && $# -eq 4 ]] || exit 64
    platform="$(cat "${STUB_DIR}/platform")"
    printf 'STAND-IN-GO-BINARY %s %s %s\n' "${platform%/*}" "${STUB_ARCH:-${platform#*/}}" "${STUB_VERDICT:-clean}" >"$4"
    ;;
  buildx)
    [[ "$2" == imagetools && "$3" == inspect && "$4" == --raw && $# -eq 5 ]] || exit 64
    [[ "${STUB_INDEX:-}" != fail ]] || { echo "stand-in docker: unauthorized" >&2; exit 1; }
    index='{"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","platform":{"architecture":"arm64","os":"linux","variant":"v8"}},{"digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","platform":{"architecture":"amd64","os":"linux"}}]}'
    printf '%s\n' "${STUB_INDEX:-${index}}"
    ;;
  rm) ;;
  *) exit 64 ;;
esac
EOF
# A file named unreadable cannot be read, as head finds a file it may not
# read; anything else goes to the real head.
command -v head >"${tmp}/real-head" || die "head is not on PATH"
cat >"${tmp}/bin/head" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
for arg in "$@"; do
  [[ "${arg##*/}" != unreadable ]] || { echo "head: ${arg}: Permission denied" >&2; exit 1; }
done
exec "$(cat "${STUB_DIR}/real-head")" "$@"
EOF
chmod 0755 "${tmp}/bin/go" "${tmp}/bin/docker" "${tmp}/bin/head"

# binary <path> <goos> <goarch> <verdict>
binary() {
  mkdir -p "$(dirname "$1")"
  printf 'STAND-IN-GO-BINARY %s %s %s\n' "$2" "$3" "$4" >"$1"
  chmod 0755 "$1"
}

# dist <directory> <verdict of the demo's victim>
# A product archive with two binaries at its top, and a demo archive wrapped in
# one directory with three binaries under bin/ beside a script and a README.
dist() {
  local d="$1" stage="${tmp}/stage-$RANDOM"
  mkdir -p "${d}" "${stage}/product" "${stage}/demo/product-demo/examples"
  binary "${stage}/product/cli" linux arm64 clean
  binary "${stage}/product/gateway" linux arm64 clean
  printf 'readme\n' >"${stage}/product/README.md"
  tar -czf "${d}/product_1.0.0_linux_arm64.tar.gz" -C "${stage}/product" .
  local demo="${stage}/demo/product-demo"
  binary "${demo}/bin/cli" darwin amd64 clean
  binary "${demo}/bin/gateway" darwin amd64 clean
  binary "${demo}/bin/vulnerable-mcp-agent" darwin amd64 "$2"
  printf '#!/bin/sh\n' >"${demo}/examples/call.sh"
  chmod 0755 "${demo}/examples/call.sh"
  tar -czf "${d}/product-demo_1.0.0_darwin_amd64.tar.gz" -C "${stage}/demo" product-demo
}

cases=0
# check <name> <pass|fail> <text the output must hold> [VAR=value...] -- <script arguments>
check() {
  local name="$1" want="$2" text="$3" rc=0 out
  shift 3
  local -a envs=()
  while [[ $# -gt 0 && "$1" != -- ]]; do
    envs+=("$1")
    shift
  done
  shift
  rm -f "${tmp}/scanned" "${tmp}/docker" "${tmp}/platform"
  out="$(env ${envs[@]+"${envs[@]}"} STUB_DIR="${tmp}" PATH="${tmp}/bin:${PATH}" bash "${script}" "$@" 2>&1)" || rc=$?
  if [[ "${want}" == pass && ${rc} -ne 0 ]]; then
    die "${name}: refused (exit ${rc}), want a pass:"$'\n'"${out}"
  fi
  if [[ "${want}" == fail && ${rc} -eq 0 ]]; then
    die "${name}: passed, want a refusal:"$'\n'"${out}"
  fi
  [[ "${out}" == *"${text}"* ]] || die "${name}: the output does not say \"${text}\":"$'\n'"${out}"
  cases=$((cases + 1))
}

# scanned <name> <count>: the stand-in scanner was asked about that many binaries.
scanned() {
  local n=0
  [[ -f "${tmp}/scanned" ]] && n="$(grep -c . "${tmp}/scanned")"
  [[ "${n}" -eq "$2" ]] || die "$1: the scanner was asked about ${n} binaries, want $2"
}

clean="${tmp}/clean"
dist "${clean}" clean
check "clean archives" pass \
  "scan-binaries: 5 binaries from 2 archives, go1.99.0, vulnerability database of 2001-02-03T04:05:06Z, govulncheck@v9.8.7, no known vulnerability" \
  -- archives "${clean}"
scanned "clean archives" 5
check "a binary's facts" pass \
  "scan-binaries: product-demo_1.0.0_darwin_amd64.tar.gz/product-demo/bin/vulnerable-mcp-agent: darwin/amd64, go1.99.0, example.com/probe v1.2.3, vcs.revision 0123456789abcdef0123456789abcdef01234567" \
  -- archives "${clean}"

mkdir -p "${tmp}/empty"
check "no archive" fail "holds no .tar.gz archive" -- archives "${tmp}/empty"

mkdir -p "${tmp}/nogo/stage/bin" "${tmp}/nogo/dist"
printf '#!/bin/sh\necho hi\n' >"${tmp}/nogo/stage/bin/tool"
chmod 0755 "${tmp}/nogo/stage/bin/tool"
printf 'readme\n' >"${tmp}/nogo/stage/README.md"
tar -czf "${tmp}/nogo/dist/x_linux_amd64.tar.gz" -C "${tmp}/nogo/stage" .
check "an archive with no Go binary" fail "x_linux_amd64.tar.gz holds no Go binary" -- archives "${tmp}/nogo/dist"

mkdir -p "${tmp}/broken"
printf 'not gzip\n' >"${tmp}/broken/y_linux_amd64.tar.gz"
check "an archive that cannot be extracted" fail "y_linux_amd64.tar.gz could not be extracted" -- archives "${tmp}/broken"

# A clean binary, a vulnerable one whose name holds a newline, and a truncated
# executable: split on the newline, the list would name one clean binary.
stage="${tmp}/stage-newline"
mkdir -p "${stage}" "${tmp}/newline"
binary "${stage}/clean" linux amd64 clean
binary "${stage}/vuln"$'\n'"x" linux amd64 vulnerable
printf '\177ELF\002\001' >"${stage}/vuln2"
chmod 0755 "${stage}/vuln2"
tar -czf "${tmp}/newline/product_1.0.0_linux_amd64.tar.gz" -C "${stage}" .
check "a file named with a newline" fail "product_1.0.0_linux_amd64.tar.gz holds a file whose name holds a newline or a tab" \
  -- archives "${tmp}/newline"
rm -f "${stage}/vuln"$'\n'"x"
binary "${stage}/vuln"$'\t'"x" linux amd64 vulnerable
rm -rf "${tmp}/newline"
mkdir -p "${tmp}/newline"
tar -czf "${tmp}/newline/product_1.0.0_linux_amd64.tar.gz" -C "${stage}" .
check "a file named with a tab" fail "product_1.0.0_linux_amd64.tar.gz holds a file whose name holds a newline or a tab" \
  -- archives "${tmp}/newline"
rm -f "${stage}/vuln"$'\t'"x"
rm -rf "${tmp}/newline"
mkdir -p "${tmp}/newline"
tar -czf "${tmp}/newline/product_1.0.0_linux_amd64.tar.gz" -C "${stage}" .
check "the truncated executable alone" fail "product_1.0.0_linux_amd64.tar.gz/vuln2 is an ELF or Mach-O file" \
  -- archives "${tmp}/newline"
mkdir -p "${tmp}/oddname"
cp "${clean}/product_1.0.0_linux_arm64.tar.gz" "${tmp}/oddname/a"$'\n'"b_linux_arm64.tar.gz"
check "an archive named with a newline" fail "an archive's name holds a newline or a tab" -- archives "${tmp}/oddname"

# archive <dist> <name> <file> <goos> <goarch>: one stand-in binary in an archive of that name.
archive() {
  local stage="${tmp}/stage-$RANDOM"
  mkdir -p "$1" "${stage}"
  binary "${stage}/$3" "$4" "$5" clean
  tar -czf "$1/$2" -C "${stage}" .
}
archive "${tmp}/unnamed" product.tar.gz gateway linux amd64
check "an archive that names no platform" fail "product.tar.gz names no platform as _<os>_<arch>.tar.gz" \
  -- archives "${tmp}/unnamed"
archive "${tmp}/misbuilt" product_1.0.0_linux_amd64.tar.gz gateway linux arm64
check "a binary for another platform than its archive's" fail \
  "product_1.0.0_linux_amd64.tar.gz/gateway: built for linux/arm64, not linux/amd64" -- archives "${tmp}/misbuilt"
scanned "a binary for another platform than its archive's" 0

# An executable header with no build information behind it, beside a good binary.
for kind in ELF Mach-O; do
  stage="${tmp}/stage-$RANDOM"
  mkdir -p "${stage}/bin"
  binary "${stage}/bin/gateway" linux amd64 clean
  case "${kind}" in
    ELF) printf '\177ELF\002\001\001\000rest\n' >"${stage}/bin/opaque" ;;
    Mach-O) printf '\317\372\355\376\007\000\000\001rest\n' >"${stage}/bin/opaque" ;;
  esac
  chmod 0755 "${stage}/bin/opaque"
  rm -rf "${tmp}/opaque"
  mkdir -p "${tmp}/opaque"
  tar -czf "${tmp}/opaque/product_1.0.0_linux_amd64.tar.gz" -C "${stage}" .
  check "an ${kind} file go cannot read" fail \
    "product_1.0.0_linux_amd64.tar.gz/bin/opaque is an ELF or Mach-O file whose Go build information cannot be read" \
    -- archives "${tmp}/opaque"
done

stage="${tmp}/stage-unreadable"
mkdir -p "${stage}/bin" "${tmp}/unreadable-bytes"
binary "${stage}/bin/gateway" linux amd64 clean
printf '\177ELF\002\001\001\000rest\n' >"${stage}/bin/unreadable"
chmod 0755 "${stage}/bin/unreadable"
tar -czf "${tmp}/unreadable-bytes/product_1.0.0_linux_amd64.tar.gz" -C "${stage}" .
check "a file whose first bytes cannot be read" fail \
  "product_1.0.0_linux_amd64.tar.gz/bin/unreadable: its first bytes could not be read" -- archives "${tmp}/unreadable-bytes"
scanned "a file whose first bytes cannot be read" 0

vuln="${tmp}/vuln"
dist "${vuln}" vulnerable
check "one vulnerable binary" fail \
  "product-demo_1.0.0_darwin_amd64.tar.gz/product-demo/bin/vulnerable-mcp-agent: govulncheck exited 3" \
  -- archives "${vuln}"
scanned "one vulnerable binary" 5
check "the finding shown" fail "Vulnerability #1: GO-0000-0001" -- archives "${vuln}"
check "the count of failures" fail "1 of 5 binaries from 2 archives have a known vulnerability" -- archives "${vuln}"

unreadable="${tmp}/unreadable"
dist "${unreadable}" unreadable
check "a binary the scanner cannot read" fail "bin/vulnerable-mcp-agent: govulncheck exited 1" -- archives "${unreadable}"

check "no database time" fail "names db_last_modified 0 times" STUB_JSON=nodb -- archives "${clean}"
check "a malformed database time" fail "names the database's time as 'yesterday'" STUB_JSON=badtime -- archives "${clean}"
check "a JSON scan that fails" fail "govulncheck could not read the vulnerability database" STUB_JSON=fail -- archives "${clean}"

digest="ghcr.io/example/probe@sha256:$(printf '%064d' 0)"
check "an image by digest" pass \
  "scan-binaries: 2 binaries from ${digest} for linux/amd64 linux/arm64, go1.99.0, vulnerability database of 2001-02-03T04:05:06Z" \
  -- image "${digest}" linux/amd64 linux/arm64
scanned "an image by digest" 2
for want in "linux/amd64 ghcr.io/example/probe@sha256:$(printf '2%.0s' {1..64})" \
  "linux/arm64 ghcr.io/example/probe@sha256:$(printf '1%.0s' {1..64})"; do
  grep -qxF "create --pull always --platform ${want}" "${tmp}/docker" ||
    die "an image by digest: ${want%% *} not pulled by its own manifest's digest:"$'\n'"$(cat "${tmp}/docker")"
done
check "a local image" pass "1 binary from goreleaser.ko.local:sha-1 for linux/arm64" -- image goreleaser.ko.local:sha-1 linux/arm64
grep -q '^create --pull never --platform linux/arm64 goreleaser.ko.local:sha-1$' "${tmp}/docker" ||
  die "a local image: pulled from a registry:"$'\n'"$(cat "${tmp}/docker")"

check "an image binary for another platform" fail "built for linux/amd64, not linux/arm64" \
  STUB_ARCH=amd64 -- image "${digest}" linux/amd64 linux/arm64
check "an image with no entrypoint" fail "names no absolute entrypoint: null" STUB_ENTRYPOINT=null -- image "${digest}" linux/amd64 linux/arm64
check "an image with a relative entrypoint" fail "names no absolute entrypoint" \
  'STUB_ENTRYPOINT=["gateway"]' -- image "${digest}" linux/amd64 linux/arm64
check "a container that cannot be created" fail "no container could be created from ${digest} for linux/amd64" \
  STUB_CREATE=fail -- image "${digest}" linux/amd64 linux/arm64
check "a vulnerable image binary" fail "linux/arm64:/ko-app/gateway: govulncheck exited 3" \
  STUB_VERDICT=vulnerable -- image "${digest}" linux/amd64 linux/arm64
check "a platform that is not os/arch" fail "linux is not os/arch" -- image "${digest}" linux
check "a reference holding white space" fail "the image reference holds white space" -- image "${digest}"$'\n'"x" linux/amd64

index() {
  local m="" p n=2
  for p in "$@"; do
    n=$((n + 1))
    m+="${m:+,}{\"digest\":\"sha256:$(printf "${n}%.0s" {1..64})\",\"platform\":{\"os\":\"${p%/*}\",\"architecture\":\"${p#*/}\"}}"
  done
  printf '{"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[%s]}' "${m}"
}
check "an index with a platform more" fail \
  "holds images for linux/amd64 linux/arm64 linux/s390x, and the scan names linux/amd64 linux/arm64" \
  "STUB_INDEX=$(index linux/amd64 linux/arm64 linux/s390x)" -- image "${digest}" linux/amd64 linux/arm64
scanned "an index with a platform more" 0
check "an index with a platform fewer" fail \
  "holds images for linux/amd64, and the scan names linux/amd64 linux/arm64" \
  "STUB_INDEX=$(index linux/amd64)" -- image "${digest}" linux/amd64 linux/arm64
check "a manifest where an index belongs" fail "the index of ${digest} could not be read as an image index" \
  'STUB_INDEX={"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{}}' -- image "${digest}" linux/amd64
check "an index manifest with no digest" fail "the index of ${digest} could not be read as an image index" \
  'STUB_INDEX={"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"platform":{"os":"linux","architecture":"amd64"}}]}' \
  -- image "${digest}" linux/amd64
check "an index that cannot be read" fail "the index of ${digest} could not be read as an image index" \
  STUB_INDEX=fail -- image "${digest}" linux/amd64 linux/arm64

printf 'scan-binaries-probe: %d case(s), each passed or refused as named\n' "${cases}"
