#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# The dependency rule's negative control. In a copy of the files the repository
# holds, it plants the fixture from internal/core/testdata/dependency-probe and
# requires each mechanism to refuse it for the reasons that mechanism answers
# for:
#   check-imports.sh, layering_test.go  every planted import, os/exec reached
#                                       through a helper package, that helper
#                                       lying outside the trees the name
#                                       refusals cover, each file a
#                                       guarded package holds that is not plain
#                                       Go built on this platform or that the
#                                       foreign platform leaves out, each Go
#                                       file with a build constraint line in a
#                                       guarded or reached tree, and a package
#                                       left out of every listing by its file's
#                                       name
#   layering_test.go                    each //nolint that excuses a guarded
#                                       file from depguard or forbidigo, and
#                                       each clock, input and randomness read
#                                       by name, in a guarded or reached tree
#   golangci-lint, depguard             every planted import, and net/http in
#                                       a planted test file
#   golangci-lint, forbidigo            each clock read, I/O function and draw
#                                       on the system's randomness, in a
#                                       guarded or reached tree
#   go mod tidy -diff                   a module imported with no direct
#                                       requirement in go.mod
#
# The lint fixture goes into every package of every guarded tree and of each
# tree the probe names itself, its package clause rewritten, and into one new
# package per tree, which also takes the platform fixture. An exclusion that
# spares a path, a file name or generated code therefore loses a refusal
# wherever it lands. A second new package per tree holds only a file its name
# keeps to FreeBSD, so no listing names it. The fixture's clock and I/O reads
# alone also go into every package of each tree a guarded tree reaches, where
# a helper would otherwise read the clock for it, and so does a file whose
# constraint line every listed platform satisfies, which only the line itself
# shows.
# golangci-lint runs with the configuration `make lint` names and every linter
# that configuration enables, so what the probe proves is what `make lint` runs.
#
# A mechanism that fails without naming the reason, because the probe stopped
# compiling for instance, has refused nothing, and the probe fails.
set -euo pipefail

# source= resolves against this script's directory through line 2.
_PROBE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
# shellcheck source=lib/repo-files.sh
. "${_PROBE_DIR}/lib/repo-files.sh"
# shellcheck source=lib/dependency-rule.sh
. "${_PROBE_DIR}/lib/dependency-rule.sh"

die() {
  printf 'check-imports-probe: %s\n' "$*" >&2
  exit 1
}

root="$(repo_root)"
fixture="${root}/internal/core/testdata/dependency-probe"
[[ -d "${fixture}" ]] || die "missing fixture directory ${fixture}"
for tool in go golangci-lint; do
  command -v "${tool}" >/dev/null 2>&1 || die "${tool} is not on PATH, so the probe cannot run"
done

copy="$(mktemp -d)"
trap 'rm -rf "${copy}"' EXIT
staged="$(repo_stage "${copy}")"

module="$(cd "${copy}" && GOWORK=off go list -m)"
adapter="${module}/adapters/probeadapter"
helper="${module}/internal/probehelper"
not_allowed="which the dependency rule does not allow"
left_out="which build constraints leave out on this platform"
foreign_out="which build constraints leave out on ${foreign_platform[0]}/${foreign_platform[1]}"
constrained="holds a build constraint, so it may not build from the same files on every platform"
unlisted="is named by no go list listing on"
outside_scope="is reached by a guarded tree and lies outside every tree in which the rule refuses clock, input and randomness reads by name"
timestamppb="google.golang.org/protobuf/types/known/timestamppb"

# The trees the probe plants in: these, written out, and every other tree the
# rule's lists guard; then the reached trees the same way. A tree dropped from
# every list at once keeps its fixture and fails the probe, where planting only
# what the lists name would not.
trees=(
  internal/core
  internal/policy
  internal/canon
  internal/evidence
  pkg/contract
  internal/supervise
)
for tree in "${guarded[@]}"; do
  case " ${trees[*]} " in
    *" ${tree} "*) ;;
    *) trees+=("${tree}") ;;
  esac
done
reached_trees=(
  internal/channel
  internal/observe
  internal/trailchain
)
for tree in "${reached[@]}"; do
  case " ${reached_trees[*]} " in
    *" ${tree} "*) ;;
    *) reached_trees+=("${tree}") ;;
  esac
done

# list_targets <tree>
# Appends to `targets` one "<directory> <package name>" line per package of the
# tree as the staged copy holds it, before anything is planted.
list_targets() {
  local listing path name
  [[ -d "${copy}/$1" ]] || die "tree $1 is not in the staged copy; the probe does not create it"
  listing="$(cd "${copy}" && go list -f '{{.ImportPath}} {{.Name}}' "./$1/...")" ||
    die "go list ./$1/... failed in the copy"
  [[ -n "${listing}" ]] || die "tree $1 holds no package in the staged copy"
  while read -r path name; do
    [[ -n "${path}" ]] || continue
    [[ "${path}" == "${module}/"* ]] || die "go list named ${path}, which is not a package of ${module}"
    targets+="${path#"${module}/"} ${name}"$'\n'
  done <<<"${listing}"
}

# The packages of those trees as the repository holds them, listed before
# anything is planted, one "<directory> <package name>" line each; then the new
# package the probe adds to every guarded tree. A reached tree gets none, since
# no guarded tree would reach it. A tree the staged copy does not hold is a
# failure, not a place to plant: creating it here would report every expected
# refusal for a tree the rule no longer examines.
targets=""
for tree in "${trees[@]}"; do
  list_targets "${tree}"
  targets+="${tree}/ioprobe ioprobe"$'\n'
done
lint_targets="${targets}"
targets=""
for tree in "${reached_trees[@]}"; do
  list_targets "${tree}"
done
reads_targets="${targets}"

# plant <fixture subdirectory> <directory in the copy> <package name> [<file>]
# Copies every file of the fixture subdirectory, or the one file named, the
# package clause of each Go file rewritten to the package it joins.
plant() {
  local file
  [[ "$3" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || die "the package in $2 is named '$3', which is not an identifier"
  mkdir -p "${copy}/$2"
  for file in "${fixture}/$1"/${4:-*}; do
    [[ -f "${file}" ]] || die "the fixture holds no ${file}"
    sed "s/^package ioprobe\$/package $3/" "${file}" >"${copy}/$2/${file##*/}"
  done
}

plant probeadapter adapters/probeadapter probeadapter
plant probehelper internal/probehelper probehelper
lint_dirs=()
while read -r dir name; do
  [[ -n "${dir}" ]] || continue
  plant lint "${dir}" "${name}"
  lint_dirs+=("${dir}")
done <<<"${lint_targets}"
reads_dirs=()
while read -r dir name; do
  [[ -n "${dir}" ]] || continue
  plant lint "${dir}" "${name}" zz_probe_reads.go
  plant platform "${dir}" "${name}" zz_probe_notplan9.go
  reads_dirs+=("${dir}")
done <<<"${reads_targets}"
for tree in "${trees[@]}"; do
  plant platform "${tree}/ioprobe" ioprobe
  plant nameonly "${tree}/nameprobe" nameprobe
done

failures=0
expected=0
runs=0
out=""
shown=""

# run <mechanism> <command...>
# Runs the command in the copy and keeps its output for expect. Exit 0 is a
# failure of the probe: the mechanism accepted what it had to refuse.
run() {
  local name="$1" rc=0
  shift
  runs=$((runs + 1))
  shown=""
  out="$(cd "${copy}" && "$@" 2>&1)" || rc=$?
  if [[ ${rc} -eq 0 ]]; then
    printf 'check-imports-probe: %s exited 0 over the probe\n' "${name}" >&2
    failures=$((failures + 1))
  fi
}

# expect <mechanism> <text a line must hold> [<more text the same line must hold>]
# The first miss also prints the head of the mechanism's output, which is where
# a compile error that stopped it would show.
expect() {
  local lines
  expected=$((expected + 1))
  lines="$(grep -F -- "$2" <<<"${out}" || true)"
  if [[ -n "${lines}" ]] && grep -qF -- "${3:-$2}" <<<"${lines}"; then
    return 0
  fi
  printf 'check-imports-probe: %s did not report: %s %s\n' "$1" "$2" "${3:-}" >&2
  failures=$((failures + 1))
  if [[ "${shown}" != *"[$1]"* ]]; then
    shown+="[$1]"
    printf -- '--- the first 30 lines %s printed:\n' "$1" >&2
    head -n 30 <<<"${out}" >&2
    printf -- '---\n' >&2
  fi
}

# expect_walker <mechanism> <line prefix>
# The refusals the two go list walkers share, in their shared wording.
expect_walker() {
  local dir tree imp file
  for dir in "${lint_dirs[@]}"; do
    for imp in net os io/ioutil golang.org/x/sync/errgroup; do
      expect "$1" "$2${module}/${dir} imports ${imp}, ${not_allowed}"
    done
    expect "$1" "$2${module}/${dir} imports ${adapter}, a tree the dependency rule denies"
  done
  # A machine that is not amd64 also leaves zz_probe_amd64.go out of its own
  # listing; only the foreign refusal holds on every machine the gate runs on.
  for tree in "${trees[@]}"; do
    expect "$1" "$2${module}/${tree}/ioprobe holds zz_probe_windows.go, ${left_out}"
    expect "$1" "$2${module}/${tree}/ioprobe holds zz_probe_other.go, ${left_out}"
    expect "$1" "$2${module}/${tree}/ioprobe holds zz_probe_unix.go, ${foreign_out}"
    expect "$1" "$2${module}/${tree}/ioprobe holds zz_probe_amd64.go, ${foreign_out}"
    for file in zz_probe_other.go zz_probe_unix.go zz_probe_notplan9.go; do
      expect "$1" "$2${tree}/ioprobe/${file} ${constrained}"
    done
    expect "$1" "$2${module}/${tree}/ioprobe holds zz_probe_s390x.s, ${left_out}"
    expect "$1" "$2${module}/${tree}/ioprobe holds zz_probe.s, which is not plain Go (SFiles)"
    expect "$1" "$2${tree}/nameprobe/zz_probe_freebsd.go ${unlisted} this platform"
    expect "$1" "$2${tree}/nameprobe/zz_probe_freebsd.go ${unlisted} ${foreign_platform[0]}/${foreign_platform[1]}"
  done
  for dir in "${reads_dirs[@]}"; do
    expect "$1" "$2${dir}/zz_probe_notplan9.go ${constrained}"
  done
  expect "$1" "$2${helper} imports os/exec, ${not_allowed}"
  expect "$1" "$2${helper} ${outside_scope}"
}

run check-imports.sh scripts/check-imports.sh
expect_walker check-imports.sh "FAIL "

run layering_test.go go test -count=1 \
  -run '^(TestGuardedTreesImportOnlyAllowedPackages|TestGuardedTreesTakeNoInlineException|TestGuardedAndReachedFilesHoldNoBuildConstraint|TestGuardedFilesAreNamedByEveryListing|TestReachedPackagesReadNothingByName)$' \
  ./internal/core/
expect_walker layering_test.go ""
for dir in "${lint_dirs[@]}"; do
  expect layering_test.go "${dir}/zz_probe.go:" "excuses a guarded file from forbidigo"
  expect layering_test.go "${dir}/zz_probe_test.go:" "excuses a guarded file from depguard"
  expect layering_test.go "${dir}/zz_probe.go:" "names time.Now, "
done
for dir in "${lint_dirs[@]}" "${reads_dirs[@]}"; do
  for name in time.Now time.Since time.Until time.After time.AfterFunc time.Tick \
    time.NewTicker time.NewTimer time.Sleep "${timestamppb}.Now" context.WithTimeout \
    context.WithDeadline fmt.Scanln time.LoadLocation time.Local "the method Local" \
    "the method Zone" "the method ZoneBounds" "the method IsDST" crypto/ed25519.GenerateKey; do
    expect layering_test.go "${dir}/zz_probe_reads.go:" "names ${name}, "
  done
done

# Every linter the configuration enables, over every guarded tree, and no
# collapsing: by default golangci-lint keeps one issue per line and three of the
# same text, which would drop expected refusals for reasons that have nothing
# to do with the rule.
lint=(golangci-lint run --config .golangci.yml --uniq-by-line=false
  --max-issues-per-linter=0 --max-same-issues=0 --output.text.print-issued-lines=false)
for tree in "${trees[@]}" "${reached_trees[@]}"; do
  lint+=("./${tree}/...")
done
run golangci-lint "${lint[@]}"
for dir in "${lint_dirs[@]}"; do
  for imp in net os io/ioutil golang.org/x/sync/errgroup "${adapter}"; do
    expect depguard "${dir}/zz_probe.go:" "import '${imp}' is not allowed from list 'core'"
  done
  expect depguard "${dir}/zz_probe_test.go:" "import 'net/http' is not allowed from list 'core-tests'"
  expect forbidigo "${dir}/zz_probe.go:" "use of \`time.Now\` forbidden"
done
for dir in "${lint_dirs[@]}" "${reads_dirs[@]}"; do
  for call in probeclock.Now probeclock.Since probeclock.Until probeclock.After \
    probeclock.AfterFunc probeclock.Tick probeclock.NewTicker probeclock.NewTimer \
    probeclock.Sleep timestamppb.Now context.WithTimeout context.WithDeadline \
    fmt.Scanln probeclock.LoadLocation probeclock.Local t.Local t.Zone t.ZoneBounds p.IsDST \
    ed25519.GenerateKey; do
    expect forbidigo "${dir}/zz_probe_reads.go:" "use of \`${call}\` forbidden"
  done
done

run 'go mod tidy -diff' go mod tidy -diff
# The line tidy adds when the module moves into the direct requirements.
expect 'go mod tidy -diff' $'+\tgolang.org/x/sync v'

if [[ ${failures} -ne 0 ]]; then
  printf 'check-imports-probe: %d failure(s) against %d expected refusal(s); the dependency rule let part of the probe through\n' \
    "${failures}" "${expected}" >&2
  exit 1
fi
printf 'check-imports-probe: %d file(s) staged, the fixture planted in %d package(s) of %d guarded tree(s) and its reads in %d package(s) of %d reached tree(s); all %d expected refusal(s) reported by %d command(s)\n' \
  "${staged}" "${#lint_dirs[@]}" "${#trees[@]}" "${#reads_dirs[@]}" "${#reached_trees[@]}" "${expected}" "${runs}"
