#!/usr/bin/env bash
# Runs the race tests while every processor is kept busy, so a test that
# depends on the clock or on the scheduler's goodwill fails here and not in a
# release gate. It starts one busy loop per processor, runs `make test-race`
# and refuses to report a pass when a loop died meanwhile, since the run was
# then not the loaded one it claims to be.
#
#   scripts/test-race-loaded.sh
set -euo pipefail

die() {
  printf 'test-race-loaded: %s\n' "$*" >&2
  exit 1
}

top="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)"
cd "${top}"

cpus="$(getconf _NPROCESSORS_ONLN)"
[[ "${cpus}" =~ ^[1-9][0-9]*$ ]] || die "cannot read the processor count: ${cpus}"

burners=()
stop() {
  kill "${burners[@]}" 2>/dev/null || true
}
trap stop EXIT
for ((i = 0; i < cpus; i++)); do
  (while :; do :; done) &
  burners+=("$!")
done
printf 'test-race-loaded: %d busy loop(s) on %d processor(s)\n' "${#burners[@]}" "${cpus}"

rc=0
make test-race || rc=$?

alive=0
for pid in "${burners[@]}"; do
  if kill -0 "${pid}" 2>/dev/null; then
    alive=$((alive + 1))
  fi
done
[[ ${alive} -eq ${#burners[@]} ]] ||
  die "only ${alive} of ${#burners[@]} busy loops outlived the tests; the run was not loaded throughout"
[[ ${rc} -eq 0 ]] || die "make test-race failed under load (exit ${rc})"
printf 'test-race-loaded: green with %d busy loop(s) throughout\n' "${alive}"
