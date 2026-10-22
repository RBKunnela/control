#!/usr/bin/env bash
# shellcheck disable=SC2034 # every array is read by a script that sources this file
# The dependency rule's lists for the shell half of the gate. check-imports.sh
# enforces them; check-imports-probe.sh plants its fixture in every guarded
# tree. The depguard rules in .golangci.yml and internal/core/layering_test.go
# carry the same lists, and internal/core/layering_agreement_test.go fails when
# any two disagree.
#
# The rule is an allowlist. A package in a guarded tree may import a package of
# this module outside the denied trees, any package of a module in `modules`,
# and a standard library package named in `stdlib`. Nothing else.
#
# Each array holds one bare word per line: the agreement test reads this file
# as text.

# Trees that hold the decision path, or judge a run against its procedure, and
# must stay free of I/O.
guarded=(
  internal/core
  internal/policy
  internal/canon
  internal/evidence
  pkg/contract
  internal/supervise
)

# Trees of this module outside `guarded` that the non-test build of a guarded
# tree reaches. A reached package is held to the import rule and to the same
# files on every platform like a guarded one, and .golangci.yml refuses the same
# clock, input and randomness reads by name in it: otherwise a helper would be a
# way around them. A guarded tree that reaches a package of this module under
# neither list fails check-imports.sh, and so does an entry here that no guarded
# tree reaches any more.
reached=(
  internal/observe
  internal/trailchain
)

# Trees of this module that a guarded tree must not import.
denied=(
  adapters
  internal/storage
  internal/controlapi
  internal/gateway
  internal/ingest
)

# Modules outside this one, every package of which a guarded tree may import.
modules=(
  google.golang.org/protobuf
)

# Trees of this module accepted whole, their own imports not examined.
# Generated code imports reflect and unsafe by construction, and proto-check
# keeps it equal to what the pinned generator writes.
generated=(
  api/gen
)

# Standard library packages a guarded tree may import, matched exactly: "io"
# does not admit "io/ioutil". None opens a connection, a file or a process,
# reads the environment or draws randomness, except through functions
# .golangci.yml refuses by name in the guarded and reached trees (time.Now,
# time.Sleep, fmt.Scan, ed25519.GenerateKey and the like); fmt.Print is refused
# everywhere.
# A read that no name reveals is not refused: time.Unix(...).Format reads the
# local zone. crypto/ed25519 imports crypto/rand itself, which the rule does not
# examine.
stdlib=(
  bufio
  bytes
  cmp
  context
  crypto/ed25519
  crypto/sha256
  crypto/subtle
  encoding/binary
  encoding/hex
  encoding/json
  errors
  fmt
  io
  maps
  math
  math/bits
  slices
  sort
  strconv
  strings
  sync
  sync/atomic
  time
  unicode
  unicode/utf16
  unicode/utf8
)

# go list fields a package held to the rule may not hold a file in. The first
# two list what build constraints leave out on this platform, which a build for
# another platform compiles and the gate on this one never sees. The rest is
# every source the go command compiles or links besides plain Go, and any of
# those reaches the clock or the kernel with no import at all. A package held to
# the rule therefore builds from the same Go files on every platform.
refused_files=(
  IgnoredGoFiles
  IgnoredOtherFiles
  CgoFiles
  CFiles
  CXXFiles
  MFiles
  HFiles
  FFiles
  SFiles
  SwigFiles
  SwigCXXFiles
  SysoFiles
)

# The platform, GOOS then GOARCH, for which every package held to the rule is
# listed once more, for the files a name suffix (_GOOS, _GOARCH, _GOOS_GOARCH)
# keeps to other platforms. It shares neither its GOOS nor its GOARCH with a
# machine the gate runs on (darwin/arm64, linux/amd64), so a suffix one of
# those compiles, _linux or _amd64, is left out of this listing. A constraint
# line is not left to the listings: `//go:build !plan9` holds on every platform
# listed, so check-imports.sh refuses the line itself.
foreign_platform=(
  windows
  386
)
