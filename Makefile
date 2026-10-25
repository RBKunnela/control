# The one quality gate. CI runs these target names, so do not rename them.
SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
GO ?= go
RANGE ?= HEAD~1..HEAD
PKGS := ./...
FUZZTIME ?= 10s

# An --eval or -E string, on the command line or in MAKEFLAGS or GNUMAKEFLAGS,
# runs before this Makefile is read and can rename the goal or the default
# goal around the guard below, so it is refused whatever the goal. make reports
# every such string in -*-eval-flags-*-, which no eval can clear.
ifneq ($(strip $(-*-eval-flags-*-)$(findstring --eval,$(MAKEFLAGS))),)
$(error this Makefile takes no --eval or -E: $(-*-eval-flags-*-))
endif

# A makefile named in MAKEFILES is read before this one and can undefine
# MAKECMDGOALS, MAKEFILE_LIST or MAKE around every guard below, so it is
# refused whatever the goal. One that also undefines MAKEFILES, like one named
# by -f before this one, is beyond any guard a makefile can hold: CI's command
# line unsets MAKEFILES, and gate-commit.sh starts make with a clean
# environment.
ifneq ($(strip $(value MAKEFILES)),)
$(error this Makefile is read alone; MAKEFILES names $(value MAKEFILES))
endif

# The guard below reads the goals from MAKECMDGOALS. One set on the command
# line or taken from the environment replaces make's own without changing the
# goals make runs, and would turn the guard off, so it is refused whatever
# the goal.
ifneq ($(filter-out default undefined,$(origin MAKECMDGOALS)),)
$(error MAKECMDGOALS is make's own; it comes from the $(origin MAKECMDGOALS))
endif

# With no goal named, make runs .DEFAULT_GOAL, which MAKECMDGOALS does not
# hold, so one set on the command line, through MAKEFLAGS or from the
# environment could run quality around the guard below. It is refused
# whatever the goal.
ifneq ($(filter-out file default undefined,$(origin .DEFAULT_GOAL)),)
$(error .DEFAULT_GOAL is this Makefile's; it comes from the $(origin .DEFAULT_GOAL))
endif

# make quality reports green only over work it did. A dry run, a touch, a
# question, ignored errors or the environment over this Makefile would print
# its last line over recipes that never ran or failed; another makefile, a
# shell startup file, a stand-in for make or go, or a variable set on the
# command line or taken from the environment could redefine what the recipes
# run; and GOFLAGS would change what every go command builds and tests. Each
# is refused before any recipe, however it was set, since an earlier CI step
# can set any of them through the environment. GO=go is the one command-line
# variable allowed, so a caller can name the go it means.
#
# A variable from the environment reaches the recipes' shell as written, not
# as make expands it, so these guards read each one's value unexpanded: a
# spelling that expands to nothing in make, such as SHELLOPTS='$(if ,noexec)',
# still sets it for bash. CDPATH redirects a recipe's cd into a module and
# GLOBIGNORE drops files from a recipe's glob.
ifneq ($(filter quality,$(MAKECMDGOALS)),)
shell_state := $(foreach v,BASH_ENV ENV SHELLOPTS BASHOPTS CDPATH GLOBIGNORE,$(if $(value $(v)),$(v))) $(filter BASH_FUNC_%,$(.VARIABLES))
ifneq ($(strip $(shell_state)),)
$(error make quality starts its recipes' shell clean; BASH_ENV, ENV, SHELLOPTS, BASHOPTS, CDPATH, GLOBIGNORE or an exported function is set: $(strip $(shell_state)))
endif
ifneq ($(words $(MAKEFILE_LIST)),1)
$(error make quality reads one makefile, this one: $(MAKEFILE_LIST))
endif
ifneq ($(origin MAKE),default)
$(error make quality runs its checks through the make that reads this Makefile; MAKE comes from the $(origin MAKE): $(MAKE))
endif
ifneq ($(GO),go)
$(error make quality runs go itself; GO is $(GO))
endif
ifneq ($(strip $(filter-out GO=go,$(MAKEOVERRIDES))),)
$(error make quality sets no variable but GO=go: $(filter-out GO=go,$(MAKEOVERRIDES)))
endif
ifneq ($(origin FUZZTIME) $(origin RANGE),file file)
$(error make quality takes FUZZTIME and RANGE from this Makefile; FUZZTIME comes from the $(origin FUZZTIME), RANGE from the $(origin RANGE))
endif
ifneq ($(strip $(value GOFLAGS)$(shell $(GO) env GOFLAGS 2>/dev/null)),)
$(error make quality builds what the module says; GOFLAGS is set: $(strip $(value GOFLAGS) $(shell $(GO) env GOFLAGS 2>/dev/null)))
endif
ifneq ($(strip $(foreach f,n t q i e,$(findstring $(f),$(firstword -$(MAKEFLAGS))))),)
$(error make quality runs and checks every recipe; MAKEFLAGS asks for a dry run, a touch, a question, ignored errors or the environment over this Makefile: $(MAKEFLAGS))
endif
endif

# This Makefile's own directory. Recipes use paths relative to it, so a recipe
# started from anywhere else changes there first rather than half-working on
# paths that happen to resolve.
ROOT := $(patsubst %/,%,$(dir $(abspath $(firstword $(MAKEFILE_LIST)))))

# make splits variables into whitespace-separated words, so $(dir) and
# $(abspath) above silently truncate a checkout path that contains a space and
# leave ROOT pointing at a parent directory. Refuse to run rather than run the
# gate somewhere else. A quote in the path is fine; a space is not fixable here.
ifeq ($(wildcard $(ROOT)/scripts/lib/repo-files.sh),)
$(error cannot locate the repository root: computed $(ROOT). A path containing \
        whitespace breaks GNU make word splitting; move the checkout)
endif

# The root reaches the recipes through the environment rather than being
# interpolated into the recipe text, so a checkout path containing a quote
# cannot break the shell line make generates.
export REPO_ROOT := $(ROOT)

# Empty in the normal case, where make already runs at the root. That keeps the
# echoed command lines short enough to read the gate as a transcript.
#
# CD uses && so a failed cd stops the command instead of running it in whatever
# directory make happened to start in; RUN gets the same protection from set -e.
ifeq ($(CURDIR),$(ROOT))
CD :=
RUN := set -euo pipefail;
else
CD := cd -- "$$REPO_ROOT" &&
RUN := set -euo pipefail; cd -- "$$REPO_ROOT";
endif

# The project's only file enumerator: git ls-files where a work tree exists,
# find otherwise.
REPO_FILES := scripts/lib/repo-files.sh

# A developer's untracked go.work would make the go command resolve and cover
# modules differently here than in CI, which has none.
export GOWORK := off

# Every Go module the repository holds, the root first.
GO_MODULES := . scripts/lib/go-modules.sh; go_modules

# $(call each_module,command,label) runs the command once per Go module, from
# the root with the shell variable dir naming the module's directory and pkgs
# the packages to cover there, and stops at the first module that fails, naming
# it. ./... stops at a nested go.mod, so a command run once from the root would
# pass without looking at that module. PKGS narrows the root module only. The
# list is read from fd 3 so that a command reading its standard input cannot
# swallow the modules after it.
define each_module
@$(RUN) \
mods=$$($(GO_MODULES)); \
n=0; \
while IFS= read -r dir <&3; do \
  [[ -n "$$dir" ]] || continue; \
  if [[ "$$dir" == . ]]; then pkgs="$(PKGS)"; else pkgs=./...; fi; \
  echo "$(2): module $$dir"; \
  { $(1); } || { echo "$(2): FAIL in module $$dir" >&2; exit 1; }; \
  n=$$((n + 1)); \
done 3<<<"$$mods"; \
if [[ $$n -eq 0 ]]; then echo "$(2): no Go module listed; refusing to report a pass" >&2; exit 1; fi; \
echo "$(2): $$n module(s)"
endef

# Hand-written Go. Generated code under api/gen/ is never reformatted.
GO_SRC := . $(REPO_FILES); repo_files '*.go' | { grep -v '^api/gen/' || true; }

# The gate is read as a transcript; -j would interleave the targets' output
# and hide which one reported what.
.NOTPARALLEL:

# A bare `make` must not run bootstrap, which installs software.
.DEFAULT_GOAL := quality-quick

.PHONY: bootstrap fmt fmt-check vet lint test test-race fuzz-smoke security scan-repo-files-probe \
        proto proto-check proto-breaking docs-check docs-gen docs-impact tidy-check check-brand \
        release-snapshot check-demo-archive scan-binaries scan-binaries-probe \
        check-imports check-imports-probe check-modules-probe check-sizes check-actions \
        check-shell pre-push-probe check-python check-python-probe check-mcp-client \
        quality-quick quality

bootstrap:
	$(CD) scripts/bootstrap.sh

fmt:
	@$(RUN) \
	files=$$($(GO_SRC)); \
	if [[ -z "$$files" ]]; then echo "fmt: no Go source found" >&2; exit 1; fi; \
	gofmt -w $$files; \
	$(GO) tool goimports -w $$files

# Both tools, because fmt runs both: gofmt alone accepts imports that goimports
# would regroup, which would let `quality-quick` pass on a file `make fmt` is
# about to rewrite.
fmt-check:
	@$(RUN) \
	files=$$($(GO_SRC)); \
	if [[ -z "$$files" ]]; then echo "fmt-check: no Go source found" >&2; exit 1; fi; \
	badfmt=$$(gofmt -l $$files); \
	badimports=$$($(GO) tool goimports -l $$files); \
	if [[ -n "$$badfmt$$badimports" ]]; then \
	  [[ -z "$$badfmt" ]] || { echo "fmt-check: not gofmt-clean:" >&2; echo "$$badfmt" >&2; }; \
	  [[ -z "$$badimports" ]] || { echo "fmt-check: not goimports-clean:" >&2; echo "$$badimports" >&2; }; \
	  exit 1; \
	fi; \
	echo "fmt-check: $$(echo "$$files" | wc -l | tr -d ' ') file(s) clean (gofmt, goimports)"

# The second vet compiles the non-unix side of the build constraints, which no
# workflow runner and no release target builds.
vet:
	$(call each_module,$(GO) -C "$$dir" vet $$pkgs && GOOS=windows GOARCH=amd64 $(GO) -C "$$dir" vet $$pkgs,vet)
	@$(RUN) \
	gens=$$(. $(REPO_FILES); repo_files 'scripts/*.go'); \
	if [[ -z "$$gens" ]]; then \
	  echo "vet: no generator under scripts/, and the repository has them, so the search stopped working" >&2; \
	  exit 1; \
	else \
	  for g in $$gens; do \
	    $(GO) build -o /dev/null "$$g" || exit 1; \
	  done; \
	  echo "vet: $$(echo "$$gens" | wc -l | tr -d ' ') generator(s) compile"; \
	fi

# The configuration is named, not discovered: golangci-lint prefers a
# .golangci.yaml, .golangci.toml or .golangci.json beside .golangci.yml, so a
# file dropped at the root would replace the one the security maintainers own
# and the agreement tests read. A nested module is linted with the same file.
lint:
	$(call each_module,(cd -- "$$dir" && golangci-lint run --allow-serial-runners --config "$$REPO_ROOT/.golangci.yml" ./...),lint)

test:
	$(call each_module,$(GO) -C "$$dir" test -count=1 -shuffle=on -json $$pkgs | $(GO) run scripts/test-report.go,test)

# Through the reporter, as test is: a TestMain only a race build compiles could
# otherwise return before m.Run and pass with no test run.
test-race:
	$(call each_module,$(GO) -C "$$dir" test -count=1 -race -json $$pkgs | $(GO) run scripts/test-report.go,test-race)

fuzz-smoke:
	$(CD) scripts/fuzz-smoke.sh $(FUZZTIME)

# actionlint reads workflows only: handed a composite action it parses it as a
# workflow and reports five syntax errors that are not there. zizmor reads
# both, so it is the one that audits .github/actions.
#
# Neither takes a setting from the tree, since each would silence a finding:
# actionlint reads an empty configuration instead of .github/actionlint.yaml,
# and the shellcheck it runs over each run: block reads no rc file; zizmor
# loads no zizmor.yml and honours no "zizmor: ignore" comment.
#
# govulncheck runs from the root, whose go.mod pins it, and changes into each
# module with its own -C.
security:
	$(call each_module,$(GO) tool govulncheck -C "$$dir" ./...,govulncheck)
	$(CD) scripts/scan-repo-files.sh
	@$(RUN) \
	workflows=$$(. $(REPO_FILES); repo_files '.github/workflows/*.yml' '.github/workflows/*.yaml'); \
	actions=""; \
	if [[ -d .github/actions ]]; then \
	  actions=$$(. $(REPO_FILES); repo_files '.github/actions/*action.yml' '.github/actions/*action.yaml'); \
	fi; \
	if [[ -z "$$workflows" && -d .github/workflows ]]; then \
	  echo "security: .github/workflows exists but no workflow file was listed; refusing to report a pass" >&2; \
	  exit 1; \
	fi; \
	if [[ -z "$$actions" && -d .github/actions ]]; then \
	  echo "security: .github/actions exists but no action file was listed; refusing to report a pass" >&2; \
	  exit 1; \
	fi; \
	if [[ -n "$$workflows" ]]; then \
	  echo "$$workflows" | SHELLCHECK_OPTS=--norc xargs actionlint -config-file /dev/null; \
	else \
	  echo "security: SKIP actionlint, no .github/workflows directory"; \
	fi; \
	if [[ -n "$$workflows$$actions" ]]; then \
	  printf '%s\n' $$workflows $$actions | xargs zizmor --no-config --no-ignores; \
	else \
	  echo "security: SKIP zizmor, no workflow or composite action file"; \
	fi

# The negative control of the secret and dependency scan: the script, staged
# in a tree with no .git, must pass a clean tree and refuse a planted secret, a
# lockfile the scanner did not read, a tree with no lockfile and a missing
# scanner. It runs the real scanners, so it needs the network as security does.
scan-repo-files-probe:
	$(CD) scripts/scan-repo-files-probe.sh

proto:
	$(CD) buf generate
	$(CD) buf lint

# The regeneration check compares a fresh tree against the committed one
# rather than asking git for a diff, so it gives the same answer in an export
# with no history.
proto-check:
	$(CD) buf lint
	$(CD) buf format -d --exit-code
	$(CD) scripts/proto-breaking-probe.sh
	@$(RUN) \
	tmp=$$(mktemp -d); \
	trap 'rm -rf "$$tmp"' EXIT; \
	buf generate --output "$$tmp"; \
	diff -r "$$tmp/api/gen" api/gen

# Wire compatibility against the latest release tag before HEAD. Outside
# quality: an export has no history to compare with, and the script then prints
# UNKNOWN and fails, never a pass; scripts/gate-commit.sh compares each commit.
proto-breaking:
	$(CD) scripts/proto-breaking.sh

docs-check:
	$(CD) $(GO) test -count=1 ./internal/docscheck/...

# Rewrites the generated reference pages. Deliberately outside `quality`: a gate
# that regenerates a page cannot also report that the committed page had
# drifted. TestReasonCodesDocIsCurrent and TestObligationsDocIsCurrent report
# that.
# Names the pages a diff makes suspect. Not part of quality: it needs git and
# a range, and says NOT MEASURED when it has neither.
docs-impact:
	$(CD) $(GO) run scripts/docs-impact.go --range $(RANGE)

docs-gen:
	$(CD) $(GO) run scripts/gen-reason-codes.go -o docs/reference/reason-codes.md
	$(CD) $(GO) run scripts/gen-obligations.go -o docs/reference/obligations.md
	$(CD) $(GO) run scripts/gen-diagrams.go -o docs/concepts/enforcement-modes.md
	$(CD) $(GO) run scripts/gen-diagrams.go -o docs/concepts/how-a-call-is-decided.md
	$(CD) $(GO) run scripts/gen-diagrams.go -o docs/concepts/evidence-and-the-spool.md
	$(CD) $(GO) run scripts/gen-metrics.go -o docs/reference/metrics.md
	$(CD) $(GO) run scripts/gen-index.go -o docs/index.md
	$(CD) $(GO) run scripts/gen-config.go -o docs/reference/configuration.md
	$(CD) $(GO) run scripts/gen-wire.go -o docs/reference/wire/action_envelope.md action_envelope.proto
	$(CD) $(GO) run scripts/gen-wire.go -o docs/reference/wire/approval.md approval.proto
	$(CD) $(GO) run scripts/gen-wire.go -o docs/reference/wire/bundle.md bundle.proto
	$(CD) $(GO) run scripts/gen-wire.go -o docs/reference/wire/common.md common.proto
	$(CD) $(GO) run scripts/gen-wire.go -o docs/reference/wire/decision.md decision.proto
	$(CD) $(GO) run scripts/gen-wire.go -o docs/reference/wire/event.md event.proto
	$(CD) $(GO) run scripts/gen-wire.go -o docs/reference/wire/finding.md finding.proto
	$(CD) $(GO) run scripts/gen-wire.go -o docs/reference/wire/result.md result.proto
	$(CD) $(GO) run scripts/gen-pyschema.go -o clients/python/src/guardana_control/enforce/_schema.py
	$(CD) $(GO) run scripts/gen-site.go -o site/index.html

check-brand:
	$(CD) scripts/check-brand.sh

# The archives, bills of materials and checksums a tag would publish, built
# into dist/ without a signature. Not part of quality: it builds eight binaries
# and needs goreleaser and syft. --parallelism=1 keeps each archive's digest
# the same from run to run.
release-snapshot:
	$(CD) goreleaser release --snapshot --clean --skip=sign --parallelism=1

# Runs the demo from this machine's demo archive in dist/, as a release user
# would, with no Go on PATH. It reads what release-snapshot built.
check-demo-archive:
	$(CD) scripts/check-demo-archive.sh dist

# govulncheck in binary mode over every binary of every archive in dist/ and
# the binary of the image release-snapshot loaded, as the dry run scans them.
# Not part of quality: it needs a built dist/, Docker and the vulnerability
# database, which is a network fetch.
scan-binaries:
	$(CD) scripts/scan-binaries.sh archives dist
	@$(RUN) \
	image="goreleaser.ko.local:sha-$$(jq -r .commit dist/metadata.json)"; \
	platform="$$(docker image inspect "$$image" --format '{{.Os}}/{{.Architecture}}')"; \
	scripts/scan-binaries.sh image "$$image" "$$platform"

# The negative control of scan-binaries: the script run against a stand-in go
# and docker, which must pass a clean release and refuse each planted defect.
scan-binaries-probe:
	$(CD) scripts/scan-binaries-probe.sh

check-imports:
	$(CD) scripts/check-imports.sh

# The dependency rule's negative control: plants the rule's fixture in every
# package of every guarded tree of a staged copy of the repository, and fails
# unless every mechanism refuses it.
check-imports-probe:
	$(CD) scripts/check-imports-probe.sh

# The negative control of the targets that loop over every Go module: plants a
# defect in a nested module of a staged tree and fails unless each target
# refuses it, and unless each passes once the module is clean.
check-modules-probe:
	$(CD) scripts/check-modules-probe.sh

# The guide for an existing MCP setup run end to end with an MCP client
# outside the Go SDK and the reference filesystem server. Not part of quality:
# it needs Node.js and the network, and CI runs it as its own job (ADR-0057).
check-mcp-client:
	$(CD) scripts/check-mcp-client.sh

# The Python client: its tests on both pinned interpreters, the linter, the
# type checker and a build of the wheel, each in an emptied environment. A
# missing uv or interpreter fails; make bootstrap installs them.
check-python:
	$(CD) scripts/check-python.sh

# The negative control of check-python: the script, staged with one thing
# planted that would make it examine something other than the commit, must
# refuse each.
check-python-probe:
	$(CD) scripts/check-python-probe.sh

# The negative control of the pre-push hook: a throwaway repository in which
# the hook must refuse an ungated commit sent to main and pass a branch push.
pre-push-probe:
	$(CD) scripts/pre-push-probe.sh

# go.mod and go.sum exactly as `go mod tidy` would write them, so a module a
# change starts importing, or stops needing, shows up here and not in review.
# The pass line is part of the command it reports on, so a recipe that ignored
# the command's failure would lose the line with it.
tidy-check:
	$(call each_module,$(GO) -C "$$dir" mod tidy -diff && echo "tidy-check: go.mod and go.sum are tidy",tidy-check)

check-sizes:
	$(CD) scripts/check-file-sizes.sh

check-actions:
	$(CD) scripts/check-actions-pinned.sh

# Every shell script repo_files lists; scripts/check-shell.sh says what it
# refuses besides shellcheck's own findings.
check-shell:
	$(CD) scripts/check-shell.sh

quality-quick: fmt-check vet test check-imports

# The checks run in a second make with their names written here, because make
# skips a prerequisite it is told is up to date (-o, --old-file, or either in
# MAKEFLAGS or GNUMAKEFLAGS) and would still print the pass line, and that
# option never reaches a make started from a recipe. The second make starts
# with no flags from this one. A makefile named after this one is read after
# the guard, so the makefiles are counted again here.
quality:
	@[ $(words $(MAKEFILE_LIST)) = 1 ] || { echo "make quality reads one makefile, this one; $(words $(MAKEFILE_LIST)) were read" >&2; exit 1; }
	@MAKEFLAGS= GNUMAKEFLAGS= MFLAGS= $(MAKE) --no-print-directory -f "$$REPO_ROOT/$(notdir $(firstword $(MAKEFILE_LIST)))" \
	  fmt-check vet lint test test-race fuzz-smoke security scan-repo-files-probe proto-check \
	  docs-check tidy-check check-imports check-imports-probe check-modules-probe check-brand \
	  check-sizes check-actions check-shell scan-binaries-probe pre-push-probe check-python \
	  check-python-probe
	@echo "quality: green"
