package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/coverage"
	ondisk "github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/observe"
	"github.com/guardana/control/internal/observelog"
)

const (
	coverageName = "coverage"
	coverageForm = "--inventory <file> [--plane <config> [--evidence <export>]]...\n" +
		"      [--source <descriptor> --log <dir>]..."
	coverageUsage = "takes --inventory once, any --plane each followed by at most one --evidence, " +
		"and each --source with its --log, in order"
)

const (
	// maxInventoryFileBytes is coverage.ReadInventory's own bound.
	maxInventoryFileBytes = 1 << 20
	// maxExportFileBytes bounds one evidence export, which is read whole.
	maxExportFileBytes = 256 << 20
)

// valueList is a flag given once per value.
type valueList []string

func (l *valueList) String() string { return strings.Join(*l, " ") }

func (l *valueList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

type coverageArgs struct {
	inventory, planes, sources, logs valueList
	// evidence is the export given for each plane, by its index in planes.
	evidence map[int]string
}

// planeEvidence is --evidence, the export of the --plane given before it:
// an export says nothing of a plane whose trail it is not.
type planeEvidence struct{ a *coverageArgs }

func (e *planeEvidence) String() string { return "" }

func (e *planeEvidence) Set(v string) error {
	i := len(e.a.planes) - 1
	if i < 0 {
		return errors.New("an --evidence is the export of the --plane before it, and none is")
	}
	if _, ok := e.a.evidence[i]; ok {
		return fmt.Errorf("--plane %s has an --evidence already", strconv.Quote(e.a.planes[i]))
	}
	e.a.evidence[i] = v
	return nil
}

func coverageFlags(command string, out io.Writer) (*flag.FlagSet, *coverageArgs) {
	flags := commandFlags(command, out)
	a := &coverageArgs{evidence: map[int]string{}}
	flags.Var(&a.inventory, "inventory", "the inventory of declared paths, a JSON `file` of this account that no other account may write; given once")
	flags.Var(&a.planes, "plane", "a plane's configuration `file`, read without this shell's environment; repeatable")
	flags.Var(&a.sources, "source", "a source descriptor `file`, paired in order with --log; one that does not exist covers nothing; repeatable")
	flags.Var(&a.logs, "log", "the observation log `dir` of the --source in the same place; one with no log yet was never heard; repeatable")
	flags.Var(&planeEvidence{a}, "evidence", "the evidence `export` of the --plane before it, as the gateway's trail export wrote it, "+
		"to join observations with; at most one per plane")
	return flags, a
}

func coverageFlagSet(command string, out io.Writer) *flag.FlagSet {
	flags, _ := coverageFlags(command, out)
	return flags
}

// coverageCommand prints, for each declared path, what covers it and on what
// basis, then the standing row for undeclared paths. It exits 0 when every
// declared path is at least observed and no call went around a plane, 1 when
// one is weaker, one did or a walk down a trace was cut at its bound, and 2
// when an input was refused, with no map printed.
func coverageCommand(args []string, stdout, stderr io.Writer) int {
	flags, a := coverageFlags(coverageName, io.Discard)
	err := flags.Parse(args)
	switch {
	case err != nil:
		return refuseCoverage(stderr, err.Error()+"; "+coverageUsage)
	case flags.NArg() != 0 || len(a.inventory) != 1 || len(a.sources) != len(a.logs):
		return refuseCoverage(stderr, coverageUsage)
	}
	in, err := readCoverageInput(a)
	if err != nil {
		return refuseCoverage(stderr, err.Error())
	}
	// Read after every log, so no import report the command read was
	// received after the time liveness is measured to.
	in.Now = time.Now()
	report, err := coverage.Map(in)
	if err != nil {
		return refuseCoverage(stderr, err.Error())
	}
	if _, err := io.WriteString(stdout, strings.Join(report.Lines(), "\n")+"\n"); err != nil {
		return refuseCoverage(stderr, "writing to standard output: "+err.Error())
	}
	return coverage.ExitStatus(report, nil)
}

func refuseCoverage(stderr io.Writer, message string) int {
	writeLine(stderr, brand.CLI+": "+coverageName+": "+oneLine(message))
	return coverage.ExitRefused
}

func readCoverageInput(a *coverageArgs) (coverage.Input, error) {
	var in coverage.Input
	inv, err := readInventoryFile(a.inventory[0])
	if err != nil {
		return in, err
	}
	in.Inventory = inv
	for i, path := range a.planes {
		p, err := readPlane(path)
		if err != nil {
			return in, err
		}
		if x, ok := a.evidence[i]; ok {
			if p.Export, err = readEvidence(x); err != nil {
				return in, err
			}
		}
		in.Planes = append(in.Planes, p)
	}
	for i := range a.sources {
		src, present, err := readSource(a.sources[i], a.logs[i])
		if err != nil {
			return in, err
		}
		if present {
			in.Sources = append(in.Sources, src)
		} else {
			in.AbsentDescriptors = append(in.AbsentDescriptors, a.sources[i])
		}
	}
	return in, nil
}

func refusedInput(flagName, path string, err error) error {
	return fmt.Errorf("--%s %s: %w", flagName, strconv.Quote(path), err)
}

// readInventoryFile reads the inventory as the descriptor is read: it states
// what the map is judged against, so only its owner may write it.
func readInventoryFile(path string) (*coverage.Inventory, error) {
	raw, err := ondisk.ReadOwned(path, maxInventoryFileBytes, descriptorForbidden, os.Geteuid())
	if err != nil {
		return nil, refusedInput("inventory", path, err)
	}
	inv, err := coverage.ReadInventory(raw)
	if err != nil {
		return nil, refusedInput("inventory", path, err)
	}
	return inv, nil
}

// readPlane loads a plane's configuration with no environment: the shell
// running this command is not the plane's, so its variables say nothing of
// how the plane runs. A plane serving the enforcement API is cooperative, and
// its tool table names the tools it decides.
func readPlane(path string) (coverage.Plane, error) {
	cfg, err := gatewayconfig.Load(path, nil)
	if err != nil {
		return coverage.Plane{}, refusedInput("plane", path, err)
	}
	mode, err := cfg.Mode()
	if err != nil {
		return coverage.Plane{}, refusedInput("plane", path, err)
	}
	p := coverage.Plane{Name: path, Mode: mode, FailOpenRead: cfg.Policy.FailOpenRead, Cooperative: cfg.Listener.Kind == gatewayconfig.ListenerEnforceAPI}
	for i := range cfg.Tools {
		c, err := cfg.Tools[i].Classification()
		if err != nil {
			return coverage.Plane{}, refusedInput("plane", path, fmt.Errorf("tools.%d.%w", i, err))
		}
		p.Tools = append(p.Tools, coverage.Tool{Name: cfg.Tools[i].Name, Effect: c.Effect})
	}
	for _, u := range cfg.Upstreams {
		p.Upstreams = append(p.Upstreams, u.Name)
	}
	for i := range cfg.Overrides {
		o := &cfg.Overrides[i]
		c, err := o.Classification()
		if err != nil {
			return coverage.Plane{}, refusedInput("plane", path, fmt.Errorf("overrides.%d.%w", i, err))
		}
		p.Overrides = append(p.Overrides, coverage.Override{Upstream: o.Upstream, Tool: o.Tool, Fingerprint: o.Fingerprint, Effect: c.Effect})
	}
	return p, nil
}

// readSource reads one source's descriptor as observe import does, and its
// log. A descriptor that does not exist is a removed source: it is not
// passed, so the paths naming it are not covered by it, and its log is not
// read. A log directory that holds no log yet gives no records, which is
// never heard.
func readSource(descriptor, logDir string) (coverage.Source, bool, error) {
	raw, err := ondisk.ReadOwned(descriptor, maxDescriptorBytes, descriptorForbidden, os.Geteuid())
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return coverage.Source{}, false, nil
	case err != nil:
		return coverage.Source{}, false, refusedInput("source", descriptor, err)
	}
	desc, err := observe.ReadDescriptor(raw)
	if err != nil {
		return coverage.Source{}, false, refusedInput("source", descriptor, err)
	}
	if err := ondisk.CheckDir(logDir, 0); err != nil {
		return coverage.Source{}, false, refusedInput("log", logDir, err)
	}
	records, err := observelog.ReadFile(filepath.Join(logDir, observelog.FileName))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return coverage.Source{}, false, refusedInput("log", logDir, err)
	}
	return coverage.Source{Descriptor: desc, Records: records}, true, nil
}

// readExportFile reads an export as the descriptor is read: what it holds is
// taken as the plane's evidence, so only its owner may write it, and as a
// regular file, so a pipe or a device put at its name cannot hold the command.
func readExportFile(path string) ([]byte, error) {
	raw, err := ondisk.ReadOwned(path, maxExportFileBytes, descriptorForbidden, os.Geteuid())
	if err != nil {
		return nil, refusedInput("evidence", path, err)
	}
	return raw, nil
}

func readEvidence(path string) (*coverage.Export, error) {
	raw, err := readExportFile(path)
	if err != nil {
		return nil, err
	}
	x, err := coverage.ReadExport(bytes.NewReader(raw))
	if err != nil {
		return nil, refusedInput("evidence", path, err)
	}
	return x, nil
}
