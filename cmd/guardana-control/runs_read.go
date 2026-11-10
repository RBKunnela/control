package main

import (
	"errors"
	"flag"
	"fmt"

	"github.com/guardana/control/internal/runs"
	"github.com/guardana/control/internal/runs/signedruns"
)

const runsReadHint = "--roster <file> --root-key <file> --tenant <t> --project <p>"

var errUnsignedJudged = errors.New("--roster, --root-key, --tenant and --project judge a signed runs directory, and this one is not")

// runsReadFlags are what a command that reads a runs directory and writes
// nothing judges a signed layout's records by: the plane's roster, the trust
// root it verifies under, and the plane's tenant and project.
type runsReadFlags struct {
	roster, rootKey, tenant, project valueList
	// routeRoster and routeRootKey are a command's --roster and --root-key
	// when it declares them for a route too, the same plane's files.
	routeRoster, routeRootKey string
	// note names on standard error the roster a signed layout is judged by.
	note *rosterNote
}

func (f *runsReadFlags) declare(flags *flag.FlagSet) {
	flags.Var(&f.roster, "roster", "for a signed --runs: the plane's trust.roster `file`, which every record read has to be signed under; given once")
	flags.Var(&f.rootKey, "root-key", "for a signed --runs: the plane's trust.root_public_key `file`, which the roster has to verify under; given once")
	f.declareScope(flags)
}

// declareScope declares only --tenant and --project, for a command whose
// --roster and --root-key are its route's.
func (f *runsReadFlags) declareScope(flags *flag.FlagSet) {
	flags.Var(&f.tenant, "tenant", "for a signed --runs: the plane's tenant, which every record read has to be of; given once")
	flags.Var(&f.project, "project", "for a signed --runs: the plane's project, which every record read has to be of; given once")
}

func (f runsReadFlags) any() bool {
	return len(f.roster)+len(f.rootKey)+len(f.tenant)+len(f.project) != 0
}

// judge is the roster judge the flags make, refused unless each of the four
// is given once.
func (f runsReadFlags) judge() (runs.Judge, error) {
	if len(f.roster) == 0 && f.routeRoster != "" {
		f.roster = valueList{f.routeRoster}
	}
	if len(f.rootKey) == 0 && f.routeRootKey != "" {
		f.rootKey = valueList{f.routeRootKey}
	}
	for _, l := range []valueList{f.roster, f.rootKey, f.tenant, f.project} {
		if len(l) != 1 || l[0] == "" {
			return nil, fmt.Errorf("%w: a signed runs directory is read with %s, each once", runs.ErrUnjudged, runsReadHint)
		}
	}
	doc, err := readRoster(f.roster[0], f.rootKey[0], f.note)
	if err != nil {
		return nil, err
	}
	return signedruns.Roster{Document: doc, Tenant: f.tenant[0], Project: f.project[0]}, nil
}

// apply gives admin the judge of a signed layout's records, and refuses the
// flags for an unsigned directory, which has nothing to judge.
func (f runsReadFlags) apply(admin *runs.Admin) error {
	if !admin.Signed() {
		if f.any() {
			return errUnsignedJudged
		}
		return nil
	}
	j, err := f.judge()
	if err != nil {
		return err
	}
	admin.JudgeWith(j)
	return nil
}

// openRunsLookup opens dir for a command that looks runs up and writes
// nothing: an unsigned directory as a plane opens it, and a signed layout,
// whose state/ is the plane's, through the operator's handle, which takes a
// record only once the judge the flags make takes it.
func openRunsLookup(dir string, f runsReadFlags) (lookupRun, func() error, error) {
	plane, err := runs.OpenPlane(dir)
	switch {
	case err == nil && f.any():
		return nil, nil, errors.Join(errUnsignedJudged, plane.Close())
	case err == nil:
		return plane.Lookup, plane.Close, nil
	case !errors.Is(err, runs.ErrLayout):
		return nil, nil, err
	}
	admin, err := openRuns(runs.OpenAdmin, dir)
	if err != nil {
		return nil, nil, err
	}
	if err := f.apply(admin); err != nil {
		return nil, nil, errors.Join(err, admin.Close())
	}
	return admin.Lookup, admin.Close, nil
}
