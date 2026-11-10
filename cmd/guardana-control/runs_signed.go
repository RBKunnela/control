package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/runs"
	"github.com/guardana/control/internal/runs/signedruns"
)

// runsSignHint is what an operator adds to write a signed layout.
const runsSignHint = "--key <operator key file> --roster <roster file> --root-key <trust root public key file>"

// runSignFlags is what a signed write of a runs directory is told: the
// operator's key, and the roster and trust root its records, and the records
// it signs over, are checked against.
type runSignFlags struct {
	key, roster, rootKey *string
}

func runsSignFlags(flags *flag.FlagSet) runSignFlags {
	return runSignFlags{
		key:     flags.String("key", "", "the operator's private key file, which signs the record for a plane under the signed authority"),
		roster:  flags.String("roster", "", "the plane's trust.roster, which every record signed or signed over has to be signed under"),
		rootKey: flags.String("root-key", "", "the plane's trust.root_public_key, which the roster has to verify under"),
	}
}

// given reports whether any of the three flags was given; problem says what
// is wrong with what was.
func (f runSignFlags) given() (bool, string) {
	set := 0
	for _, v := range []*string{f.key, f.roster, f.rootKey} {
		if *v != "" {
			set++
		}
	}
	switch set {
	case 0:
		return false, ""
	case 3:
		return true, ""
	}
	return true, "a signed write takes " + runsSignHint + ", all three"
}

// authority reads the roster, verified under the root key and usable now,
// into the judge every record signed or signed over is held to: an operator
// key of it granted operate over tenant and project signed it, for the
// directory the write is in, and tells note which roster it took. It reads
// the operator key into a signer, which is kept for the command's life and
// cleared by release.
func (f runSignFlags) authority(tenant, project string, note *rosterNote) (runs.Signer, runs.Judge, func(), error) {
	doc, err := readRoster(*f.roster, *f.rootKey, note)
	if err != nil {
		return runs.Signer{}, nil, nil, err
	}
	key, err := policykey.ReadPrivate(*f.key)
	if err != nil {
		return runs.Signer{}, nil, nil, fmt.Errorf("--key: %w", err)
	}
	s := runs.Signer{KeyID: policykey.KeyID(publicHalf(key)), Sign: func(payloadType string, body []byte) ([]byte, error) {
		return bundle.SignBytesAs(payloadType, body, key)
	}}
	return s, signedruns.Roster{Document: doc, Tenant: tenant, Project: project}, func() { clear(key) }, nil
}

// runsHint is what an operator does about a write the directory refused: a
// signed layout takes only a signed write, and a signed write signs over no
// record the roster does not vouch for.
func runsHint(err error) error {
	switch {
	case errors.Is(err, runs.ErrSigned):
		return fmt.Errorf("%w; sign it with %s", err, runsSignHint)
	case errors.Is(err, runs.ErrNotVouched):
		return fmt.Errorf("%w; nothing was signed: someone without a roster key may have written that record, so read it before anything is signed over it", err)
	}
	return err
}

// signedRunLine is what a signed write says it signed, on standard error:
// the run, its state, its tenant and project, the records/ it is bound to
// and the key.
func signedRunLine(command string, rec runs.Record, binding, keyID string) string {
	state := "open, expires_at " + stampOf(rec.ExpiresAt)
	if rec.Closed() {
		state = "closed at " + stampOf(rec.ClosedAt)
	}
	return fmt.Sprintf("%s: %s: signed run %s %s, root %s, tenant %s project %s, for %s, with key %s", brand.CLI, command,
		rec.ID, state, rec.Root, oneLine(rec.Who.TenantID), oneLine(rec.Who.ProjectID), oneLine(binding), oneLine(keyID))
}

// writeSigned says on stderr what a signed write signed.
func writeSigned(stderr io.Writer, command string, rec runs.Record, binding, keyID string) {
	writeLine(stderr, signedRunLine(command, rec, binding, keyID))
}
