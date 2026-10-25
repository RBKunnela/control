package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policy/rules"
	"github.com/guardana/control/pkg/contract"
)

// signingSeed is the fixed seed of the key every case is signed with. The
// signature only has to verify against the key the same run loads; a fixed
// key keeps two runs of a directory byte-identical, which a key drawn from
// the system's randomness would not.
const signingSeed = "fixed seed for policy test cases"

const signingKeyID = "policy-test"

// policyTest runs every case of dir through the kernel and prints one line
// per case: `ok   name: VERDICT Action [CODES]`, or `FAIL name: ...` with the
// mismatch or the reason the case could not run. It exits 1 when any case
// fails and when the directory holds no case, so an empty directory is
// never a pass.
func policyTest(dir string, stdout, stderr io.Writer) int {
	names, err := caseFiles(dir)
	if err != nil {
		return fail(stderr, "policy test", err)
	}
	status := exitOK
	for _, name := range names {
		line, ok := runCase(filepath.Join(dir, name))
		mark := "ok  "
		if !ok {
			mark = "FAIL"
			status = exitFail
		}
		if _, err := fmt.Fprintf(stdout, "%s %s: %s\n", mark, oneLine(name), line); err != nil {
			return fail(stderr, "policy test", fmt.Errorf("writing to standard output: %w", err))
		}
	}
	return status
}

// caseFiles lists the regular files of dir named *.json, in name order, and
// refuses a directory that holds none. Regularity is decided through Stat,
// which follows a link, so a linked case is run rather than skipped without
// a word; a link that leads nowhere is a refusal.
func caseFiles(dir string) ([]string, error) {
	dir = filepath.Clean(dir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		info, err := os.Stat(filepath.Join(dir, e.Name())) //nolint:gosec // G703: an entry ReadDir listed in the directory the operator named
		if err != nil {
			return nil, err
		}
		if info.Mode().IsRegular() {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("%s: no *.json case in the directory", dir)
	}
	return names, nil
}

// runCase reads, signs, loads and decides one case, and reports its line and
// whether the decision was the one expected. The line is one line whatever
// the case's own text holds.
func runCase(path string) (string, bool) {
	raw, err := readBounded(path)
	if err != nil {
		return oneLine(err.Error()), false
	}
	c, err := readCase(raw)
	if err != nil {
		return oneLine(err.Error()), false
	}
	got, err := decide(c)
	if err != nil {
		return oneLine(err.Error()), false
	}
	if !got.equal(c.expect) {
		return oneLine(fmt.Sprintf("got %s, want %s", got, c.expect)), false
	}
	return got.String(), true
}

// decide signs the case's document in memory, loads it at loaded_at and
// decides the envelope at decided_at. The envelope goes through the JSON
// decoder a receiver would use, and what that decoder refuses is handed to
// the kernel as its refusal rather than stopping the case.
func decide(c *testCase) (outcome, error) {
	p, err := prepare(c, policy.Sign)
	if err != nil {
		return outcome{}, err
	}
	out := p.kernel.Decide(context.Background(), p.request, p.snap)
	if out.Decision == nil {
		return outcome{}, errors.New("the kernel returned no decision")
	}
	return outcome{verdict: out.Decision.GetVerdict(), action: out.Action, codes: out.Decision.GetReasonCodes()}, nil
}

// explainCase is decide through Kernel.Explain, which decides as Decide does.
// It signs with signLoadable, so it explains every document a plane loads,
// one the obligation parameter check refuses among them.
func explainCase(c *testCase) (explained, error) {
	p, err := prepare(c, signLoadable)
	if err != nil {
		return explained{}, err
	}
	out, why := p.kernel.Explain(context.Background(), p.request, p.snap)
	if out.Decision == nil {
		return explained{}, errors.New("the kernel returned no decision")
	}
	ref := p.snap.Ref()
	return explained{
		outcome:  outcome{verdict: out.Decision.GetVerdict(), action: out.Action, codes: out.Decision.GetReasonCodes()},
		decision: out.Decision,
		bundleID: ref.GetBundleId(),
		version:  ref.GetVersion(),
		why:      why,
	}, nil
}

// prepared is a case ready to decide: its kernel, its request and its
// snapshot.
type prepared struct {
	kernel  *core.Kernel
	request core.Request
	snap    *policy.Snapshot
}

// signer signs a case's document in memory.
type signer func(document []byte, key ed25519.PrivateKey, keyID string) (*controlv1.PolicyBundle, error)

// signLoadable signs document as policy.Sign does, without the obligation
// parameter check, which Load does not run either: a bundle signed elsewhere
// can hold what that check refuses and still load. Load then runs every check
// it runs on a plane's bundle, so a bundle this signer gets wrong is refused
// there.
func signLoadable(document []byte, key ed25519.PrivateKey, keyID string) (*controlv1.PolicyBundle, error) {
	doc, canonical, err := rules.Parse(document)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", policy.ErrDocument, err)
	}
	signature, err := bundle.SignBytes(canonical, key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", policy.ErrSigningKey, err)
	}
	return &controlv1.PolicyBundle{
		Ref:             &controlv1.PolicyBundleRef{BundleId: doc.Bundle.ID, Version: doc.Bundle.Version, Digest: bundle.Digest(canonical)},
		Canonical:       canonical,
		SignatureAlg:    bundle.SignatureAlg,
		Signature:       signature,
		KeyId:           keyID,
		MaxStaleSeconds: doc.Bundle.MaxStaleSeconds,
	}, nil
}

func prepare(c *testCase, sign signer) (prepared, error) {
	key := ed25519.NewKeyFromSeed([]byte(signingSeed))
	signed, err := sign(c.document, key, signingKeyID)
	if err != nil {
		return prepared{}, err
	}
	keys := bundle.Keyring{signingKeyID: key.Public().(ed25519.PublicKey)}
	snap, err := policy.Load(signed, keys, c.loadedAt)
	if err != nil {
		return prepared{}, err
	}
	kernel, err := core.New(c.options, func() time.Time { return c.decidedAt }, func() string { return "policy-test" })
	if err != nil {
		return prepared{}, err
	}
	env, refusal := contract.DecodeJSON(c.envelope)
	return prepared{
		kernel: kernel,
		request: core.Request{
			Envelope:       env,
			Refusal:        refusal,
			AuthorizedArgs: c.authorizedArgs,
			Flow:           c.flow,
			External:       c.external,
		},
		snap: snap,
	}, nil
}

// String spells an outcome the way a case's expect member does, so a line
// and the member an author would write to make it pass read the same.
func (o outcome) String() string {
	return fmt.Sprintf("%s %s [%s]", verdictName(o.verdict), actionName(o.action), strings.Join(o.codes, " "))
}
