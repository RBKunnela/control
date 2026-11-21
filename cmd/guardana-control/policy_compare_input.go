package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/guardana/control/internal/coverage"
	ondisk "github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policy/rules"
	"github.com/guardana/control/internal/policycompare"
	"github.com/guardana/control/pkg/contract"
)

// readCompareInput reads and signs both documents, reads every case, the
// export and the labels, and refuses the run at the first input it cannot
// take whole.
func readCompareInput(a *compareArgs) (policycompare.Run, error) {
	run := policycompare.Run{Build: version}
	var err error
	if run.Current, err = signCompared("current", a.current); err != nil {
		return run, err
	}
	if run.Candidate, err = signCompared("candidate", a.candidate); err != nil {
		return run, err
	}
	digest := run.Current.Bundle.GetRef().GetDigest()
	if a.cases != "" {
		cases, source, err := readComparedCases(a.cases, digest)
		if err != nil {
			return run, err
		}
		run.Cases, run.Provenance.Cases = cases, source
	}
	if a.evidence != "" {
		cases, source, err := readComparedEvidence(a.evidence, digest)
		if err != nil {
			return run, err
		}
		run.Cases, run.Provenance.Evidence = append(run.Cases, cases...), source
	}
	if a.labels != "" {
		raw, err := ondisk.ReadRegular(a.labels, maxLabelsBytes, 0)
		if err != nil {
			return run, refusedInput("labels", a.labels, err)
		}
		if run.Labels, err = policycompare.ReadLabels(raw); err != nil {
			return run, refusedInput("labels", a.labels, err)
		}
		run.Provenance.Labels = &policycompare.LabelsSource{Path: a.labels, SHA256: sha256Of(raw), Labeller: run.Labels.Labeller}
	}
	return run, nil
}

// signCompared signs a document in memory with the key policy test signs
// with, as policy explain does, so a document a plane would load compares.
func signCompared(flagName, path string) (policycompare.Policy, error) {
	raw, err := readBounded(path)
	if err != nil {
		return policycompare.Policy{}, refusedInput(flagName, path, err)
	}
	key := ed25519.NewKeyFromSeed([]byte(signingSeed))
	signed, err := signLoadable(raw, key, signingKeyID)
	if err != nil {
		return policycompare.Policy{}, refusedInput(flagName, path, err)
	}
	return policycompare.Policy{Bundle: signed, Keys: bundle.Keyring{signingKeyID: key.Public().(ed25519.PublicKey)}}, nil
}

// readComparedCases reads every case file of dir as policy explain reads a
// case, and refuses a case whose document is not the current one: compared
// under the candidate, it would compare two other policies. The digest is
// over each file's name and the SHA-256 of its bytes, in name order.
func readComparedCases(dir, currentDigest string) ([]policycompare.Case, *policycompare.CasesSource, error) {
	names, err := caseFiles(dir)
	if err != nil {
		return nil, nil, refusedInput("cases", dir, err)
	}
	if len(names) > policycompare.MaxCases {
		return nil, nil, refusedInput("cases", dir, fmt.Errorf("%d case files, at most %d", len(names), policycompare.MaxCases))
	}
	var listing bytes.Buffer
	cases := make([]policycompare.Case, 0, len(names))
	for _, name := range names {
		raw, err := readBounded(filepath.Join(dir, name))
		if err != nil {
			return nil, nil, refusedInput("cases", dir, err)
		}
		c, err := comparedCase(name, raw, currentDigest)
		if err != nil {
			return nil, nil, refusedInput("cases", dir, fmt.Errorf("%s: %w", name, err))
		}
		cases = append(cases, c)
		fmt.Fprintf(&listing, "%s  %s\n", sha256Of(raw)[len("sha256:"):], name)
	}
	return cases, &policycompare.CasesSource{Dir: dir, Files: len(names), Digest: sha256Of(listing.Bytes())}, nil
}

func comparedCase(name string, raw []byte, currentDigest string) (policycompare.Case, error) {
	tc, err := readCaseExpecting(raw, false)
	if err != nil {
		return policycompare.Case{}, err
	}
	_, canonical, err := rules.Parse(tc.document)
	if err != nil {
		return policycompare.Case{}, fmt.Errorf("document: %w", err)
	}
	if got := bundle.Digest(canonical); got != currentDigest {
		return policycompare.Case{}, fmt.Errorf("its document is not --current: digest %s, want %s", got, currentDigest)
	}
	env, refusal := contract.DecodeJSON(tc.envelope)
	return policycompare.Case{ID: "case:" + name, Source: policycompare.SourceCase, Input: policycompare.Input{
		Envelope:       env,
		Refusal:        refusal,
		AuthorizedArgs: tc.authorizedArgs,
		Flow:           tc.flow,
		External:       tc.external,
		Options:        tc.options,
		LoadedAt:       tc.loadedAt,
		DecidedAt:      tc.decidedAt,
	}}, nil
}

// readComparedEvidence reads an export as coverage reads one, under a bound
// of its own, and makes a case of each request it names.
func readComparedEvidence(path, currentDigest string) ([]policycompare.Case, *policycompare.EvidenceSource, error) {
	raw, err := ondisk.ReadOwned(path, maxCompareExportBytes, descriptorForbidden, os.Geteuid())
	if err != nil {
		return nil, nil, refusedInput("evidence", path, err)
	}
	x, events, err := coverage.ReadExportEvents(bytes.NewReader(raw))
	if err != nil {
		return nil, nil, refusedInput("evidence", path, err)
	}
	cases := policycompare.EvidenceCases(policycompare.Export{Events: events, Whole: x.Whole, NotWhole: x.NotWhole}, currentDigest)
	return cases, &policycompare.EvidenceSource{Path: path, SHA256: sha256Of(raw), Whole: x.Whole, NotWhole: x.NotWhole,
		Requests: len(cases)}, nil
}

func sha256Of(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
