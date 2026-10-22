package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	ondisk "github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
)

// checkStatementOut refuses, before anything is raised, an output path whose
// directory is missing or is a floor directory, and one that exists and is
// not a regular file holding a freshness statement. A floor directory always
// holds its marker, since policystate opens none without one, so the marker
// tells the signer's own floor directory and a plane's alike.
// policykey.WriteStatement judges the path again as it writes; this check
// keeps a refused path from costing a raise.
func checkStatementOut(out string) error {
	switch _, err := os.Stat(filepath.Join(filepath.Dir(out), floorMarker)); {
	case err == nil:
		return fmt.Errorf("--out %s: %s", out, errFloorDirectory)
	case !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("--out %s: %w", out, err)
	}
	info, err := os.Lstat(out)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := ondisk.CheckDir(filepath.Dir(out), 0); err != nil {
			return fmt.Errorf("--out %s: %w", out, err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("--out %s: %w", out, err)
	case !info.Mode().IsRegular():
		return fmt.Errorf("--out %s: %w", out, policykey.ErrStatementOut)
	}
	raw, err := ondisk.ReadRegular(out, policykey.MaxStatementFileBytes, 0)
	// The file judged may be a key given in the wrong place.
	defer clear(raw)
	if err != nil || !policykey.IsStatement(raw) {
		return fmt.Errorf("--out %s: %w", out, policykey.ErrStatementOut)
	}
	return nil
}

// checkNotNewer refuses an out that holds, under the freshness key, a
// statement for st's bundle id ordered after st, which a renew under another
// floor directory wrote. One equal to st is st, byte for byte, since an
// Ed25519 signature over one body is one value, so writing it again changes
// nothing. An absent out, or one holding a statement this key did not sign
// or another id's, is replaced; one that can no longer be read as a
// statement is refused, since it was one before the raise.
func checkNotNewer(out string, st policy.Statement, freshPub ed25519.PublicKey) error {
	env, err := policykey.ReadStatement(out)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("--out %s: %w; the signer floor was raised to this renew's statement", out, err)
	}
	held, ours := signedBy(env, freshPub)
	if !ours || held.BundleID() != st.BundleID() {
		return nil
	}
	if held.Serial() > st.Serial() || (held.Serial() == st.Serial() && held.IssuedAt().After(st.IssuedAt())) {
		return fmt.Errorf("--out %s: %s; the signer floor was raised to this renew's statement", out, errRaceLost)
	}
	return nil
}

// signedBy reads env as a statement pub signed, and reports whether it is
// one.
func signedBy(env policy.StatementEnvelope, pub ed25519.PublicKey) (policy.Statement, bool) {
	st, err := policy.VerifyStatement(env, bundle.Keyring{policykey.KeyID(pub): pub})
	return st, err == nil
}
