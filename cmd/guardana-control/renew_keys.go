package main

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	ondisk "github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
)

// readPublicKey reads the public key file flagName names. A file the length
// of no public key line is refused before it becomes a string, which nothing
// can clear: the file may be a private key given in the wrong place.
func readPublicKey(flagName, path string) (ed25519.PublicKey, error) {
	line, err := ondisk.ReadRegular(path, maxPublicKeyFileBytes, 0)
	defer clear(line)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", flagName, err)
	}
	if n := len(bytes.TrimSuffix(line, []byte("\n"))); n != publicLineBytes {
		return nil, fmt.Errorf("%s: %w", flagName, policykey.ErrPublicLine)
	}
	pub, err := policykey.ParsePublic(string(line))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", flagName, err)
	}
	return pub, nil
}

// verifiedBundle reads the bundle and verifies it under pub, by the id that
// key derives, with every check a plane's load makes: the signature, the
// canonical form, the digest.
func verifiedBundle(bundlePath string, pub ed25519.PublicKey, now time.Time) (*policy.Snapshot, error) {
	raw, err := ondisk.ReadRegular(bundlePath, maxReadBytes, 0)
	// The file named may be a key given in the wrong place; the decoder
	// copies what it keeps.
	defer clear(raw)
	if err != nil {
		return nil, fmt.Errorf("--bundle %s: %w", bundlePath, err)
	}
	var b controlv1.PolicyBundle
	if !policykey.IsBundle(raw) || proto.Unmarshal(raw, &b) != nil {
		return nil, fmt.Errorf("--bundle %s: %s", bundlePath, errNotABundle)
	}
	snap, err := policy.Load(&b, bundle.Keyring{policykey.KeyID(pub): pub}, now)
	if err != nil {
		return nil, fmt.Errorf("--bundle %s: %w", bundlePath, err)
	}
	return snap, nil
}

// signStatement signs a statement for snap's bundle at issuedAt and reads it
// back under the key's own public half, which is what makes the Statement a
// floor can take.
func signStatement(snap *policy.Snapshot, key ed25519.PrivateKey, issuedAt time.Time) (policy.StatementEnvelope, policy.Statement, error) {
	pub, _ := key.Public().(ed25519.PublicKey)
	keyID := policykey.KeyID(pub)
	env, err := policy.SignStatement(snap.Ref().GetBundleId(), snap.Serial(), snap.Ref().GetDigest(), issuedAt, key, keyID)
	if err != nil {
		return policy.StatementEnvelope{}, policy.Statement{}, err
	}
	st, err := policy.VerifyStatement(env, bundle.Keyring{keyID: pub})
	if err != nil {
		return policy.StatementEnvelope{}, policy.Statement{}, err
	}
	return env, st, nil
}
