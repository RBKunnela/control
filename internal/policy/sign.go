package policy

import (
	"crypto/ed25519"
	"fmt"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policy/rules"
)

// Sign parses raw as a policy document and signs its canonical bytes with key.
// Every field outside them comes from the document, and created_at stays
// unset. It refuses an empty keyID, which Load would refuse, a document Parse
// refuses (ErrDocument), one rules.CheckObligations refuses
// (ErrObligationParams) and a key bundle.SignBytes refuses (ErrSigningKey).
// It does not compile the document; Load does, and Load does not run the
// parameter check, so a bundle signed elsewhere loads.
func Sign(raw []byte, key ed25519.PrivateKey, keyID string) (*controlv1.PolicyBundle, error) {
	if keyID == "" {
		return nil, fmt.Errorf("%w: %w", ErrKey, bundle.ErrUnknownKey)
	}
	doc, canonical, err := rules.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDocument, err)
	}
	if err := rules.CheckObligations(doc); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrObligationParams, err)
	}
	signature, err := bundle.SignBytes(canonical, key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSigningKey, err)
	}
	return &controlv1.PolicyBundle{
		Ref: &controlv1.PolicyBundleRef{
			BundleId: doc.Bundle.ID,
			Version:  doc.Bundle.Version,
			Digest:   bundle.Digest(canonical),
		},
		Canonical:       canonical,
		SignatureAlg:    bundle.SignatureAlg,
		Signature:       signature,
		KeyId:           keyID,
		MaxStaleSeconds: doc.Bundle.MaxStaleSeconds,
	}, nil
}
