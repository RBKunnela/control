package signedpause

import (
	"fmt"
	"slices"

	"github.com/guardana/control/internal/operators"
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/trust"
)

// Vouched is the subject of the operator key of roster that signed f, granted
// operate or admin over f's own tenant and project, refusing as the plane's
// authenticator and authorizer would: with pause.ErrUnauthenticated a key the
// roster does not name as an operator's or a signature that does not verify,
// and with pause.ErrUnauthorized a key with no such grant. roster is one the
// caller verified under its trust root; nothing here raises a floor, so a
// writer and doctor may ask it.
func Vouched(roster trust.Document, f pause.Signed) (string, error) {
	h := f.Body.Header
	keys := roster.Keys()
	i := slices.IndexFunc(keys, func(k trust.Key) bool { return k.ID() == h.KeyID })
	if i < 0 || keys[i].Role() != trust.RoleOperator {
		return "", fmt.Errorf("%w: the roster names no operator key %s", pause.ErrUnauthenticated, h.KeyID)
	}
	key := keys[i]
	if len(f.Envelope.Signatures) != 1 || f.Envelope.PayloadType != operators.PausePayloadType {
		return "", fmt.Errorf("%w: not one signature of the pause payload type", pause.ErrUnauthenticated)
	}
	if err := key.Verify(operators.PausePayloadType, f.Envelope.Payload, f.Envelope.Signatures[0].Signature); err != nil {
		return "", fmt.Errorf("%w: %w", pause.ErrUnauthenticated, err)
	}
	if !slices.ContainsFunc(key.Grants(), func(g trust.Grant) bool {
		return g.Tenant == h.Tenant && g.Project == h.Project && g.Level >= trust.LevelOperate
	}) {
		return "", fmt.Errorf("%w: %s", pause.ErrUnauthorized, key.Subject())
	}
	return key.Subject(), nil
}
