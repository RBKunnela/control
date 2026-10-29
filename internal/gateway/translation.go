package gateway

import (
	"errors"
	"fmt"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/channel"
	"github.com/guardana/control/internal/classify"
	"github.com/guardana/control/pkg/contract"
)

// translation is how far an adapter could translate a call. The zero value
// is refused, so a state nobody set hands nothing out.
type translation uint8

const (
	// translationRefused: the adapter refused the call for something other
	// than nothing classifying it, or handed in no envelope. No mode hands it
	// out.
	translationRefused translation = iota
	// translationUnclassified: every part of the envelope was built but the
	// classification, which nothing gives, as checkTranslation holds the
	// claim to. OBSERVE lets it run; every other mode blocks it with
	// ACTION_UNCLASSIFIED.
	translationUnclassified
	// translationComplete: the adapter refused nothing.
	translationComplete
)

// translationOf is the one place the plane says whether a call is
// unclassified; every reader takes it from here.
func translationOf(a Admission) translation {
	switch {
	case a.Envelope == nil:
		return translationRefused
	case a.Refusal == nil:
		return translationComplete
	case unclassifiedOnly(a.Refusal):
		return translationUnclassified
	}
	return translationRefused
}

// observable reports whether OBSERVE may hand the call out: nothing but its
// classification is missing, or the adapter refused nothing and the kernel
// took the request. An adapter that hands in an envelope the contract refuses
// and no refusal is held to the kernel's own refusal of it.
func (c *call) observable() bool {
	switch translationOf(c.in) {
	case translationUnclassified:
		return true
	case translationComplete:
		return !c.refusedInput
	}
	return false
}

// unclassifiedOnly reports whether err is ErrUnclassified and nothing else: the
// sentinel itself at the end of a chain of single wraps. A node that wraps
// several errors joins another cause with it, and the call is refused for
// that cause. A node's Is method is not consulted, since it could claim the
// sentinel over any cause.
func unclassifiedOnly(err error) bool {
	for err != nil {
		if sentinel, ok := err.(Error); ok { //nolint:errorlint // each node of the chain is read itself, so a wrap cannot hide a join
			return sentinel == ErrUnclassified
		}
		// A node that wraps several errors has no Unwrap() error, so the
		// chain ends here and the call is refused.
		err = errors.Unwrap(err)
	}
	return false
}

// checkTranslation holds what an adapter handed in to what the plane takes,
// before anything reads the call, in place of a refusal that says only that
// nothing classifies it: a kind outside the plane's vocabulary, a protocol
// that is not the adapter's name, a resource pointer that is not RFC 6901,
// and an unclassified claim the envelope does not bear out. Otherwise OBSERVE
// would run a kind no pause scope names, or an envelope the kernel never
// validated. A refusal for anything else stays the call's own.
func (c *call) checkTranslation() {
	if translationOf(c.in) == translationRefused {
		return
	}
	action := c.in.Envelope.GetAction()
	switch {
	case !channel.KnownKind(action.GetKind()):
		c.in.Refusal = &contract.ValidationError{Field: "action.kind", Err: contract.ErrInvalidValue}
	case action.GetProtocol() != c.p.name:
		c.in.Refusal = &contract.ValidationError{Field: "action.protocol", Err: contract.ErrInvalidValue}
	case classify.CheckPointer(c.in.Classification.ResourceFrom) != nil:
		c.in.Refusal = fmt.Errorf("%w: the resource pointer is not RFC 6901", contract.ErrInvalidValue)
	case translationOf(c.in) == translationUnclassified:
		if err := unclassifiedClaim(c.in.Envelope, c.in.Arguments); err != nil {
			c.in.Refusal = err
		}
	}
}

// unclassifiedClaim is what refutes a claim that nothing but the
// classification is missing from env: an effect class, which the claim says
// nothing gave; a refusal of contract.ValidateUnclassified; arguments canon
// refuses, under the code the kernel's digest gives them; or a hash that names
// other bytes than args. The kernel stops at a refusal handed in, so it checks
// none of this itself.
func unclassifiedClaim(env *controlv1.ActionEnvelope, args []byte) error {
	if env.GetAction().GetEffect() != controlv1.EffectClass_EFFECT_CLASS_UNSPECIFIED {
		return &contract.ValidationError{Field: "action.effect", Err: fmt.Errorf("%w: set on a call nothing classifies", contract.ErrInvalidValue)}
	}
	if err := contract.ValidateUnclassified(env); err != nil {
		return err
	}
	held, err := canon.ArgumentsHashV1(args)
	if err != nil {
		bound := contract.ErrInvalidValue
		if errors.Is(err, canon.ErrArgumentsTooLarge) || errors.Is(err, canon.ErrTooDeep) {
			bound = contract.ErrTooLarge
		}
		return &contract.ValidationError{Err: fmt.Errorf("%w: arguments: %w", bound, err)}
	}
	if sent := env.GetArguments().GetCanonicalHash(); sent != "" && held != sent {
		return &contract.ValidationError{Field: "arguments.canonical_hash", Err: fmt.Errorf("%w: names other bytes", contract.ErrInvalidValue)}
	}
	return nil
}
