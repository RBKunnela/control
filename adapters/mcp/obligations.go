package mcp

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/adapterkit"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/policy/rules"
	"github.com/guardana/control/pkg/contract"
)

// The obligation types the adapter applies, each with a conformance test.
// The pipeline applies the rewriting ones; the kernel refuses an obligation
// outside the union of the two sets as OBLIGATION_NOT_UNDERSTOOD.
const (
	obligationReadOnly          = "read_only"
	obligationRestrictResources = "restrict_resources"
	obligationShortenTimeout    = "shorten_timeout"
	obligationDenyExternalSink  = "deny_external_sink"

	paramIDs    = "ids"
	paramPrefix = "prefix"
	paramMS     = "ms"
)

// applies is each type the adapter applies, in the order it declares them.
// The parameters each reads are the catalogue's.
var applies = []string{obligationReadOnly, obligationRestrictResources, obligationShortenTimeout, obligationDenyExternalSink}

// AppliedObligations returns the obligation types the adapter applies to a
// call it sends, which it declares to the kernel as applicable.
func AppliedObligations() []string {
	return slices.Clone(applies)
}

// applied is what the obligations of a decision demand of the send.
type applied struct {
	timeout time.Duration
}

// errResourceMoved is authorized bytes whose member naming the resource does
// not name the one the envelope was decided on: a rewriting obligation
// changed it.
const errResourceMoved Error = "mcp: the authorized arguments name another resource than the one decided on"

// authorizedSend checks what the authorized bytes may be sent under: they
// name the resource the envelope was decided on, and every obligation left
// for the adapter holds.
func authorizedSend(c *call, d gateway.Disposition) (applied, error) {
	if c.entry != nil && c.entry.ResourceFrom != "" && !sameResource(c, d.AuthorizedArgs) {
		return applied{}, errResourceMoved
	}
	return applyObligations(c, d.Obligations)
}

// sameResource reports whether the authorized bytes name the resource the
// envelope was decided on.
func sameResource(c *call, authorized []byte) bool {
	return adapterkit.SameResource(c.admission.Arguments, authorized, c.entry.ResourceFrom, c.admission.Envelope.GetResource().GetId())
}

// applyObligations checks every obligation against the call and returns
// what the send has to honour, or the obligation the call fails: a
// non-advisory one the adapter cannot satisfy for this call stops it. An
// advisory obligation that fails is skipped and the call proceeds.
func applyObligations(c *call, obligations []*controlv1.Obligation) (applied, error) {
	var out applied
	for _, o := range obligations {
		err := applyOne(c, o, &out)
		if err != nil && !o.GetAdvisory() {
			return applied{}, fmt.Errorf("%s: %w", o.GetType(), err)
		}
	}
	return out, nil
}

func applyOne(c *call, o *controlv1.Obligation, out *applied) error {
	if err := onlyParams(o); err != nil {
		return err
	}
	env := c.admission.Envelope
	switch o.GetType() {
	case obligationReadOnly:
		if contract.IsMaterial(env.GetAction().GetEffect()) {
			return fmt.Errorf("the call's effect is %s, not a read", env.GetAction().GetEffect())
		}
	case obligationRestrictResources:
		id := env.GetResource().GetId()
		if id == "" || !resourceAllowed(id, o.GetParams()) {
			return errors.New("the resource is outside the allowed set")
		}
	case obligationShortenTimeout:
		return shorten(o.GetParams(), out)
	case obligationDenyExternalSink:
		if contract.IsUntrusted(env.GetDestination().GetTrustZone()) {
			return errors.New("the destination is not trusted")
		}
	default:
		return errors.New("not applied by this adapter")
	}
	return nil
}

// onlyParams refuses a parameter outside the ones the catalogue declares for
// the obligation's type: a parameter nobody read would be an instruction
// nobody followed. A bundle signed without the catalogue's check can still
// carry one.
func onlyParams(o *controlv1.Obligation) error {
	if !slices.Contains(applies, o.GetType()) {
		return errors.New("not applied by this adapter")
	}
	known, ok := rules.ParamNames(o.GetType())
	if !ok {
		return errors.New("not an obligation type of the catalogue")
	}
	for key := range o.GetParams() {
		if !slices.Contains(known, key) {
			return fmt.Errorf("parameter %q is not one this adapter applies", key)
		}
	}
	return nil
}

// shorten reads ms as a positive integer and keeps the shortest timeout. A
// value past what a duration holds is refused: multiplied, it would wrap to
// no bound or to one nobody wrote.
func shorten(params map[string]string, out *applied) error {
	ms, err := strconv.ParseInt(params[paramMS], 10, 64)
	if err != nil || ms <= 0 {
		return fmt.Errorf("%s is not a positive integer", paramMS)
	}
	if ms > int64(math.MaxInt64/time.Millisecond) {
		return fmt.Errorf("%s is longer than a duration holds", paramMS)
	}
	d := time.Duration(ms) * time.Millisecond
	if out.timeout == 0 || d < out.timeout {
		out.timeout = d
	}
	return nil
}

// resourceAllowed reads the parameters as exact ids, comma-separated, and a
// literal prefix; a call passes when either matches. Neither parameter
// present allows nothing.
func resourceAllowed(id string, params map[string]string) bool {
	if ids, ok := params[paramIDs]; ok {
		for _, want := range strings.Split(ids, ",") {
			if want != "" && want == id {
				return true
			}
		}
	}
	if prefix, ok := params[paramPrefix]; ok && prefix != "" && strings.HasPrefix(id, prefix) {
		return plainBelow(id[strings.LastIndex(prefix, "/")+1:])
	}
	return false
}

// plainBelow reports whether the path from the segment the prefix ends in
// avoids every spelling this adapter knows a resolver to read as leaving it:
// a percent escape, a `;` parameter, a `?` or `#`, which a URI resolver cuts
// before it removes dot segments, a backslash, a byte outside printable
// ASCII, a segment of only dots and spaces, and an empty segment but a
// trailing one. The upstream's own resolver is not consulted.
func plainBelow(rest string) bool {
	for i := 0; i < len(rest); i++ {
		if !plainByte(rest[i]) {
			return false
		}
	}
	segments := strings.Split(rest, "/")
	for i, s := range segments {
		if s == "" {
			if i != len(segments)-1 {
				return false
			}
			continue
		}
		if strings.Trim(s, ". ") == "" {
			return false
		}
	}
	return true
}

// plainByte reports whether b is printable ASCII that no resolver reads as
// an escape, a parameter, a query, a fragment or a separator.
func plainByte(b byte) bool {
	switch b {
	case '%', ';', '?', '#', '\\':
		return false
	}
	return b >= 0x20 && b <= 0x7e
}
