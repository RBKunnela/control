package mcp_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guardana/control/adapters/mcp"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
)

// The modes a rig runs the real pipeline in.
const (
	modeObserve  = controlv1.EnforcementMode_ENFORCEMENT_MODE_OBSERVE
	modeEnforce  = controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE
	modeLockdown = controlv1.EnforcementMode_ENFORCEMENT_MODE_LOCKDOWN
)

// The rules the rigs decide against.
const (
	allowReads      = `{"id":"allow-reads","effect":"ALLOW","when":{"action":{"effect":["READ"]}}}`
	allowMail       = `{"id":"allow-mail","effect":"ALLOW","when":{"action":{"effect":["COMMUNICATE"]}}}`
	denyMail        = `{"id":"deny-mail","effect":"DENY","when":{"action":{"effect":["COMMUNICATE"]}}}`
	denyAliceMail   = `{"id":"deny-alice-mail","effect":"DENY","when":{"principal":{"id":["alice"]},"action":{"effect":["COMMUNICATE"]}}}`
	allowDeletes    = `{"id":"allow-deletes","effect":"ALLOW","when":{"action":{"effect":["DELETE"]}}}`
	allowTransacts  = `{"id":"allow-transacts","effect":"ALLOW","when":{"action":{"effect":["TRANSACT"]}}}`
	allowEverything = allowReads + "," + allowMail + "," + allowDeletes + "," + allowTransacts
)

// realPipeline is the pipeline of internal/gateway, counting the previews
// list shaping asked for and keeping the request id of every admission.
type realPipeline struct {
	*gateway.Pipeline
	previews atomic.Int64

	mu       sync.Mutex
	proposed []string
}

func (r *realPipeline) Admit(ctx context.Context, a gateway.Admission) gateway.Disposition {
	r.mu.Lock()
	r.proposed = append(r.proposed, a.Envelope.GetRequestId())
	r.mu.Unlock()
	return r.Pipeline.Admit(ctx, a)
}

// admitted are the request ids the adapter proposed, in order.
func (r *realPipeline) admitted() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.proposed)
}

func (r *realPipeline) Preview(ctx context.Context, a gateway.Admission) gateway.Previewed {
	r.previews.Add(1)
	return r.Pipeline.Preview(ctx, a)
}

// plan is the pipeline the rig drives: the fake, or the real one in the
// mode the options name, over a bundle of their rules.
func (r *rig) plan(t *testing.T, a *mcp.Adapter, o rigOptions) mcp.Pipeline {
	t.Helper()
	if o.mode == controlv1.EnforcementMode_ENFORCEMENT_MODE_UNSPECIFIED {
		return r.pipe
	}
	var n atomic.Int64
	r.sink = &evidence.MemorySink{}
	r.approvals = &gateway.MemoryApprovals{}
	p, err := gateway.New(gateway.Config{
		Mode:          o.mode,
		Adapter:       a,
		KernelOptions: core.Options{MaxStale: 10 * time.Minute},
		Policy:        policyOf(t, o),
		Pause:         gateway.PauseDisabled(),
		Stops:         gateway.StopsDisabled(),
		Sink:          r.sink,
		Approvals:     r.approvals,
		Clock:         time.Now,
		NewID:         func() string { return "gw-" + strconv.FormatInt(n.Add(1), 10) },
		ApprovalTTL:   time.Minute,
		RetryAfter:    time.Second,
		MaxHeld:       16,
		MaxOpen:       16,
		MaxRuns:       16,
	})
	if err != nil {
		t.Fatalf("gateway.New refused a configuration this test builds as valid: %v", err)
	}
	r.real = &realPipeline{Pipeline: p}
	return r.real
}

type fixedPolicy struct{ snap *policy.Snapshot }

func (f fixedPolicy) Current() *policy.Snapshot { return f.snap }

// policyOf is the options' policy source, or a fixed snapshot of their rules.
func policyOf(t *testing.T, o rigOptions) gateway.PolicySource {
	t.Helper()
	if o.policy != nil {
		return o.policy
	}
	return fixedPolicy{snap: snapshot(t, o.rules...)}
}

// swappedPolicy serves the snapshot stored last, as a plane that installed a
// new bundle does.
type swappedPolicy struct {
	snap atomic.Pointer[policy.Snapshot]
}

func (s *swappedPolicy) Current() *policy.Snapshot { return s.snap.Load() }

func key() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
}

func pinned() bundle.Keyring {
	return bundle.Keyring{"k1": ed25519.PublicKey(slices.Clone(key()[ed25519.SeedSize:]))}
}

// snapshot signs a document of rules in memory and loads it now.
func snapshot(t *testing.T, rules ...string) *policy.Snapshot {
	t.Helper()
	doc := []byte(`{"apiVersion":"agent-policy/v1alpha1","bundle":{"id":"mcp","version":"2026-09-19.1","serial":1,"maxStaleSeconds":600},"rules":[` +
		strings.Join(rules, ",") + `]}`)
	b, err := policy.Sign(doc, key(), "k1")
	if err != nil {
		t.Fatalf("Sign refused a document this test builds as valid: %v", err)
	}
	snap, err := policy.Load(b, pinned(), time.Now())
	if err != nil {
		t.Fatalf("Load refused a bundle this test builds as valid: %v", err)
	}
	return snap
}

// events returns what the real pipeline's sink kept.
func (r *rig) events() []*controlv1.Event { return r.sink.Events() }

// kindsOf lists the kinds of the events of one request id, in order.
func (r *rig) kindsOf(t *testing.T, requestID string) []controlv1.EventKind {
	t.Helper()
	var out []controlv1.EventKind
	for _, e := range r.events() {
		if requestID == "" || e.GetRequestId() == requestID {
			out = append(out, e.GetKind())
		}
	}
	return out
}
