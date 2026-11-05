package gateway_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/operators"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/policystate"
	"github.com/guardana/control/internal/trust"
)

// The hold every signed case holds is the refund helpers.go builds, of this
// tenant and project.
const (
	holdTenant  = "tenant-1"
	holdProject = "proj-1"
)

func operatorKey(name string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("gateway-signed/" + name))
	return ed25519.NewKeyFromSeed(seed[:])
}

func operatorPublic(name string) ed25519.PublicKey {
	return operatorKey(name).Public().(ed25519.PublicKey)
}

func operatorID(name string) string { return policykey.KeyID(operatorPublic(name)) }

// rosterEntry is name's key in a roster, for subject name, with grants of
// tenant, project and level.
func rosterEntry(name string, grants ...[3]string) map[string]any {
	gs := make([]any, 0, len(grants))
	for _, g := range grants {
		gs = append(gs, map[string]any{"tenant": g[0], "project": g[1], "level": g[2]})
	}
	return map[string]any{
		"keyId": operatorID(name), "alg": "ed25519", "role": "operator", "subject": name,
		"publicKey": policykey.FormatPublic(operatorPublic(name)), "grants": gs,
	}
}

// standardRoster is alice operating the hold's project, bob operating another
// and reading the hold's, and carol administering the hold's.
func standardRoster() []any {
	return []any{
		rosterEntry("alice", [3]string{holdTenant, holdProject, "operate"}),
		rosterEntry("bob", [3]string{holdTenant, "proj-2", "operate"}, [3]string{holdTenant, holdProject, "read"}),
		rosterEntry("carol", [3]string{holdTenant, holdProject, "admin"}),
	}
}

func signAs(t *testing.T, payloadType string, body []byte, signer ed25519.PrivateKey, keyID string) trust.Envelope {
	t.Helper()
	sig, err := bundle.SignBytesAs(payloadType, body, signer)
	if err != nil {
		t.Fatal(err)
	}
	return trust.Envelope{PayloadType: payloadType, Payload: body, Signatures: []trust.Signature{{KeyID: keyID, Signature: sig}}}
}

// rosterWorld is a roster file the root signed, the floor that keeps its
// serial, and the operator ports over them, all read at clock.
type rosterWorld struct {
	path   string
	roster trust.Roster
	authn  operators.Authenticator
	authz  operators.Authorizer
}

// newRosterWorld writes a roster of fileID at serial 1 over keys, a floor
// listing floorIDs, and opens the roster port taking configured alone.
func newRosterWorld(t *testing.T, clock func() time.Time, configured, fileID string, keys []any, floorIDs ...string) *rosterWorld {
	t.Helper()
	dir := t.TempDir()
	w := &rosterWorld{path: filepath.Join(dir, "roster.json")}
	floor := filepath.Join(dir, "floor")
	for _, id := range floorIDs {
		if err := policystate.InitAuthority(t.Context(), floor, id); err != nil {
			t.Fatal(err)
		}
	}
	w.write(t, fileID, 1, keys)
	r, err := trust.Open(t.Context(), trust.Config{Root: operatorPublic("root"), RosterID: configured, Path: w.path, FloorDir: floor, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	w.roster = r
	if w.authn, err = operators.NewAuthenticator(operators.AuthenticatorRoster, r, operators.Bounds{}); err != nil {
		t.Fatal(err)
	}
	if w.authz, err = operators.NewAuthorizer(operators.AuthorizerRoster, r, operators.Bounds{}); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *rosterWorld) write(t *testing.T, id string, serial int64, keys []any) {
	t.Helper()
	body, err := canon.Canonicalize(map[string]any{
		"kind": trust.DocumentKind, "rosterId": id, "serial": serial,
		"issuedAt": "2026-09-11T00:00:00Z", "expiresAt": "2026-09-12T00:00:00Z", "keys": keys,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := trust.MarshalFile(signAs(t, trust.PayloadType, body, operatorKey("root"), operatorID("root")))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(w.path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// clockOf is h's clock, or base before h is built: a roster port reads its
// clock once as it opens.
func clockOf(h *harness) time.Time {
	if h == nil {
		return base()
	}
	return h.clock.read()
}

// answerBox is an authority a test files answers in by approval id, with the
// state every batch it hands out carries.
type answerBox struct {
	mu      sync.Mutex
	kind    gateway.AuthorityKind
	state   gateway.BatchState
	signed  map[string][]trust.Envelope
	claimed map[string][]*controlv1.Approval
	asked   int
}

func newAnswerBox(kind gateway.AuthorityKind) *answerBox {
	return &answerBox{kind: kind, state: gateway.BatchComplete, signed: map[string][]trust.Envelope{}, claimed: map[string][]*controlv1.Approval{}}
}

func (b *answerBox) Answers(_ context.Context, approvalID string) gateway.AnswerBatch {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.asked++
	out := gateway.AnswerBatch{State: b.state, Signed: slices.Clone(b.signed[approvalID])}
	for _, a := range b.claimed[approvalID] {
		out.Claimed = append(out.Claimed, proto.CloneOf(a))
	}
	return out
}

func (b *answerBox) Status(context.Context) gateway.AuthorityStatus {
	return gateway.AuthorityStatus{Kind: b.kind, Health: gateway.AuthorityUsable}
}

func (b *answerBox) file(approvalID string, env trust.Envelope) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.signed[approvalID] = append(b.signed[approvalID], env)
}

func (b *answerBox) claim(approvalID string, a *controlv1.Approval) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.claimed[approvalID] = append(b.claimed[approvalID], a)
}

func (b *answerBox) setState(s gateway.BatchState) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.state = s
}

// signedTo makes cfg take its answers from box under the signed kind, judged
// over w.
func signedTo(box *answerBox, w *rosterWorld) func(*gateway.Config) {
	return func(cfg *gateway.Config) {
		cfg.Authority, cfg.AuthorityKind = box, gateway.AuthoritySigned
		cfg.Authenticator, cfg.Authorizer = w.authn, w.authz
	}
}

// claimsTo makes cfg take its answers from box under the directory kind.
func claimsTo(box *answerBox) func(*gateway.Config) {
	return func(cfg *gateway.Config) { cfg.Authority, cfg.AuthorityKind = box, gateway.AuthorityDirectory }
}

// answerTo is the answer to the hold requested announced, decided at a
// minute past base, before edit changes it.
func answerTo(requested *controlv1.Approval, decision string, edit func(*approvals.Answer)) approvals.Answer {
	a := approvals.Answer{
		Tenant: holdTenant, Project: holdProject, RequestID: requested.GetRequestId(), ApprovalID: requested.GetApprovalId(),
		ActionDigest: requested.GetActionDigest(), BundleDigest: requested.GetPolicyBundleDigest(),
		Decision: decision, DecidedAt: base().Add(time.Minute), Reason: "checked",
	}
	if edit != nil {
		edit(&a)
	}
	return a
}

// signedBy is a signed under name's key, naming that key.
func signedBy(t *testing.T, name string, a approvals.Answer) trust.Envelope {
	t.Helper()
	return signedWith(t, operatorKey(name), operatorID(name), a)
}

func signedWith(t *testing.T, key ed25519.PrivateKey, keyID string, a approvals.Answer) trust.Envelope {
	t.Helper()
	a.Alg, a.KeyID = "ed25519", keyID
	body, err := approvals.MarshalAnswer(a)
	if err != nil {
		t.Fatal(err)
	}
	return signAs(t, operators.AnswerPayloadType, body, key, keyID)
}

// claimOf is the directory kind's approval of requested by approver, decided
// a minute past base.
func claimOf(requested *controlv1.Approval, approver string) *controlv1.Approval {
	a := proto.CloneOf(requested)
	a.State, a.ApproverId, a.DecidedAt = approved, approver, timestamppb.New(base().Add(time.Minute))
	return a
}

// requestedOf is the approval the hold of requestID announced on its trail.
func requestedOf(t *testing.T, h *harness, requestID string) *controlv1.Approval {
	t.Helper()
	for _, e := range h.trailOf(requestID) {
		if e.GetKind() == kindApprovalRequested {
			return e.GetApproval()
		}
	}
	t.Fatalf("%s announced no approval", requestID)
	return nil
}
