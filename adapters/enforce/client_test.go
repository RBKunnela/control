package enforce_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	"github.com/guardana/control/internal/enforceclient"
)

// tool records what the reference client handed it.
type tool struct {
	ran  int
	sent []byte
}

func (tl *tool) exec(_ context.Context, authorized []byte) (enforceclient.Result, error) {
	tl.ran++
	tl.sent = authorized
	return enforceclient.Result{Status: enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_SUCCESS}, nil
}

func (r *rig) client(t *testing.T, token string) *enforceclient.Client {
	t.Helper()
	c, err := enforceclient.New(enforceclient.Config{Socket: r.socket, Token: token, Timeout: 5 * time.Second, Now: r.clock.read})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestTheReferenceClientCooperatesWithTheReceiver(t *testing.T) {
	o := defaults()
	o.rules = []string{allowReads, cappedRefunds}
	r := newRig(t, o)
	c := r.client(t, runA)

	var read tool
	ans, err := c.Call(t.Context(), "read_file", []byte(`{"path":"a"}`), read.exec)
	if err != nil || read.ran != 1 || string(read.sent) != `{"path":"a"}` || ans.Ending != recorded {
		t.Fatalf("read: %v, ran %d with %q, ending %s", err, read.ran, read.sent, ans.Ending)
	}

	var capped tool
	ans, err = c.Call(t.Context(), "refund", []byte(`{"account":"acc-1","amount":1250}`), capped.exec)
	if err != nil || capped.ran != 1 || ans.Ending != recorded {
		t.Fatalf("capped refund: %v, ran %d, ending %s", err, capped.ran, ans.Ending)
	}
	var sent struct{ Amount int }
	if err := json.Unmarshal(capped.sent, &sent); err != nil || sent.Amount != 1000 {
		t.Fatalf("the tool got %s", capped.sent)
	}
	if r.count(kindDone) != 2 || r.count(kindFailed) != 0 {
		t.Fatalf("trail %v", r.kinds())
	}
}

func TestTheReferenceClientNeverRunsABlockedOrHeldCall(t *testing.T) {
	o := defaults()
	o.mode, o.rules = modeApprove, []string{approveRefunds}
	r := newRig(t, o)
	c := r.client(t, runA)
	var tl tool
	if _, err := c.Call(t.Context(), "drop_database", []byte(`{}`), tl.exec); !errors.Is(err, enforceclient.ErrBlocked) {
		t.Fatalf("an unclassified tool: %v", err)
	}
	ans, err := c.Call(t.Context(), "refund", []byte(refund), tl.exec)
	if !errors.Is(err, enforceclient.ErrPending) || ans.Pending.GetApprovalId() == "" {
		t.Fatalf("a held call: %v, %v", err, ans.Pending)
	}
	if tl.ran != 0 || r.count(kindStarted) != 0 {
		t.Fatalf("the tool ran %d times; trail %v", tl.ran, r.kinds())
	}
}
