package hookbridge_test

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"

	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/enforceclient"
	"github.com/guardana/control/internal/hookbridge"
)

type (
	readFunc func(*hookbridge.Profile, io.Reader) (hookbridge.Event, error)
	preFunc  func(context.Context, *hookbridge.Profile, hookbridge.Event, hookbridge.Client, *hookbridge.Store, string) hookbridge.PreOutcome
	postFunc func(context.Context, *hookbridge.Profile, hookbridge.Event, hookbridge.Client, *hookbridge.Store, string) hookbridge.PostOutcome
)

// impl is a bridge under test: the reference one, or a mutant that breaks
// one rule.
type impl struct {
	read readFunc
	pre  preFunc
	post postFunc
}

func reference() impl { return impl{hookbridge.ReadEvent, hookbridge.Pre, hookbridge.Post} }

// recording is a client that keeps what the bridge asked of the receiver,
// and can lose the answer to a complete after the receiver had it.
type recording struct {
	inner        hookbridge.Client
	mu           sync.Mutex
	answers      []enforceclient.Answer
	completes    int
	aborts       []enforcev1alpha1.AbortCause
	loseComplete bool
}

func (r *recording) Admit(ctx context.Context, tool string, args []byte, key string, carry enforceclient.Carry) (enforceclient.Answer, enforceclient.Admission, enforcev1alpha1.AbortCause, error) {
	ans, adm, cause, err := r.inner.Admit(ctx, tool, args, key, carry)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.answers = append(r.answers, ans)
	return ans, adm, cause, err
}

func (r *recording) Complete(ctx context.Context, handle string, sent []byte, res enforceclient.Result, toolErr error) (enforcev1alpha1.Ending, error) {
	ending, err := r.inner.Complete(ctx, handle, sent, res, toolErr)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.completes++
	if r.loseComplete {
		return enforcev1alpha1.Ending_ENDING_UNSPECIFIED, fmt.Errorf("%w: the answer was lost", enforceclient.ErrTransport)
	}
	return ending, err
}

func (r *recording) Abort(ctx context.Context, handle string, cause enforcev1alpha1.AbortCause) (enforcev1alpha1.Ending, error) {
	ending, err := r.inner.Abort(ctx, handle, cause)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.aborts = append(r.aborts, cause)
	return ending, err
}

func (r *recording) sent() (admits, completes int, aborts []enforcev1alpha1.AbortCause) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.answers), r.completes, slices.Clone(r.aborts)
}

// env is one plane, one store and one bridge under test.
type env struct {
	t     *testing.T
	b     impl
	p     *hookbridge.Profile
	pl    *plane
	c     *recording
	s     *hookbridge.Store
	dir   string
	token string
}

func setup(t *testing.T, b impl, o planeOptions) *env {
	t.Helper()
	pl := newPlane(t, o)
	dir := storeDir(t)
	return &env{t: t, b: b, p: neutral(t), pl: pl, c: &recording{inner: clientFor(t, pl.socket)}, s: openStore(t, dir), dir: dir, token: runToken}
}

func admitEvent(call, input string) string {
	return `{"event":"BeforeTool","session":"s-1","call":"` + call + `","tool":"refund","input":` + input + `,"cwd":"/w"}`
}

func postEvent(name, call, input, extra string) string {
	in := ""
	if input != "" {
		in = `,"input":` + input
	}
	return `{"event":"` + name + `","session":"s-1","call":"` + call + `","tool":"refund"` + in + `,"response":{"ok":true}` + extra + `}`
}

func (e *env) read(raw string) (hookbridge.Event, error) {
	return e.b.read(e.p, strings.NewReader(raw))
}

func (e *env) pre(raw string) (hookbridge.PreOutcome, error) {
	ev, err := e.read(raw)
	if err != nil {
		return hookbridge.PreOutcome{}, err
	}
	return e.b.pre(context.Background(), e.p, ev, e.c, e.s, e.token), nil
}

func (e *env) post(raw string) (hookbridge.PostOutcome, error) {
	ev, err := e.read(raw)
	if err != nil {
		return hookbridge.PostOutcome{}, err
	}
	return e.b.post(context.Background(), e.p, ev, e.c, e.s, e.token), nil
}

func (e *env) entries() int { return len(names(e.t, e.dir)) }

// closing returns the one closing record's kind, status and protocol status,
// or a miss when there is not exactly one.
func (e *env) closing() (controlv1.EventKind, controlv1.ResultStatus, string, []string) {
	cs := e.pl.closings()
	if len(cs) != 1 {
		return 0, 0, "", []string{fmt.Sprintf("%d closing records, want 1: %v", len(cs), e.pl.kinds())}
	}
	r := cs[0].GetResult()
	return cs[0].GetKind(), r.GetStatus(), r.GetToolProtocolStatus(), nil
}

// wantClosing returns a miss unless the one closing record is kind, status
// and protocol status.
func (e *env) wantClosing(kind controlv1.EventKind, status controlv1.ResultStatus, protocol string) []string {
	k, s, p, miss := e.closing()
	if miss != nil {
		return miss
	}
	if k != kind || s != status || p != protocol {
		return []string{fmt.Sprintf("closing %s %s %q, want %s %s %q", k, s, p, kind, status, protocol)}
	}
	return nil
}

func check(miss *[]string, failed bool, format string, args ...any) {
	if failed {
		*miss = append(*miss, fmt.Sprintf(format, args...))
	}
}
