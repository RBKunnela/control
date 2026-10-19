package main

import (
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	"github.com/guardana/control/internal/enforceclient"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// receiver is an enforcement receiver that lets every call run with the
// bytes it proposed and records every completion, or, when hung is set,
// never answers. It keeps the path and run token of each request.
type receiver struct {
	hung chan struct{}
	mu   sync.Mutex
	got  []string
}

func (r *receiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.got = append(r.got, req.URL.Path+" "+req.Header.Get(enforceclient.RunTokenHeader))
	r.mu.Unlock()
	if r.hung != nil {
		<-r.hung
		return
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var answer proto.Message
	switch req.URL.Path {
	case enforceclient.PathAdmit:
		in := &enforcev1alpha1.AdmitRequest{}
		if err := protojson.Unmarshal(body, in); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		answer = &enforcev1alpha1.AdmitResponse{
			Outcome: enforcev1alpha1.Outcome_OUTCOME_EXECUTE,
			Execution: &enforcev1alpha1.Execution{
				Handle: "h-1", AuthorizedArguments: in.GetArguments(),
				ExpiresAt: timestamppb.New(time.Now().Add(time.Minute)),
			},
		}
	case enforceclient.PathComplete:
		answer = &enforcev1alpha1.CompleteResponse{Ending: enforcev1alpha1.Ending_ENDING_RECORDED}
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}
	out, err := protojson.Marshal(answer)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

func (r *receiver) requests() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.got)
}

// serveReceiver serves r on a Unix socket in a fresh short directory, since a
// socket path is bounded at about 104 bytes, and returns the socket's path.
func serveReceiver(t *testing.T, r *receiver) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "hk")
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "s")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: r, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = os.RemoveAll(dir)
	})
	if r.hung != nil {
		t.Cleanup(func() { close(r.hung) })
	}
	return socket
}

// TestACallThePlaneLetsRunExitsZeroAndIsRecorded: an admit the receiver lets
// run exits 0 with nothing written, the one answer that lets the runtime run
// the call as proposed, and its completion exits 0 once the receiver
// recorded it.
func TestACallThePlaneLetsRunExitsZeroAndIsRecorded(t *testing.T) {
	r := &receiver{}
	socket := serveReceiver(t, r)
	state := stateDir(t)
	t.Setenv(hookTokenVariable, "tok")
	for _, event := range []string{admitEvent, completeEvent} {
		code, stdout, stderr := hookRun(t, event, "--profile-file", neutralProfile, "--socket", socket, "--state-dir", state)
		if code != exitOK || stdout != "" || stderr != "" {
			t.Fatalf("%s: exit %d, stdout %q, stderr %q; want 0 and nothing written", event, code, stdout, stderr)
		}
	}
	want := []string{enforceclient.PathAdmit + " tok", enforceclient.PathComplete + " tok"}
	if got := r.requests(); !slices.Equal(got, want) {
		t.Fatalf("the receiver got %q, want %q", got, want)
	}
}

// TestAReceiverThatNeverAnswersIsGivenUpInsideTheHookTimeout: with a hook
// timeout of one second the command blocks the call before the runtime
// gives up on the hook, which without its fail-closed setting runs the call.
func TestAReceiverThatNeverAnswersIsGivenUpInsideTheHookTimeout(t *testing.T) {
	profile := neutralWith(t, `"hook_timeout_seconds": 30`, `"hook_timeout_seconds": 1`)
	r := &receiver{hung: make(chan struct{})}
	socket := serveReceiver(t, r)
	t.Setenv(hookTokenVariable, "tok")
	start := time.Now()
	code, stdout, stderr := hookRun(t, admitEvent, "--profile-file", profile, "--socket", socket, "--state-dir", stateDir(t))
	took := time.Since(start)
	if code != 2 || stdout != "" || took >= time.Second {
		t.Fatalf("exit %d after %v, stdout %q, stderr %q; want 2 within the hook timeout", code, took, stdout, stderr)
	}
	if got := r.requests(); len(got) != 1 || got[0] != enforceclient.PathAdmit+" tok" {
		t.Fatalf("the receiver got %q, want the one admit it never answered", got)
	}
}

// TestTheHookDeadlinesFitInsideTheRuntimesTimeout: for every timeout a
// profile may give, an admit and the abort it may owe both fit inside the
// command's deadline, which ends before the runtime's.
func TestTheHookDeadlinesFitInsideTheRuntimesTimeout(t *testing.T) {
	for s := 1; s <= 600; s++ {
		timeout := time.Duration(s) * time.Second
		whole, each := hookDeadlines(timeout)
		if each <= 0 || 2*each > whole || whole >= timeout {
			t.Fatalf("a timeout of %v gives the whole %v and each request %v", timeout, whole, each)
		}
	}
}
