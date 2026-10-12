package adapterkit_test

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/guardana/control/internal/adapterkit"
	"github.com/guardana/control/internal/gateway"
)

func TestTheRunTokenIsTheOneHeaderValue(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values []string
		token  string
		cause  gateway.RunCause
	}{
		{"none", nil, "", gateway.RunMissing},
		{"an empty one", []string{""}, "", gateway.RunMissing},
		{"two", []string{"run.a", "run.b"}, "", gateway.RunMalformed},
		{"two, one empty", []string{"run.a", ""}, "", gateway.RunMalformed},
		{"one", []string{"run.a"}, "run.a", ""},
	} {
		h := http.Header{}
		for _, v := range tc.values {
			h.Add("run-token", v)
		}
		token, cause := adapterkit.HeaderToken(h)
		if token != tc.token || cause != tc.cause {
			t.Errorf("%s: HeaderToken = %q, %q; want %q, %q", tc.name, token, cause, tc.token, tc.cause)
		}
	}
}

type resolver struct {
	run   gateway.OpenedRun
	err   error
	asked int
}

func (r *resolver) Resolve(context.Context, string, gateway.RunIdentity, time.Time) (gateway.OpenedRun, error) {
	r.asked++
	return r.run, r.err
}

func TestResolveNamesTheCauseOfARefusal(t *testing.T) {
	who := gateway.RunIdentity{TenantID: "t", PrincipalType: "user", PrincipalID: "u", AgentID: "a"}
	open := gateway.OpenedRun{ID: "run-1", Root: "run-1", Who: who}
	for _, tc := range []struct {
		name  string
		r     resolver
		cause gateway.RunCause
	}{
		{"a closed run", resolver{err: &gateway.RunRefusal{Cause: gateway.RunClosed}}, gateway.RunClosed},
		{"a wrapped refusal", resolver{err: fmt.Errorf("directory: %w", &gateway.RunRefusal{Cause: gateway.RunExpired})}, gateway.RunExpired},
		{"a refusal with no cause", resolver{err: &gateway.RunRefusal{}}, gateway.RunUnreadable},
		{"a refusal with a cause outside the set", resolver{err: &gateway.RunRefusal{Cause: "revoked"}}, gateway.RunUnreadable},
		{"any other error", resolver{err: errors.New("disk")}, gateway.RunUnreadable},
		{"a run with no id", resolver{run: gateway.OpenedRun{Who: who}}, gateway.RunUnreadable},
		{"an open run", resolver{run: open}, ""},
	} {
		run, cause := adapterkit.Resolve(context.Background(), &tc.r, "run-1.s", who, time.Unix(0, 0))
		if cause != tc.cause || (cause == "" && run != open) || (cause != "" && run != gateway.OpenedRun{}) {
			t.Errorf("%s: Resolve = %+v, %q; want cause %q", tc.name, run, cause, tc.cause)
		}
	}
	r := &resolver{run: open}
	if _, cause := adapterkit.Resolve(context.Background(), r, "", who, time.Unix(0, 0)); cause != gateway.RunMissing || r.asked != 0 {
		t.Errorf("the empty token: cause %q, resolver asked %d times", cause, r.asked)
	}
}

func TestTheRunCounterKeepsEveryCauseAndNoOther(t *testing.T) {
	c := adapterkit.NewRunCounter()
	c.Count(gateway.RunClosed)
	c.Count(gateway.RunClosed)
	c.Count("revoked")
	got := c.Snapshot()
	if keys := slices.Sorted(maps.Keys(got)); !slices.Equal(keys, slices.Sorted(slices.Values(gateway.RunCauses()))) {
		t.Fatalf("the counter keys %v", keys)
	}
	for cause, n := range got {
		want := uint64(0)
		switch cause {
		case gateway.RunClosed:
			want = 2
		case gateway.RunUnreadable:
			want = 1
		}
		if n != want {
			t.Errorf("%s = %d, want %d", cause, n, want)
		}
	}
}
