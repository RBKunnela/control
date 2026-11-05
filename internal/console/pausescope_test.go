package console

import (
	"net/http"
	"testing"

	"github.com/guardana/control/internal/pause"
)

// TestAnIdentityPauseThroughThePage: a run, an agent and a principal entry
// written through the page reach the file with their id, and the page says
// which calls each covers.
func TestAnIdentityPauseThroughThePage(t *testing.T) {
	for _, c := range []struct {
		body   string
		want   pause.Scope
		covers string
	}{
		{`{"kind":"run","provider":"","action":"","name":"","id":"run-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`, pause.Scope{Kind: pause.ScopeRun, ID: "run-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			"run run-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, or every run under it as their root"},
		{`{"kind":"agent","provider":"","action":"","name":"","id":"orders-assistant"}`, pause.Scope{Kind: pause.ScopeAgent, ID: "orders-assistant"},
			"every call of agent orders-assistant"},
		{`{"kind":"principal","provider":"","action":"","name":"","id":"agent-runner"}`, pause.Scope{Kind: pause.ScopePrincipal, ID: "agent-runner"},
			"every call of principal agent-runner"},
	} {
		t.Run(string(c.want.Kind), func(t *testing.T) {
			dir, _ := newPlane(t)
			file := newPauseFile(t)
			s := serve(t, dir, file)
			a := s.do(t, s.write("/api/pause", `{"scope":`+c.body+`,"reason":""}`))
			if a.status != http.StatusOK {
				t.Fatalf("pause answered %d %q", a.status, a.body)
			}
			if e := onlyEntry(t, file); e.Scope != c.want {
				t.Fatalf("the file holds %+v, want %+v", e.Scope, c.want)
			}
			var st stateReply
			decode(t, s.do(t, s.readState()), &st)
			if st.Pause == nil || len(st.Pause.Entries) != 1 || st.Pause.Entries[0].Covers != c.covers || st.Pause.Entries[0].Scope.ID != c.want.ID {
				t.Errorf("the page shows %+v, want it to cover %q", st.Pause, c.covers)
			}
		})
	}
}
