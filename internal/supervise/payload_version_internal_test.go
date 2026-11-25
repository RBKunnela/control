package supervise

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// TestAPayloadIsReadByTheSharedVersionTable: each payload that carries a
// version of its own is held to the table every receiver follows, inside an
// event of 1.0; an event with no payload, or one that carries no version, is
// read.
func TestAPayloadIsReadByTheSharedVersionTable(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "contracts", "schema_versions.json"))
	if err != nil {
		t.Fatal(err)
	}
	var table []struct {
		Version  string `json:"version"`
		Admitted bool   `json:"admitted"`
	}
	if err := json.Unmarshal(raw, &table); err != nil {
		t.Fatal(err)
	}
	payloads := map[string]func(ev *controlv1.Event, v string){
		"proposal": func(ev *controlv1.Event, v string) {
			ev.Payload = &controlv1.Event_Proposed{Proposed: &controlv1.ActionEnvelope{SchemaVersion: v}}
		},
		"decision": func(ev *controlv1.Event, v string) {
			ev.Payload = &controlv1.Event_Decision{Decision: &controlv1.Decision{SchemaVersion: v}}
		},
		"approval": func(ev *controlv1.Event, v string) {
			ev.Payload = &controlv1.Event_Approval{Approval: &controlv1.Approval{SchemaVersion: v}}
		},
		"result": func(ev *controlv1.Event, v string) {
			ev.Payload = &controlv1.Event_Result{Result: &controlv1.ActionResult{SchemaVersion: v}}
		},
	}
	var refused int
	for name, payload := range payloads {
		for _, tc := range table {
			ev := &controlv1.Event{EventId: "e1", SchemaVersion: "1.0"}
			payload(ev, tc.Version)
			if got := payloadReadable(ev); got != tc.Admitted {
				t.Errorf("a %s of %q is read %v, want %v", name, tc.Version, got, tc.Admitted)
			}
			if !tc.Admitted {
				refused++
			}
		}
	}
	if refused < 40 {
		t.Fatalf("%d refusals, too few to pin the rule on four payloads", refused)
	}
	for name, ev := range map[string]*controlv1.Event{
		"no payload": {EventId: "e1", SchemaVersion: "1.0"},
		"a finding":  {EventId: "e1", SchemaVersion: "1.0", Payload: &controlv1.Event_Finding{Finding: &controlv1.Finding{}}},
	} {
		if !payloadReadable(ev) {
			t.Errorf("%s is not read", name)
		}
	}
}
