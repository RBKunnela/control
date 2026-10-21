package enforceclient

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// TestTheDecisionVersionRuleIsTheContractsTable holds the client's reading of
// a decision's version to the table pkg/contract and internal/evidence read.
func TestTheDecisionVersionRuleIsTheContractsTable(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "contracts", "schema_versions.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Version  string `json:"version"`
		Admitted bool   `json:"admitted"`
	}
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) < 10 {
		t.Fatalf("the table holds %d rows", len(rows))
	}
	for _, r := range rows {
		if got := checkDecisionVersion(&controlv1.Decision{SchemaVersion: r.Version}) == nil; got != r.Admitted {
			t.Errorf("a decision of schema_version %q read %v, the table says %v", r.Version, got, r.Admitted)
		}
	}
	if err := checkDecisionVersion(nil); err != nil {
		t.Errorf("an answer with no decision: %v", err)
	}
}
