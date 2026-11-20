package attempts

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardana/control/internal/scenario"
)

// demoScenario reads one of the demo's scenarios, the files the demo
// manifest labels.
func demoScenario(t *testing.T, name string) *scenario.Scenario {
	t.Helper()
	s, err := scenario.ReadFile(filepath.Join("..", "..", "examples", "vulnerable-mcp-agent", "scenarios", name))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// threeSteps is deny.json with a second read after the first.
func threeSteps(t *testing.T) *scenario.Scenario {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "examples", "vulnerable-mcp-agent", "scenarios", "deny.json"))
	if err != nil {
		t.Fatal(err)
	}
	read := `,
    {"call": {"tool": "read_order", "args": {"id": "ord-2"}, "answer": {"kind": "result", "codes": []},
      "decided": {"verdict": "ALLOW", "codes": ["RULE_ALLOW"], "obligations": []},
      "trail": {"request": "new", "kinds": ["ACTION_PROPOSED"]}}}
  ]`
	end := strings.LastIndex(string(raw), "\n  ]")
	if end < 0 {
		t.Fatal("deny.json does not end its steps as this test expects")
	}
	s, err := scenario.Read("deny.json", []byte(string(raw[:end])+read+string(raw[end+4:])))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestLabelsCoverTheScenario(t *testing.T) {
	deny := map[string]*scenario.Scenario{"../scenarios/deny.json": demoScenario(t, "deny.json")}
	pause := map[string]*scenario.Scenario{"../scenarios/deny.json": demoScenario(t, "pause.json")}
	if err := mustRead(t, []byte(validManifest)).Bind(deny); err != nil {
		t.Fatalf("the fixture against deny.json: %v", err)
	}
	for _, c := range []struct {
		name      string
		raw       []byte
		scenarios map[string]*scenario.Scenario
		want      Error
	}{
		{"a step left unlabelled", []byte(validManifest), map[string]*scenario.Scenario{"../scenarios/deny.json": threeSteps(t)}, ErrLabel},
		{"a step the scenario lacks", replaced(t, `{"step": 1, "label": "legitimate"}`, `{"step": 1, "label": "legitimate"}, {"step": 2, "label": "legitimate"}`), deny, ErrLabel},
		{"an effect of another call", replaced(t, `"call": "refund"`, `"call": "read_order"`), deny, ErrEffect},
		{"an operator's action labelled otherwise", replaced(t, `{"step": 1, "label": "legitimate"}`,
			`{"step": 1, "label": "legitimate"}, {"step": 2, "label": "legitimate"}, {"step": 3, "label": "legitimate"}`), pause, ErrLabel},
		{"a scenario not read", []byte(validManifest), map[string]*scenario.Scenario{}, ErrLabel},
	} {
		if err := mustRead(t, c.raw).Bind(c.scenarios); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
}
