package enforce_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/guardana/control/adapters/enforce"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/classify"
)

const casesDir = "../../testdata/enforce"

type caseEntry struct {
	ID              string `json:"id"`
	Side            string `json:"side"`
	Contract        string `json:"contract"`
	Rule            string `json:"rule"`
	NegativeControl struct {
		Defect string `json:"defect"`
		Breaks string `json:"breaks"`
	} `json:"negative_control"`
}

type setupFile struct {
	Mode              string            `json:"mode"`
	Rules             []json.RawMessage `json:"rules"`
	Tools             []toolFile        `json:"tools"`
	ExecutionLifetime string            `json:"execution_lifetime"`
	Runs              []runFile         `json:"runs"`
}

type toolFile struct {
	Name               string `json:"name"`
	Effect             string `json:"effect"`
	Provider           string `json:"provider"`
	ResourceType       string `json:"resource_type"`
	ResourceFrom       string `json:"resource_from"`
	TrustZone          string `json:"trust_zone"`
	ReturnsTrust       string `json:"returns_trust"`
	ReturnsSensitivity string `json:"returns_sensitivity"`
}

type runFile struct {
	Name   string `json:"name"`
	Token  string `json:"token"`
	For    string `json:"for"`
	Closed bool   `json:"closed"`
}

// step is one line of exchange.jsonl: exactly one of a request, a clock
// advance, a sweep, an approval or requests sent together.
type step struct {
	request
	Advance  string    `json:"advance"`
	Sweep    *int      `json:"sweep"`
	Approve  string    `json:"approve"`
	Together *together `json:"together"`
}

type request struct {
	As     string          `json:"as"`
	Post   string          `json:"post"`
	Body   json.RawMessage `json:"body"`
	Raw    *string         `json:"raw"`
	Status int             `json:"status"`
	Answer json.RawMessage `json:"answer"`
}

type expected struct {
	Status int             `json:"status"`
	Answer json.RawMessage `json:"answer"`
}

type together struct {
	Requests []request  `json:"requests"`
	Answers  []expected `json:"answers"`
}

type trailFile struct {
	Unordered bool           `json:"unordered"`
	Events    []trailedEvent `json:"events"`
}

type trailedEvent struct {
	Kind   string    `json:"kind"`
	Codes  *[]string `json:"codes,omitempty"`
	Status string    `json:"status,omitempty"`
	Code   *string   `json:"code,omitempty"`
}

func strictJSON(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

func readJSON(t *testing.T, name string, v any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(name))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	if err := strictJSON(data, v); err != nil {
		t.Fatalf("decoding %s: %v", name, err)
	}
}

func receiverCases(t *testing.T) []caseEntry {
	t.Helper()
	var file struct {
		Cases []caseEntry `json:"cases"`
	}
	readJSON(t, filepath.Join(casesDir, "cases.json"), &file)
	var out []caseEntry
	for _, c := range file.Cases {
		if c.Side == "receiver" {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		t.Fatal("cases.json lists no receiver case")
	}
	return out
}

func loadSteps(t *testing.T, dir string) []step {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(filepath.Join(dir, "exchange.jsonl")))
	if err != nil {
		t.Fatal(err)
	}
	var out []step
	for i, line := range bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n")) {
		var s step
		if err := strictJSON(line, &s); err != nil {
			t.Fatalf("%s line %d: %v", dir, i+1, err)
		}
		kinds := 0
		for _, set := range []bool{s.Post != "", s.Advance != "", s.Sweep != nil, s.Approve != "", s.Together != nil} {
			if set {
				kinds++
			}
		}
		if kinds != 1 || (s.Post != "" && s.Status == 0) {
			t.Fatalf("%s line %d: one kind of step, and a request names its status", dir, i+1)
		}
		out = append(out, s)
	}
	return out
}

// enumValue reads an enumeration value by the name protojson writes, so a
// setup file spells it as an answer does.
func enumValue[T ~int32](t *testing.T, name string, values map[string]int32) T {
	t.Helper()
	if name == "" {
		return 0
	}
	v, ok := values[name]
	if !ok {
		t.Fatalf("no enumeration value %q", name)
	}
	return T(v)
}

func buildFromSetup(t *testing.T, s setupFile, d defect) (*rig, map[string]string) {
	t.Helper()
	o := defaults()
	o.mode = enumValue[controlv1.EnforcementMode](t, s.Mode, controlv1.EnforcementMode_value)
	if d.mode != 0 {
		o.mode = d.mode
	}
	o.rules = nil
	for _, rule := range s.Rules {
		o.rules = append(o.rules, string(rule))
	}
	o.tools = nil
	for _, tf := range s.Tools {
		o.tools = append(o.tools, enforce.Tool{
			Name:     tf.Name,
			Provider: tf.Provider,
			Classification: classify.Classification{
				Effect:             enumValue[controlv1.EffectClass](t, tf.Effect, controlv1.EffectClass_value),
				ResourceType:       tf.ResourceType,
				ResourceFrom:       tf.ResourceFrom,
				TrustZone:          enumValue[controlv1.TrustZone](t, tf.TrustZone, controlv1.TrustZone_value),
				ReturnsTrust:       enumValue[controlv1.TrustZone](t, tf.ReturnsTrust, controlv1.TrustZone_value),
				ReturnsSensitivity: enumValue[controlv1.Sensitivity](t, tf.ReturnsSensitivity, controlv1.Sensitivity_value),
			},
		})
	}
	if d.tools != nil {
		o.tools = d.tools(o.tools)
	}
	lifetime, err := time.ParseDuration(s.ExecutionLifetime)
	if err != nil {
		t.Fatalf("execution_lifetime %q", s.ExecutionLifetime)
	}
	o.lifetime, o.adapter, o.pipeline, o.resolver = lifetime, d.adapter, d.pipeline, d.resolver
	r := newRig(t, o)
	tokens := map[string]string{}
	for _, run := range s.Runs {
		tokens[run.Name] = run.Token
		who := listenerWho()
		switch run.For {
		case "listener":
		case "other":
			who.AgentID = "agent-2"
		case "nobody":
			continue
		default:
			t.Fatalf("run %s is for %q", run.Name, run.For)
		}
		r.runs.add(run.Token, "run-"+run.Name, who)
		if run.Closed {
			r.runs.close(run.Token)
		}
	}
	return r, tokens
}
