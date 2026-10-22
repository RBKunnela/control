package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/loopback"
	"github.com/guardana/control/internal/policykey"
)

// devSet is every key dev gives a value of its own, and silentSet the keys it
// adds for a silent decision point. Every key under approvals is dev's too,
// set or left at its default, so a demo that tunes the store is refused
// rather than half obeyed; so is every key under pdp with a silent decision
// point.
var devSet = []string{
	"listener.address",
	"health.address",
	"policy.bundle_file",
	"policy.key_id",
	"policy.public_key",
	"policy.statement_file",
	"policy.state_dir",
	"policy.freshness_key_id",
	"policy.freshness_public_key",
	"approvals.provider",
	"approvals.dir",
	"approvals.hold_journal_dir",
	"pause.file",
	"evidence.dir",
	"export.endpoint",
	"export.allow_plaintext",
}

var silentSet = []string{
	"pdp.identifier",
	"pdp.allow_plaintext",
}

// ownedPrefixes is what dev owns beyond the keys the layer sets.
func (l devLayer) ownedPrefixes() []string {
	if _, silent := l["pdp.identifier"]; silent {
		return []string{"approvals.", "runs.", "pdp."}
	}
	return []string{"approvals.", "runs."}
}

// refuseEnvironment names the first variable under the product's prefix. Dev
// reads none of them, since the loader gets dev's own values alone; one left
// set is refused so that nobody believes it applies.
func refuseEnvironment(environ []string) error {
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, brand.EnvPrefix) {
			return fmt.Errorf("%s is set; dev sets the plane's configuration itself and reads no %s variable, so unset it", name, brand.EnvPrefix+"*")
		}
	}
	return nil
}

// devLayer is dev's own values, bound over the demo's file through the
// loader's environment, the one binder a variable goes through.
type devLayer map[string]string

// devKeys are the public halves of the two keys a dev plane pins: the one
// that signed its bundle and the freshness key that signs its statements.
type devKeys struct {
	bundle, freshness ed25519.PublicKey
}

// newLayer is dev's values for a plane whose state is under st, which pins
// keys, listens at listen and health, exports to collector and, when silent
// is not empty, asks the decision point there, each a host:port.
func newLayer(st devState, keys devKeys, listen, health, collector, silent string) devLayer {
	l := devLayer{
		"listener.address":            listen,
		"health.address":              health,
		"policy.bundle_file":          st.path(stateBundle),
		"policy.key_id":               policykey.KeyID(keys.bundle),
		"policy.public_key":           policykey.FormatPublic(keys.bundle),
		"policy.statement_file":       st.path(stateStatement),
		"policy.state_dir":            st.path(stateFloors),
		"policy.freshness_key_id":     policykey.KeyID(keys.freshness),
		"policy.freshness_public_key": policykey.FormatPublic(keys.freshness),
		"approvals.provider":          gatewayconfig.ProviderFile,
		"approvals.dir":               st.path(stateApprovals),
		"approvals.hold_journal_dir":  st.path(stateHolds),
		"pause.file":                  st.path(statePause),
		"evidence.dir":                st.path(stateSpool),
		"export.endpoint":             "http://" + collector + logsPath,
		"export.allow_plaintext":      "true",
	}
	if silent != "" {
		l["pdp.identifier"] = "http://" + silent
		l["pdp.allow_plaintext"] = "true"
	}
	return l
}

// keys is every key the layer sets, in a fixed order.
func (l devLayer) keys() []string {
	var out []string
	for _, key := range slices.Concat(devSet, silentSet) {
		if _, ok := l[key]; ok {
			out = append(out, key)
		}
	}
	return out
}

// environ is the layer as variables, without the keys in except.
func (l devLayer) environ(except ...string) []string {
	out := make([]string, 0, len(l))
	for _, key := range l.keys() {
		if !slices.Contains(except, key) {
			out = append(out, brand.Env(gatewayconfig.EnvName(key))+"="+l[key])
		}
	}
	return out
}

// resolveDemo loads the demo's configuration under the layer and refuses one
// that sets a key dev owns, a stdio listener, and any address dev reaches
// that is not a loopback IP literal. It reads the file and creates nothing.
func resolveDemo(path string, l devLayer) (*gatewayconfig.Config, error) {
	if probe, err := gatewayconfig.Load(path, l.environ("listener.address")); err == nil && probe.Listener.Kind == gatewayconfig.ListenerStdio {
		return nil, errors.New("listener.kind is stdio; a dev plane serves its agents over HTTP on the loopback")
	}
	cfg, err := gatewayconfig.Load(path, l.environ())
	if err != nil {
		return nil, err
	}
	owned := slices.Collect(maps.Keys(cfg.Sources()))
	slices.Sort(owned)
	owned = slices.DeleteFunc(owned, func(key string) bool {
		_, layered := l[key]
		return layered || !slices.ContainsFunc(l.ownedPrefixes(), func(p string) bool { return strings.HasPrefix(key, p) })
	})
	for _, key := range slices.Concat(l.keys(), owned) {
		set := true
		if _, layered := l[key]; layered {
			set = fileSets(path, l, key)
		}
		if set {
			return nil, fmt.Errorf("%s: %s sets it, and dev owns it; remove it from the demo's configuration", key, path)
		}
	}
	if err := devAddresses(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// fileSets reports whether the file at path sets key, which the layer sets
// too and so hides from the loaded configuration's sources. The file is
// loaded without the layer's key, and then without every key the layer sets
// in the key's group, which another key of it may need: a load that stands
// names the key's source if the file set it. When both fail, the file is
// loaded once more with the key's default set through the layer, and a file
// that did not set the key fails that load and the first with the same
// refusal, since both then hold the same values.
func fileSets(path string, l devLayer, key string) bool {
	group, _, _ := strings.Cut(key, ".")
	var sameGroup []string
	for _, k := range l.keys() {
		if strings.HasPrefix(k, group+".") {
			sameGroup = append(sameGroup, k)
		}
	}
	var first error
	for _, except := range [][]string{{key}, sameGroup} {
		without, err := gatewayconfig.Load(path, l.environ(except...))
		if err == nil {
			_, set := without.Sources()[key]
			return set
		}
		if first == nil {
			first = err
		}
	}
	pinned := append(l.environ(key), brand.Env(gatewayconfig.EnvName(key))+"="+defaultOf(key))
	_, again := gatewayconfig.Load(path, pinned)
	return again == nil || again.Error() != first.Error()
}

func defaultOf(key string) string {
	for _, f := range gatewayconfig.Fields() {
		if f.Path == key {
			return f.Default
		}
	}
	return ""
}

// devAddresses refuses a listener, a health address, a collector, an
// upstream's endpoint or a decision point's URL that is not a loopback IP
// literal. An upstream run as a command, and a decision point key left
// empty, name no address.
func devAddresses(cfg *gatewayconfig.Config) error {
	for _, a := range [][2]string{
		{"listener.address", cfg.Listener.Address},
		{"health.address", cfg.Health.Address},
	} {
		if err := loopback.Check(a[1]); err != nil {
			return fmt.Errorf("%s: %w", a[0], err)
		}
	}
	if err := loopback.CheckURL(cfg.Export.Endpoint); err != nil {
		return fmt.Errorf("export.endpoint: %w", err)
	}
	optional := [][2]string{
		{"pdp.identifier", cfg.PDP.Identifier},
		{"pdp.evaluation_endpoint", cfg.PDP.EvaluationEndpoint},
		{"pdp.proxy", cfg.PDP.Proxy},
	}
	for i, up := range cfg.Upstreams {
		optional = append(optional, [2]string{fmt.Sprintf("upstreams.%d.endpoint", i), up.Endpoint})
	}
	for _, a := range optional {
		if a[1] == "" {
			continue
		}
		if err := loopback.CheckURL(a[1]); err != nil {
			return fmt.Errorf("%s: %w", a[0], err)
		}
	}
	return nil
}

// writeSettings writes every scalar key the plane resolved, one `key: value`
// line each, credentials withheld as the loader withholds them.
func writeSettings(path string, cfg *gatewayconfig.Config) error {
	var b strings.Builder
	for _, s := range cfg.Settings() {
		b.WriteString(s.Path + ": " + oneLine(s.Value) + "\n")
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}
