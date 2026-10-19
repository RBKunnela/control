package hookbridge

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/guardana/control/internal/policy/strictjson"
)

// Kind is the profile format this package reads; a profile names it whole.
const Kind = "hook-profile/v1alpha1"

// kindPrefix starts every version of the format, so another version is
// refused apart from another format.
const kindPrefix = "hook-profile/"

// Bounds a profile is held to.
const (
	maxProfileBytes  = 64 << 10
	maxIDBytes       = 64
	maxNameBytes     = 256
	maxHookTimeout   = 600
	maxEventBytesCap = 64 << 20
)

// Phase is what an event is to an admitted call.
type Phase string

// The phases a profile maps events to.
const (
	PhaseAdmit           Phase = "admit"
	PhaseComplete        Phase = "complete"
	PhaseCompleteFailure Phase = "complete-failure"
)

// StrategyExitCode replies by exit code alone: block or problem, and
// silence with exit 0 for a call the runtime may run.
const StrategyExitCode = "exit-code"

// Members are the top-level member names of an event that hold each value
// the bridge reads.
type Members struct {
	Event, Tool, Input, CallID, SessionID, Interrupt string
}

// Reply is how the bridge's outcome reaches the runtime.
type Reply struct {
	Strategy        string
	BlockExitCode   int
	ProblemExitCode int
}

// Profile is one runtime surface's hook protocol as data. Claims are read
// and kept, and nothing in this package acts on them.
type Profile struct {
	ID            string
	Events        map[string]Phase
	Members       Members
	Reply         Reply
	HookTimeout   time.Duration
	MaxEventBytes int64
	Claims        Claims
}

//go:embed profiles/*/profile.json
var embedded embed.FS

// LoadProfile reads the profile id from the profiles built into the binary.
func LoadProfile(id string) (*Profile, error) {
	return loadFrom(embedded, id)
}

// ReadProfileFile reads the profile at path.
func ReadProfileFile(path string) (*Profile, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the caller names the profile file it reads
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	raw, err := readBounded(f, maxProfileBytes, fmt.Errorf("%w: over %d bytes", ErrProfile, maxProfileBytes))
	if err != nil {
		return nil, err
	}
	return ParseProfile(raw)
}

func loadFrom(fsys fs.FS, id string) (*Profile, error) {
	if !validID(id) {
		return nil, fmt.Errorf("%w: not a profile id", ErrUnknownProfile)
	}
	raw, err := fs.ReadFile(fsys, "profiles/"+id+"/profile.json")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrUnknownProfile
	}
	if err != nil {
		return nil, err
	}
	p, err := ParseProfile(raw)
	if err != nil {
		return nil, err
	}
	if p.ID != id {
		return nil, fmt.Errorf("%w: the profile names another id than its directory", ErrProfile)
	}
	return p, nil
}

// ParseProfile reads raw as a profile, refusing an unknown member, a member
// named twice, another kind and another version of this kind.
func ParseProfile(raw []byte) (*Profile, error) {
	if len(raw) > maxProfileBytes {
		return nil, fmt.Errorf("%w: over %d bytes", ErrProfile, maxProfileBytes)
	}
	o, err := strictjson.ReadObject(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProfile, err)
	}
	if err := checkKind(o); err != nil {
		return nil, err
	}
	members := []string{"kind", "id", "events", "members", "reply", "hook_timeout_seconds", "max_event_bytes", "claims"}
	if err := errors.Join(o.Only(members...), o.Require(members...)); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProfile, err)
	}
	p := &Profile{}
	var ok bool
	if p.ID, ok = strictjson.String(o["id"]); !ok || !validID(p.ID) {
		return nil, fmt.Errorf("%w: id", ErrProfile)
	}
	if err := readBounds(o, p); err != nil {
		return nil, err
	}
	if p.Events, err = readEvents(o["events"]); err != nil {
		return nil, err
	}
	if p.Members, err = readMembers(o["members"]); err != nil {
		return nil, err
	}
	if p.Reply, err = readReply(o["reply"]); err != nil {
		return nil, err
	}
	if p.Claims, err = readClaims(o["claims"]); err != nil {
		return nil, err
	}
	return p, nil
}

// checkKind refuses another format loudly, and another version of this one
// apart from it, so a newer profile is never read as this one.
func checkKind(o strictjson.Object) error {
	kind, ok := strictjson.String(o["kind"])
	if !ok {
		return fmt.Errorf("%w: no kind", ErrProfile)
	}
	switch {
	case !strings.HasPrefix(kind, kindPrefix):
		return fmt.Errorf("%w: not a hook profile", ErrProfile)
	case kind != Kind:
		return ErrProfileVersion
	}
	return nil
}

func readBounds(o strictjson.Object, p *Profile) error {
	timeout, err := positiveInt(o["hook_timeout_seconds"], maxHookTimeout)
	if err != nil {
		return fmt.Errorf("%w: hook_timeout_seconds %w", ErrProfile, err)
	}
	limit, err := positiveInt(o["max_event_bytes"], maxEventBytesCap)
	if err != nil {
		return fmt.Errorf("%w: max_event_bytes %w", ErrProfile, err)
	}
	p.HookTimeout, p.MaxEventBytes = time.Duration(timeout)*time.Second, int64(limit)
	return nil
}

func readEvents(raw json.RawMessage) (map[string]Phase, error) {
	o, err := strictjson.ReadObject(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: events %w", ErrProfile, err)
	}
	events := make(map[string]Phase, len(o))
	admits := false
	for name, v := range o {
		phase, ok := strictjson.String(v)
		if !ok || name == "" || len(name) > maxNameBytes {
			return nil, fmt.Errorf("%w: events", ErrProfile)
		}
		switch Phase(phase) {
		case PhaseAdmit:
			admits = true
		case PhaseComplete, PhaseCompleteFailure:
		default:
			return nil, fmt.Errorf("%w: events names a phase this format does not have", ErrProfile)
		}
		events[name] = Phase(phase)
	}
	if !admits {
		return nil, fmt.Errorf("%w: no event admits", ErrProfile)
	}
	return events, nil
}

func readMembers(raw json.RawMessage) (Members, error) {
	o, err := strictjson.ReadObject(raw)
	if err != nil {
		return Members{}, fmt.Errorf("%w: members %w", ErrProfile, err)
	}
	names := []string{"event", "tool", "input", "call_id", "session_id", "interrupt"}
	if err := errors.Join(o.Only(names...), o.Require(names...)); err != nil {
		return Members{}, fmt.Errorf("%w: members %w", ErrProfile, err)
	}
	var m Members
	seen := map[string]bool{}
	for _, f := range []struct {
		key  string
		into *string
	}{{"event", &m.Event}, {"tool", &m.Tool}, {"input", &m.Input}, {"call_id", &m.CallID}, {"session_id", &m.SessionID}, {"interrupt", &m.Interrupt}} {
		v, ok := strictjson.String(o[f.key])
		if !ok || v == "" || len(v) > maxNameBytes || seen[v] {
			return Members{}, fmt.Errorf("%w: members.%s", ErrProfile, f.key)
		}
		seen[v], *f.into = true, v
	}
	return m, nil
}

func readReply(raw json.RawMessage) (Reply, error) {
	o, err := strictjson.ReadObject(raw)
	if err != nil {
		return Reply{}, fmt.Errorf("%w: reply %w", ErrProfile, err)
	}
	names := []string{"strategy", "block_exit_code", "problem_exit_code"}
	if err := errors.Join(o.Only(names...), o.Require(names...)); err != nil {
		return Reply{}, fmt.Errorf("%w: reply %w", ErrProfile, err)
	}
	var r Reply
	var ok bool
	if r.Strategy, ok = strictjson.String(o["strategy"]); !ok || r.Strategy != StrategyExitCode {
		return Reply{}, fmt.Errorf("%w: reply.strategy", ErrProfile)
	}
	if r.BlockExitCode, err = positiveInt(o["block_exit_code"], 125); err != nil {
		return Reply{}, fmt.Errorf("%w: reply.block_exit_code %w", ErrProfile, err)
	}
	if r.ProblemExitCode, err = positiveInt(o["problem_exit_code"], 125); err != nil {
		return Reply{}, fmt.Errorf("%w: reply.problem_exit_code %w", ErrProfile, err)
	}
	if r.BlockExitCode == r.ProblemExitCode {
		return Reply{}, fmt.Errorf("%w: reply gives block and problem one exit code", ErrProfile)
	}
	return r, nil
}

// positiveInt reads raw, a JSON value, as an integer with no fraction or
// exponent, from 1 to hi.
func positiveInt(raw json.RawMessage, hi int) (int, error) {
	n, err := strconv.Atoi(string(raw))
	if err != nil || n < 1 || n > hi {
		return 0, fmt.Errorf("is not an integer from 1 to %d", hi)
	}
	return n, nil
}

// validID reports whether id is 1 to 64 characters of [a-z0-9-] that start
// with a letter or digit, so it names one directory and nothing above it.
func validID(id string) bool {
	if id == "" || len(id) > maxIDBytes || id[0] == '-' {
		return false
	}
	for i := 0; i < len(id); i++ {
		if c := id[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}
