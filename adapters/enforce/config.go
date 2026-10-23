package enforce

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/classify"
	"github.com/guardana/control/internal/gateway"
)

// The bounds of a listener's execution lifetime. An execution handed out is
// held open until it is completed, aborted or abandoned at its expiry, so the
// lifetime is how long one call may hold one of the plane's open slots.
const (
	MinExecutionLifetime = time.Second
	MaxExecutionLifetime = time.Hour
)

// The bounds of a request body, and the one taken when none is configured. The
// default carries an argument document of contract.MaxArgumentsBytes as
// base64 with room for the rest of the message.
const (
	MinBodyBytes     = 1 << 10
	MaxBodyBytes     = 1 << 18
	DefaultBodyBytes = 1 << 17
)

// DefaultMaxSpent is how many spent handles are kept to answer HANDLE_SPENT
// before the oldest is forgotten and answers HANDLE_UNKNOWN.
const DefaultMaxSpent = 4096

// DefaultMaxOpenPerRun is how many executions one run may hold open, its
// admits in flight included, when none is configured.
const DefaultMaxOpenPerRun = 16

// DefaultSweepMax is how many expired executions one Sweep abandons.
const DefaultSweepMax = 256

// DefaultRequestTimeout bounds how long Serve lets one request take over its
// headers and body, and its answer wait on a client that stops reading.
const DefaultRequestTimeout = 30 * time.Second

// Identity is who every call of the listener is made by: the run a token
// names has to be for this principal and agent.
type Identity struct {
	Principal *controlv1.Principal
	Agent     *controlv1.Agent
}

// Tool is the operator's classification of one tool, by name. Nothing binds
// it to what the tool does: the plane never sees the tool's definition. The
// promoted Check covers the classification alone; New checks the name and the
// provider too.
type Tool struct {
	// Name is what an admit names the tool by.
	Name string
	// Provider is the envelope's action.provider.
	Provider string
	classify.Classification
}

// Config configures an Adapter once, at New.
type Config struct {
	// Socket is the absolute path of the Unix socket Listen binds, in a
	// directory this process owns.
	Socket string
	// ExecutionLifetime is how long a handle stays open before the sweep
	// abandons it; required, between MinExecutionLifetime and
	// MaxExecutionLifetime.
	ExecutionLifetime time.Duration
	// MaxBodyBytes bounds a request body; zero takes DefaultBodyBytes.
	MaxBodyBytes int64
	// ProjectID, TenantID and Environment say where the request was received.
	// TenantID and Environment are also the resource's: a tool of this
	// listener acts where its agent runs.
	ProjectID   string
	TenantID    string
	Environment string
	Identity    Identity
	// Runs resolves the run token every request presents (ADR-0034).
	Runs gateway.RunResolver
	// Tools classifies every tool the listener serves; a name it does not
	// hold is unclassified.
	Tools []Tool
	// MaxSpent bounds the spent handles kept; zero takes DefaultMaxSpent.
	MaxSpent int
	// MaxOpenPerRun bounds the executions one run holds open, its admits in
	// flight included, so one run cannot take every slot the plane's MaxOpen
	// allows; zero takes DefaultMaxOpenPerRun.
	MaxOpenPerRun int
	// SweepMax bounds the executions one Sweep abandons; zero takes
	// DefaultSweepMax.
	SweepMax int
	// RequestTimeout bounds one request in Serve; zero takes
	// DefaultRequestTimeout.
	RequestTimeout time.Duration
	Clock          func() time.Time
	// NewID names every request the adapter admits; the client never does.
	NewID func() string
}

// maxSocketPath is the longest socket path every platform the releases ship
// can bind: a sockaddr_un holds 104 bytes on macOS, its terminator included.
const maxSocketPath = 103

// checkConfig is New's refusals, in the order New documents them.
func checkConfig(cfg Config) error {
	if err := checkListener(cfg); err != nil {
		return err
	}
	if err := checkTools(cfg.Tools); err != nil {
		return err
	}
	switch {
	case cfg.MaxSpent < 0 || cfg.MaxOpenPerRun < 0 || cfg.SweepMax < 0 || cfg.RequestTimeout < 0:
		return ErrBound
	case cfg.Clock == nil:
		return ErrNoClock
	case cfg.NewID == nil:
		return ErrNoIDSource
	}
	return nil
}

// checkListener refuses a socket path, an execution lifetime, a body bound,
// an identity or a run resolver New refuses.
func checkListener(cfg Config) error {
	switch {
	case cfg.Socket == "" || !filepath.IsAbs(cfg.Socket) || len(cfg.Socket) > maxSocketPath:
		return fmt.Errorf("%w: %d bytes", ErrSocket, len(cfg.Socket))
	case cfg.ExecutionLifetime < MinExecutionLifetime || cfg.ExecutionLifetime > MaxExecutionLifetime:
		return fmt.Errorf("%w: %v", ErrLifetime, cfg.ExecutionLifetime)
	case cfg.MaxBodyBytes != 0 && (cfg.MaxBodyBytes < MinBodyBytes || cfg.MaxBodyBytes > MaxBodyBytes):
		return fmt.Errorf("%w: %d", ErrBodyBound, cfg.MaxBodyBytes)
	case cfg.Identity.Principal.GetId() == "" || cfg.Identity.Agent.GetId() == "":
		return ErrIdentity
	case cfg.Runs == nil:
		return ErrNoRuns
	}
	return nil
}

// checkTools refuses an empty table and a tool that is incomplete, repeated
// or out of bounds, naming the tool by its position.
func checkTools(tools []Tool) error {
	if len(tools) == 0 {
		return fmt.Errorf("%w: no tool", ErrTool)
	}
	seen := make(map[string]bool, len(tools))
	for i, tool := range tools {
		if err := checkTool(tool); err != nil {
			return fmt.Errorf("%w: tools[%d]: %w", ErrTool, i, err)
		}
		if seen[tool.Name] {
			return fmt.Errorf("%w: tools[%d]: a name another tool has", ErrTool, i)
		}
		seen[tool.Name] = true
	}
	return nil
}

// The keys of a tool that are not its classification's.
const (
	keyName     = "name"
	keyProvider = "provider"
)

// checkTool refuses a name or a provider no envelope can carry, a class that
// needs a delegation this API does not carry, and a classification
// classify.Check refuses, each as a *classify.Error naming the key.
func checkTool(tool Tool) error {
	if err := classify.CheckEnvelopeString(tool.Name); err != nil {
		return &classify.Error{Key: keyName, Err: err}
	}
	if err := tool.Check(); err != nil {
		return err
	}
	if classify.RequiresDelegation(tool.Effect) {
		return &classify.Error{Key: classify.KeyEffect, Err: fmt.Errorf("%w: %s needs a delegation this API does not carry",
			classify.ErrEffect, strings.TrimPrefix(tool.Effect.String(), "EFFECT_CLASS_"))}
	}
	if err := classify.CheckEnvelopeString(tool.Provider); err != nil {
		return &classify.Error{Key: keyProvider, Err: err}
	}
	return nil
}
