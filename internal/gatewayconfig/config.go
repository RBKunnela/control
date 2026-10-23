package gatewayconfig

import (
	"fmt"
	"maps"
	"path/filepath"
	"strings"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/classify"
)

// Config is one plane's configuration, as a file and the environment set it.
// Every key of it is in the tables of fields.go; nothing is read from anywhere
// else, so a key nobody declared is a key the loader refuses.
type Config struct {
	// ModeName is the enforcement mode as the operator spelled it; Mode
	// turns it into the contract's value.
	ModeName    string
	ProjectID   string
	TenantID    string
	Environment string
	LogLevel    string

	Listener  ListenerConfig
	Health    HealthConfig
	Policy    PolicyConfig
	PDP       PDPConfig
	Approvals ApprovalsConfig
	Pause     PauseConfig
	Runs      RunsConfig
	Reaction  ReactionConfig
	Flow      FlowConfig
	Evidence  EvidenceConfig
	Export    ExportConfig
	List      ListConfig
	Upstream  UpstreamDefaults

	Upstreams []UpstreamConfig
	Overrides []OverrideConfig
	Tools     []ToolConfig

	// dir is the directory of the file the configuration was read from, which
	// every relative path in it resolves against.
	dir string
	// source names, per key, the file position or the environment variable
	// that set it. A key that is absent stands at its default.
	source map[string]string
}

// ListenerConfig is the agent-facing side. Socket, ExecutionLifetime,
// MaxBodyBytes and MaxOpenPerRun are the enforcement API's, which serves on a
// Unix socket.
type ListenerConfig struct {
	Kind              string
	Address           string
	Socket            string
	ExecutionLifetime time.Duration
	MaxBodyBytes      int64
	MaxOpenPerRun     int
	Origins           []string
	PrincipalID       string
	PrincipalType     string
	PrincipalTenant   string
	AgentID           string
	AgentFramework    string
	AgentVersion      string
	SessionIdle       time.Duration
	MaxSessions       int
}

// HealthConfig is the plane's own answers.
type HealthConfig struct {
	Address string
}

// PolicyConfig pins the bundle the plane serves and the key it verifies with,
// the freshness statement that confirms it and the key that signs that, and
// the directory that keeps its serial floor.
type PolicyConfig struct {
	BundleID           string
	BundleFile         string
	KeyID              string
	PublicKey          string
	StatementFile      string
	StateDir           string
	FreshnessKeyID     string
	FreshnessPublicKey string
	MaxStale           time.Duration
	// PollInterval is how often the plane reads the bundle and the
	// statement again. It has no default.
	PollInterval time.Duration
	FailOpenRead bool
}

// PDPConfig is the external decision point the policy's veto rules ask
// (ADR-0017). An empty Identifier configures none, and then no other key of
// it may be set.
type PDPConfig struct {
	Identifier         string
	EvaluationEndpoint string
	Timeout            time.Duration
	MaxInFlight        int
	// AllowPlaintext lets the identifier be http on a loopback address: over
	// plaintext anyone on the path can forge the answer that lifts a veto.
	AllowPlaintext bool
	// Proxy is the one proxy questions go through; its userinfo is a
	// credential.
	Proxy   string
	Headers map[string]string
	// InformationalContext names the context members an allowing answer may
	// carry; any other member makes it unreadable.
	InformationalContext []string
}

// The approval providers a plane holds its requests in. The file provider is
// a directory an approver outside the process writes; the memory provider
// keeps its records in the process that holds them, so nothing outside it
// answers a hold (ADR-0016).
const (
	ProviderMemory = "memory"
	ProviderFile   = "file"
)

// ApprovalsConfig names the store a held request is kept in and bounds what
// that store can make the plane do.
type ApprovalsConfig struct {
	Provider string
	// Dir is the approvals directory, and HoldJournalDir the plane's own
	// journal of its own holds. The file provider needs both, and the
	// journal's directory is never one another writer owns.
	Dir            string
	HoldJournalDir string
	TTL            time.Duration
	RetryAfter     time.Duration
	MaxHeld        int
	// MaxHeldPerRun bounds the requests one opened run holds; only a plane
	// with a runs directory reads it.
	MaxHeldPerRun int
	MaxOpen       int
	// MaxRecords and MaxRecordBytes bound the approvals directory and the
	// hold journal alike: one held request is one record and one entry.
	MaxRecords     int
	MaxRecordBytes int
	// ReconcileMax bounds the journal entries one reconciliation reads. A
	// pass the bound stopped is unmeasured, never done.
	ReconcileMax int
}

// PauseConfig is the operator's pause file and how often the plane reads it
// (ADR-0019). An empty File configures none, and the plane says it is
// disabled.
type PauseConfig struct {
	File         string
	PollInterval time.Duration
}

// EvidenceConfig is the spool and the one risk setting over it.
type EvidenceConfig struct {
	Dir            string
	MaxBytes       int64
	SegmentBytes   int64
	ClosingReserve int64
	Fsync          string
	FsyncInterval  time.Duration
	OnUnwritable   string
}

// ExportConfig is the collector the spool drains to.
type ExportConfig struct {
	Endpoint string
	// AllowPlaintext lets the endpoint be http on a loopback IP literal only:
	// over plaintext anyone on the path can forge the collector's acceptance
	// and read the headers.
	AllowPlaintext bool
	Headers        map[string]string
	Timeout        time.Duration
	InFlight       int
	MaxBatch       int
	Linger         time.Duration
	Backoff        time.Duration
	MaxBackoff     time.Duration
}

// ListConfig is what tools/list subtracts and for how long a shaped list
// stands.
type ListConfig struct {
	Shaping string
	TTL     time.Duration
}

// UpstreamDefaults bound every upstream call.
type UpstreamDefaults struct {
	CallTimeout time.Duration
	// ListTimeout bounds reading one upstream's list, and connecting to each
	// upstream at start; zero is the adapter's own bound.
	ListTimeout time.Duration
}

// UpstreamConfig is one server the gateway calls as itself: over Streamable
// HTTP when Endpoint is set, over a child process when Command is.
type UpstreamConfig struct {
	Name     string
	Endpoint string
	Command  string
	Args     []string
	// Env names the variables of the plane's environment a command
	// receives, beside a fixed few; nothing else of it reaches the process.
	Env         []string
	TenantID    string
	Environment string
}

// OverrideConfig is the operator's classification of one tool definition. The
// fingerprint pins the definition: a tool whose definition changed is
// unclassified until the operator looks again (ADR-0013). The trust zone is
// where a call to the tool sends data; the returns keys are what its results
// contain (ADR-0021).
type OverrideConfig struct {
	Upstream    string
	Tool        string
	Fingerprint string
	classify.Spelling
}

// Classification is the override's classification as the adapter takes it,
// or the refusal naming its key.
func (o *OverrideConfig) Classification() (classify.Classification, error) {
	return classify.Parse(o.Spelling)
}

// Mode is the enforcement mode the contract names. The table has already
// refused every spelling but the six, so an unknown one here is a table that
// drifted from the contract rather than an operator's typo.
func (c *Config) Mode() (controlv1.EnforcementMode, error) {
	number, ok := controlv1.EnforcementMode_value["ENFORCEMENT_MODE_"+c.ModeName]
	if !ok {
		return 0, fmt.Errorf("the contract declares no enforcement mode %q", c.ModeName)
	}
	return controlv1.EnforcementMode(number), nil
}

// Resolve reads a path from the configuration against the directory of the
// file it was read from, so a relative path means the same thing wherever the
// program is started.
func (c *Config) Resolve(path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(c.dir, path)
}

// Sources names, per key the file or the environment set, the file position
// or the variable that set it. A key that is absent stands at its default.
func (c *Config) Sources() map[string]string {
	return maps.Clone(c.source)
}

// Setting is one scalar key of the configuration and its value as the table
// spells it.
type Setting struct {
	Path  string
	Value string
}

// NotPrinted stands in for the value of a credential wherever the
// configuration is printed.
const NotPrinted = "set, not printed"

// Settings lists every scalar key of the top-level table, in the table's
// order, with the value the configuration holds for it; a credential that is
// set shows as NotPrinted. The lists and the maps are not scalar keys and are
// read from the struct.
func (c *Config) Settings() []Setting {
	out := make([]Setting, 0, len(configFields))
	for _, f := range configFields {
		value := f.show(c)
		switch {
		case f.credential && value != "":
			value = NotPrinted
		case f.address:
			value = ShowAddress(value)
		}
		out = append(out, Setting{Path: f.path, Value: value})
	}
	return out
}

// ShowAddress is a URL as it may be printed. Userinfo, a query or a fragment
// can each hold a credential, so a value carrying any of them is withheld
// whole, naming the first; the client's own rules for the value stay its own.
func ShowAddress(value string) string {
	i := strings.IndexAny(value, "@?#")
	if i < 0 {
		return value
	}
	carries := map[byte]string{'@': "userinfo", '?': "a query", '#': "a fragment"}[value[i]]
	return NotPrinted + ": it carries " + carries
}
