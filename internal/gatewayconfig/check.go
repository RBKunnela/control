package gatewayconfig

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

// check refuses a configuration that is complete in its own keys but says two
// things at once, or says nothing where a value is needed. What the pipeline,
// the adapter and the spool refuse is left to them, so their message names
// their own rule; what only this file knows is refused here, naming the key.
func (c *Config) check() error {
	if err := checkRequired(c, configFields, ""); err != nil {
		return err
	}
	for _, check := range []func() error{c.checkKindKeys, c.checkListener, c.checkSessionIdle, c.checkMaxSessions, c.checkPolicy, c.checkPDP, c.checkApprovals, c.checkPause, c.checkRuns, c.checkReaction, c.checkFlow, c.checkEvidence, c.checkExport, c.checkShaping, c.checkTimeouts, c.checkUpstreams, c.checkOverrides} {
		if err := check(); err != nil {
			return err
		}
	}
	return nil
}

// checkListener refuses an address on a listener that has none, and an empty
// origin.
func (c *Config) checkListener() error {
	if c.Listener.Kind == ListenerStdio && c.wasSet("listener.address") {
		return fmt.Errorf("listener.address: a stdio listener serves one agent over a pipe and binds nothing")
	}
	if c.Listener.Kind != ListenerStdio && c.Listener.Address == "" {
		return fmt.Errorf("listener.address: an HTTP listener needs an address to bind")
	}
	for i, origin := range c.Listener.Origins {
		u, err := url.Parse(origin)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("listener.origins.%d: %s is not an origin such as http://localhost:5173", i, quoteValue(origin))
		}
		// A page on the operator's own machine is only the operator's machine
		// while the listener is not reachable from elsewhere.
		if loopback(u.Hostname()) && !loopback(listenerHost(c.Listener.Address)) {
			return fmt.Errorf("listener.origins.%d: a loopback origin is admitted only while listener.address is on loopback, and it is %s", i, quoteValue(c.Listener.Address))
		}
	}
	return nil
}

// The bounds of listener.session_idle. Below the floor a session ends between
// an agent's ordinary calls; above the ceiling an abandoned one holds its
// memory for longer than a working day.
const (
	minSessionIdle = time.Minute
	maxSessionIdle = 24 * time.Hour
)

// checkSessionIdle refuses a session bound on a listener that keeps no
// session, and one outside its bounds.
func (c *Config) checkSessionIdle() error {
	if c.Listener.Kind != ListenerStatefulHTTP && c.wasSet("listener.session_idle") {
		return fmt.Errorf("listener.session_idle: only a stateful_http listener keeps sessions, and the kind is %s", c.Listener.Kind)
	}
	if c.Listener.SessionIdle < minSessionIdle || c.Listener.SessionIdle > maxSessionIdle {
		return fmt.Errorf("listener.session_idle: %v is outside %v to %v", c.Listener.SessionIdle, minSessionIdle, maxSessionIdle)
	}
	return nil
}

// maxMaxSessions is the most listener.max_sessions takes: past it the
// sessions clients may hold open outweigh what one plane is sized to keep.
const maxMaxSessions = 16384

// checkMaxSessions refuses a cap on sessions on a listener that keeps none,
// and one outside its bounds.
func (c *Config) checkMaxSessions() error {
	if c.Listener.Kind != ListenerStatefulHTTP && c.wasSet("listener.max_sessions") {
		return fmt.Errorf("listener.max_sessions: only a stateful_http listener keeps sessions, and the kind is %s", c.Listener.Kind)
	}
	if c.Listener.MaxSessions < 1 || c.Listener.MaxSessions > maxMaxSessions {
		return fmt.Errorf("listener.max_sessions: %d is outside 1 to %d", c.Listener.MaxSessions, maxMaxSessions)
	}
	return nil
}

// listenerHost is the host an address binds, and the empty string for an
// address that binds every interface.
func listenerHost(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	return host
}

// loopback reports whether a host names this machine and nothing else.
func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// checkPDP refuses a decision point key set with no decision point to apply
// it to: a key that applies to nothing is a setting the operator believes is
// in force. What the decision point's client refuses is left to it.
func (c *Config) checkPDP() error {
	if c.PDP.Identifier != "" {
		return nil
	}
	var set []string
	for _, f := range configFields {
		if f.path != "pdp.identifier" && c.wasSet(f.path) {
			set = append(set, f.path)
		}
	}
	for _, l := range listFields {
		if len(*l.get(c)) > 0 {
			set = append(set, l.path)
		}
	}
	for _, m := range mapFields {
		if len(*m.get(c)) > 0 {
			set = append(set, strings.TrimSuffix(m.prefix, "."))
		}
	}
	for _, key := range set {
		if strings.HasPrefix(key, "pdp.") {
			return fmt.Errorf("%s: set, and pdp.identifier names no decision point for it to apply to", key)
		}
	}
	return nil
}

// checkApprovals pairs the provider with what it needs, refuses a mode no
// provider can serve, and keeps the hold journal out of a directory another
// writer owns (ADR-0016).
func (c *Config) checkApprovals() error {
	if err := c.checkApprovalBounds(); err != nil {
		return err
	}
	if c.Approvals.Provider != ProviderFile {
		// Under APPROVE every allowed material call is held, and a store
		// nothing outside this process can answer would hold every one of
		// them until it expired: a total denial wearing a pending state.
		if c.ModeName == "APPROVE" {
			return fmt.Errorf("approvals.provider: %s under APPROVE; nothing outside this process answers a memory-held request, so every held call would expire (ADR-0016)", c.Approvals.Provider)
		}
		for _, key := range []string{"approvals.dir", "approvals.hold_journal_dir"} {
			if c.wasSet(key) {
				return fmt.Errorf("%s: only the %s provider reads a directory, and the provider is %s", key, ProviderFile, c.Approvals.Provider)
			}
		}
		return nil
	}
	switch {
	case c.Approvals.Dir == "":
		return fmt.Errorf("approvals.dir: the %s provider keeps its records in a directory, and no directory is named", ProviderFile)
	case c.Approvals.HoldJournalDir == "":
		return fmt.Errorf("approvals.hold_journal_dir: the %s provider keeps a journal of its own holds, and no directory is named; without one a hold lost to a restart is never closed (ADR-0016)", ProviderFile)
	}
	return c.checkJournalDir()
}

// checkApprovalBounds refuses a bound that is not positive. A bound of zero
// would leave a store that takes no record, or a reconciliation that reads
// nothing and could still report itself done.
func (c *Config) checkApprovalBounds() error {
	for _, bound := range []struct {
		key string
		n   int
	}{
		{"approvals.max_records", c.Approvals.MaxRecords},
		{"approvals.max_record_bytes", c.Approvals.MaxRecordBytes},
		{"approvals.reconcile_max", c.Approvals.ReconcileMax},
		{"approvals.max_held_per_run", c.Approvals.MaxHeldPerRun},
	} {
		if bound.n <= 0 {
			return fmt.Errorf("%s: %d; the bound has to be positive", bound.key, bound.n)
		}
	}
	return nil
}

// checkJournalDir keeps the hold journal's directory out of the spool's,
// which the spool owns and locks, and out of the approvals directory, which
// an approver may write. The journal is as trusted as the evidence, so
// nobody but the plane writes it.
func (c *Config) checkJournalDir() error {
	journal := c.Resolve(c.Approvals.HoldJournalDir)
	for _, other := range []struct{ key, dir string }{
		{"evidence.dir", c.Resolve(c.Evidence.Dir)},
		{"approvals.dir", c.Resolve(c.Approvals.Dir)},
	} {
		overlap, err := sharesDir(journal, other.dir)
		if err != nil {
			return fmt.Errorf("approvals.hold_journal_dir: %w", err)
		}
		if overlap {
			return fmt.Errorf("approvals.hold_journal_dir: %q shares a path with %s %q; the journal is written by the plane alone (ADR-0016)",
				c.Approvals.HoldJournalDir, other.key, other.dir)
		}
	}
	return nil
}

// The bounds of pause.poll_interval. A pause bites up to one interval after
// it is written, so the ceiling keeps an emergency stop an emergency stop; the
// floor keeps the reader from spinning on the file.
const (
	minPausePoll = 100 * time.Millisecond
	maxPausePoll = time.Minute
)

// checkPause bounds the poll interval, refuses one set with no pause file to
// apply to, and keeps the file out of every directory a plane locks: the
// spool's, the approvals store's and the hold journal's, each locked while a
// plane runs, where a writer of the pause file, which locks the file's own
// directory, could never write (ADR-0019). The directories are compared by
// their paths and, where both exist, by identity, so a link or a spelling in
// another case that names a locked directory is refused too.
func (c *Config) checkPause() error {
	if c.Pause.File == "" {
		if c.wasSet("pause.poll_interval") {
			return fmt.Errorf("pause.poll_interval: set, and pause.file names no pause file for it to apply to")
		}
		return nil
	}
	if c.Pause.PollInterval < minPausePoll || c.Pause.PollInterval > maxPausePoll {
		return fmt.Errorf("pause.poll_interval: %v is outside %v to %v", c.Pause.PollInterval, minPausePoll, maxPausePoll)
	}
	dir := filepath.Dir(c.Resolve(c.Pause.File))
	for _, other := range []struct{ key, dir string }{
		{"evidence.dir", c.Evidence.Dir},
		{"approvals.dir", c.Approvals.Dir},
		{"approvals.hold_journal_dir", c.Approvals.HoldJournalDir},
	} {
		if other.dir == "" {
			continue
		}
		locked := c.Resolve(other.dir)
		within, err := insideDir(dir, locked)
		if err == nil && !within {
			within, err = underSameDir(dir, locked)
		}
		if err != nil {
			return fmt.Errorf("pause.file: %w", err)
		}
		if within {
			return fmt.Errorf("pause.file: %q sits in %s %q, which a running plane locks, so no pause could be written while it runs",
				c.Pause.File, other.key, other.dir)
		}
	}
	return nil
}

// checkEvidence pairs the fsync policy with its interval: a timer under the
// policy that has none, or no timer under the policy that needs one, is a
// loss window nobody chose.
func (c *Config) checkEvidence() error {
	switch {
	case c.Evidence.Fsync == FsyncInterval && c.Evidence.FsyncInterval <= 0:
		return fmt.Errorf("evidence.fsync_interval: the interval policy needs a positive interval, which is what a power loss may cost")
	case c.Evidence.Fsync == FsyncEveryRecord && c.Evidence.FsyncInterval != 0:
		return fmt.Errorf("evidence.fsync_interval: only the interval policy takes one")
	case c.Evidence.SegmentBytes > c.Evidence.MaxBytes:
		return fmt.Errorf("evidence.segment_bytes: %d is over evidence.max_bytes %d", c.Evidence.SegmentBytes, c.Evidence.MaxBytes)
	case c.Evidence.ClosingReserve > c.Evidence.MaxBytes:
		return fmt.Errorf("evidence.closing_reserve: %d is over evidence.max_bytes %d", c.Evidence.ClosingReserve, c.Evidence.MaxBytes)
	}
	return nil
}

// checkExport refuses an endpoint that is not a collector's URL.
func (c *Config) checkExport() error {
	if !httpURL(c.Export.Endpoint) {
		return notHTTP("export.endpoint", c.Export.Endpoint)
	}
	return nil
}

// httpURL reports whether value is an http or https URL with a host.
func httpURL(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Host != "" && (u.Scheme == "http" || u.Scheme == "https")
}

// notHTTP refuses a value of key that is not an http or https URL, quoting it
// only where ShowAddress would print it.
func notHTTP(key, value string) error {
	if shown := ShowAddress(value); shown != value {
		return fmt.Errorf("%s: %s, and it is not an http or https URL", key, shown)
	}
	return fmt.Errorf("%s: %s is not an http or https URL", key, quoteValue(value))
}

// checkShaping holds ADR-0013's rule that shaping only subtracts where the
// mode enforces: under OBSERVE and SHADOW a list is answered as the upstream
// serves it.
func (c *Config) checkShaping() error {
	if c.List.Shaping != "none" && (c.ModeName == ModeObserve || c.ModeName == ModeShadow) {
		return fmt.Errorf("list.shaping: %s under %s; shaping is none in a mode that does not enforce (ADR-0013)", c.List.Shaping, c.ModeName)
	}
	return nil
}

// checkTimeouts refuses a zero bound its client would not take, naming the
// key rather than the client's option; a negative one never loads. At zero a
// call has no bound of the adapter's own. upstream.list_timeout may be zero,
// which is the adapter's own bound.
func (c *Config) checkTimeouts() error {
	for _, bound := range []struct {
		key string
		d   time.Duration
	}{
		{"upstream.call_timeout", c.Upstream.CallTimeout},
		{"pdp.timeout", c.PDP.Timeout},
		{"export.timeout", c.Export.Timeout},
	} {
		if bound.d == 0 {
			return fmt.Errorf("%s: %v; the bound has to be positive", bound.key, bound.d)
		}
	}
	return nil
}

// wasSet reports whether the file or the environment set the key, as against
// the key standing at its default.
func (c *Config) wasSet(path string) bool {
	_, ok := c.source[path]
	return ok
}
