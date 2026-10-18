package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	adaptermcp "github.com/guardana/control/adapters/mcp"
	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/holdjournal"
	"github.com/guardana/control/internal/pause"
)

// The verdict of one check. A check that could not run says so and is never a
// pass, and both verdicts below "ok" stop the run (AGENTS.md, invariant 4).
const (
	verdictOK      = "ok"
	verdictFail    = "fail"
	verdictUnknown = "unknown"
)

// doctorTimeout bounds the one check that talks to another process: reaching
// every upstream and reading its tools.
const doctorTimeout = 20 * time.Second

// doctor checks a configuration without serving anything and prints one line
// per check. It stops at the first check that is not "ok", because every later
// check reads what that one could not establish, and returns a non-zero status.
// A checked plane that does not close is a failure too, after every check.
func doctor(ctx context.Context, path string, stdout, stderr io.Writer) int {
	cfg, err := gatewayconfig.Load(path, os.Environ())
	if err != nil {
		report(stdout, verdictFail, "configuration", err.Error())
		return exitFail
	}
	report(stdout, verdictOK, "configuration", fmt.Sprintf("%s parses, %d key(s) set, the rest at their defaults", path, len(cfg.Sources())))
	printSettings(stdout, cfg)
	d := &examination{cfg: cfg, out: stdout}
	status := d.check(ctx, stderr)
	if err := d.close(); err != nil {
		found := "the checked plane did not close cleanly: " + err.Error()
		report(stdout, verdictFail, "close", found)
		writeLine(stderr, "doctor: close: "+oneLine(found))
		return exitFail
	}
	return status
}

// check runs every check in order until one is not "ok".
func (d *examination) check(ctx context.Context, stderr io.Writer) int {
	for _, check := range []func(context.Context) (string, string, string){
		d.mode, d.policy, d.evidence, d.approvals, d.pauseFile, d.runs, d.reaction, d.export, d.secrets, d.seams, d.upstreams, d.pdp,
	} {
		verdict, name, found := check(ctx)
		report(d.out, verdict, name, found)
		if verdict != verdictOK {
			writeLine(stderr, "doctor: "+name+": "+oneLine(found))
			return exitFail
		}
	}
	return exitOK
}

// examination is one run of the checks. The plane it builds is the one `run`
// would build, so whatever the pipeline, the adapter and the spool refuse is
// refused here too; it is closed again before doctor returns, and it binds no
// address.
type examination struct {
	cfg   *gatewayconfig.Config
	out   io.Writer
	plane *plane
	// pauseEntries are the entries the pause check read, whose tools the
	// upstreams check judges against the manifest.
	pauseEntries []pause.Entry
}

func (d *examination) close() error {
	if d.plane == nil {
		return nil
	}
	return d.plane.close()
}

// printSettings prints every bound and every choice the plane will run with,
// and where each came from, so the defaults are read rather than assumed. A
// header value is a credential and is never printed, and every other value
// passes through oneLine: an upstream's arguments may carry a certificate,
// and a value may carry a line break.
func printSettings(w io.Writer, cfg *gatewayconfig.Config) {
	sources := cfg.Sources()
	for _, s := range cfg.Settings() {
		source := "default"
		if where, ok := sources[s.Path]; ok {
			source = where
		}
		value := s.Value
		if s.Path == "upstream.list_timeout" && cfg.Upstream.ListTimeout == 0 {
			value = adaptermcp.DefaultListTimeout.String() + " (0s: adapter's own)"
		}
		writeLine(w, fmt.Sprintf("       %-28s %-24s (%s)", s.Path, oneLine(value), oneLine(source)))
	}
	printHeaders(w, gatewayconfig.HeadersPrefix, cfg.Export.Headers)
	printHeaders(w, gatewayconfig.PDPHeadersPrefix, cfg.PDP.Headers)
	for i, origin := range cfg.Listener.Origins {
		writeLine(w, fmt.Sprintf("       %-28s %s", fmt.Sprintf("listener.origins.%d", i), oneLine(origin)))
	}
	for i, name := range cfg.PDP.InformationalContext {
		writeLine(w, fmt.Sprintf("       %-28s %s", fmt.Sprintf("pdp.informational_context.%d", i), oneLine(name)))
	}
	for i, up := range cfg.Upstreams {
		printUpstream(w, i, up)
	}
	printTools(func(line string) { writeLine(w, line) }, cfg.Tools)
	for i, o := range cfg.Overrides {
		writeLine(w, fmt.Sprintf("       %-28s %s/%s is %s on %s from %s, returns %s %s, fingerprint %s",
			fmt.Sprintf("overrides.%d", i), oneLine(o.Upstream), oneLine(o.Tool), o.Effect, oneLine(o.ResourceType),
			oneLine(strconv.Quote(o.ResourceFrom)), orWord(o.ReturnsTrust, "untrusted"), orWord(o.ReturnsSensitivity, "unknown"),
			oneLine(o.Fingerprint)))
	}
}

// printHeaders names each header under prefix, in order, and never its value.
func printHeaders(w io.Writer, prefix string, headers map[string]string) {
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		writeLine(w, fmt.Sprintf("       %-28s %-24s (%s)", prefix+name, gatewayconfig.NotPrinted, "credential"))
	}
}

// mode reports what the configured mode needs of an adapter. A mode this build
// does not enforce is refused here, as the pipeline refuses it at start.
func (d *examination) mode(context.Context) (string, string, string) {
	mode, err := d.cfg.Mode()
	if err != nil {
		return verdictFail, "mode", err.Error()
	}
	needs, err := gateway.Requirements(mode)
	if err != nil {
		return verdictFail, "mode", err.Error()
	}
	found := fmt.Sprintf("%s needs %s from the adapter", d.cfg.ModeName, capabilityList(needs))
	if d.cfg.Listener.Kind != enforceKind {
		found += "; list shaping " + d.cfg.List.Shaping
	}
	return verdictOK, "mode", found
}

// capabilityList names the capabilities a mode needs or an adapter declares,
// in a fixed order. A mode that needs enforcement_cooperative takes an adapter
// that declares enforcement_inline too.
func capabilityList(c gateway.Capabilities) string {
	var out []string
	for _, pair := range []struct {
		name string
		set  bool
	}{
		{"observe_request", c.ObserveRequest}, {"observe_result", c.ObserveResult},
		{"enforcement_cooperative", c.Enforcement == gateway.EnforcementCooperative},
		{"enforcement_inline", c.Enforcement == gateway.EnforcementInline},
		{"authenticates", c.Authenticates}, {"bind_end_user", c.BindEndUser},
		{"see_delegation", c.SeeDelegation}, {"see_resource_ids", c.SeeResourceIDs},
	} {
		if pair.set {
			out = append(out, pair.name)
		}
	}
	if len(out) == 0 {
		return "nothing"
	}
	return strings.Join(out, ", ")
}

// evidence opens the spool where it will run: the directory has to exist, take
// the lock, take a file, and whatever is already in it has to check. Opening
// cuts a torn tail, as a start would, and the line names what that cut.
func (d *examination) evidence(context.Context) (string, string, string) {
	dir := d.cfg.Resolve(d.cfg.Evidence.Dir)
	sp, err := openSpool(d.cfg)
	if err != nil {
		return verdictFail, "evidence", err.Error()
	}
	stats, statsErr := sp.Stats()
	closeErr := sp.Close()
	switch {
	case statsErr != nil:
		return verdictUnknown, "evidence", "the spool opened and cannot answer its stats: " + statsErr.Error()
	case closeErr != nil:
		return verdictUnknown, "evidence", "the spool opened and did not close: " + closeErr.Error()
	}
	if err := writable(dir); err != nil {
		return verdictFail, "evidence", err.Error()
	}
	return verdictOK, "evidence", fmt.Sprintf("%s locks and is writable; %d segment(s), %d byte(s) unacknowledged, %d reserved, %d quarantined; "+
		"opening it cut a torn tail of %d byte(s); on_unwritable %s",
		filepath.ToSlash(dir), stats.Segments, stats.Unacknowledged, stats.Reserved, stats.QuarantinedRecords, stats.Truncated,
		d.cfg.Evidence.OnUnwritable)
}

// writable proves the directory takes a file and gives it back, because the
// lock alone does not: on unix it is taken on the directory, which a process
// with no permission to write in it can still open.
func writable(dir string) error {
	probe, err := os.CreateTemp(dir, ".writable-*")
	if err != nil {
		return fmt.Errorf("the directory is not writable: %w", err)
	}
	name := probe.Name()
	if err := probe.Close(); err != nil {
		return fmt.Errorf("the write probe did not close: %w", err)
	}
	if err := os.Remove(filepath.Clean(name)); err != nil {
		return fmt.Errorf("the write probe was left behind: %w", err)
	}
	return nil
}

// approvals says where a held request is kept and what a reconciliation would
// close, through handles that take no lock and create nothing. A command
// documented as serving nothing neither writes nor holds a lock an approver's
// probe would read as a plane waiting to consume their answer (ADR-0016).
//
// The records themselves are not read here. The one handle on that directory
// that takes no lock is the approver's, and it carries the method that answers
// an approval, which this binary must not hold; the plane's own handle takes
// the lock and makes an unused directory a store. So each directory is judged
// by its store's own judgement of the directory, which takes no lock and
// creates nothing, and its lock and its records are checked where they are
// used, at `run`.
func (d *examination) approvals(ctx context.Context) (string, string, string) {
	if d.cfg.Approvals.Provider != gatewayconfig.ProviderFile {
		return verdictOK, "approvals", fmt.Sprintf(
			"held requests are kept in process memory under the %s provider: nothing outside this process answers one, and a hold lost to a restart is never closed",
			d.cfg.Approvals.Provider)
	}
	for _, named := range []struct {
		key   string
		judge func(string) error
		dir   string
	}{
		{"approvals.dir", approvals.JudgeDirectory, d.cfg.Resolve(d.cfg.Approvals.Dir)},
		{"approvals.hold_journal_dir", holdjournal.JudgeDirectory, d.cfg.Resolve(d.cfg.Approvals.HoldJournalDir)},
	} {
		if err := named.judge(named.dir); err != nil {
			return verdictFail, "approvals", fmt.Sprintf("%s: %v", named.key, err)
		}
	}
	return d.holdJournal(ctx)
}

// holdJournal reports the holds a reconciliation would close, read through a
// handle that takes no lock and refuses every write. A directory no plane has
// made a journal yet is never read as an empty journal: it is reported as
// empty only where this check found it empty itself.
func (d *examination) holdJournal(ctx context.Context) (string, string, string) {
	dir, journalDir := d.cfg.Resolve(d.cfg.Approvals.Dir), d.cfg.Resolve(d.cfg.Approvals.HoldJournalDir)
	bounds := fmt.Sprintf("at most %d record(s) of %d byte(s), %d entry(ies) per pass",
		d.cfg.Approvals.MaxRecords, d.cfg.Approvals.MaxRecordBytes, d.cfg.Approvals.ReconcileMax)
	where := fmt.Sprintf("records in %s, holds in %s", filepath.ToSlash(dir), filepath.ToSlash(journalDir))
	journal, err := holdjournal.OpenReadOnly(journalDir,
		holdjournal.WithMaxEntries(d.cfg.Approvals.MaxRecords),
		holdjournal.WithMaxEntryBytes(d.cfg.Approvals.MaxRecordBytes))
	if err != nil {
		return unusedJournal(journalDir, where, bounds, err)
	}
	listing, listErr := journal.List(ctx, d.cfg.Approvals.ReconcileMax)
	if closeErr := journal.Close(); closeErr != nil {
		return verdictUnknown, "approvals", "the hold journal was read and did not close: " + closeErr.Error()
	}
	if listErr != nil {
		return verdictUnknown, "approvals", "the hold journal opened and cannot be read: " + listErr.Error()
	}
	found := fmt.Sprintf("%s; a restart would close %d lost hold(s), %d entry(ies) were left mid-close and %d will not decode; %s",
		where, len(listing.Held), listing.Interrupted, listing.Unreadable, bounds)
	if !listing.Complete {
		return verdictUnknown, "approvals", found + "; the pass did not read every entry, so those counts are a floor and not a total"
	}
	return verdictOK, "approvals", found
}

// unusedJournal reads a refusal of the journal directory against what is in
// it. An empty directory is one no plane has written a hold in, which is a
// pass with nothing to close; a directory holding anything else is refused as
// what it is, rather than reported as a journal with no holds.
func unusedJournal(dir, where, bounds string, refusal error) (string, string, string) {
	if !errors.Is(refusal, holdjournal.ErrNotAJournal) {
		return verdictFail, "approvals", fmt.Sprintf("approvals.hold_journal_dir: %v", refusal)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return verdictUnknown, "approvals", fmt.Sprintf("approvals.hold_journal_dir: %v", err)
	}
	if len(entries) > 0 {
		return verdictFail, "approvals", fmt.Sprintf("approvals.hold_journal_dir: %v", refusal)
	}
	return verdictOK, "approvals", fmt.Sprintf(
		"%s; no plane has written a hold here yet, so there is none to close; %s", where, bounds)
}

// export reads the endpoint as a URL and says where records will go. It sends
// nothing: a collector that is down must not stop a gateway from starting, so
// its reachability is not a check this makes.
func (d *examination) export(context.Context) (string, string, string) {
	u, err := url.Parse(d.cfg.Export.Endpoint)
	if err != nil || u.Host == "" {
		return verdictFail, "export", fmt.Sprintf("%q is not a URL", d.cfg.Export.Endpoint)
	}
	return verdictOK, "export", fmt.Sprintf("OTLP/HTTP JSON logs to %s://%s%s, %d header(s), at most %d record(s) per request, %d in flight",
		u.Scheme, u.Host, u.EscapedPath(), len(d.cfg.Export.Headers), d.cfg.Export.MaxBatch, d.cfg.Export.InFlight)
}

// seams builds every seam `run` builds but the durable approval directories:
// no address is bound, no upstream is connected, and no directory is locked or
// created. It is where the pipeline's own refusals are made, the adapter's
// declared capabilities against the mode among them.
func (d *examination) seams(context.Context) (string, string, string) {
	p, err := build(d.cfg, slog.New(slog.DiscardHandler), time.Now(), roleInspect, "")
	if err != nil {
		return verdictFail, "seams", err.Error()
	}
	d.plane = p
	return verdictOK, "seams", fmt.Sprintf(
		"the %s adapter declares %s, which covers what %s needs; at most %d held and %d open, an approval lasts %s and a retry is asked for after %s",
		p.seam().Name(), capabilityList(p.seam().Capabilities()), d.cfg.ModeName,
		d.cfg.Approvals.MaxHeld, d.cfg.Approvals.MaxOpen, d.cfg.Approvals.TTL, d.cfg.Approvals.RetryAfter)
}

// upstreams connects every upstream through the plane the previous check built,
// reads its tools into the manifest and says which of them the operator's
// overrides classify. An unclassified tool is blocked in every mode but
// OBSERVE, so outside OBSERVE it is not a pass. An enforce_api plane has no
// upstream; there it checks the socket's directory and lock file as run's
// Listen does.
func (d *examination) upstreams(ctx context.Context) (string, string, string) {
	if d.plane == nil {
		return verdictUnknown, "upstreams", "the plane was not built, so nothing connected"
	}
	if d.plane.enforce != nil {
		if err := d.plane.enforce.CheckSocketDir(); err != nil {
			return verdictFail, "upstreams", err.Error()
		}
		return verdictOK, "upstreams", fmt.Sprintf("an %s plane calls no upstream; %d tool(s) are classified by name, "+
			"each decision handed to a cooperating client; the socket's directory is this user's alone", enforceKind, len(d.cfg.Tools))
	}
	ctx, cancel := context.WithTimeout(ctx, doctorTimeout)
	defer cancel()
	if err := d.plane.startUpstreams(ctx); err != nil {
		return verdictUnknown, "upstreams", "not every upstream answered: " + err.Error()
	}
	entries := d.plane.adapter.Entries()
	unclassified, withheld := 0, 0
	for _, e := range entries {
		if e.Classified {
			continue
		}
		unclassified++
		if why, ok := e.Withheld(); ok {
			// The name and the definition may hold the very value the scan found.
			withheld++
			writeLine(d.out, fmt.Sprintf("       %s: a tool definition is withheld; %s", oneLine(e.Upstream), oneLine(why)))
			continue
		}
		writeLine(d.out, fmt.Sprintf("       %s/%s is unclassified; its definition fingerprints as %s",
			oneLine(e.Upstream), oneLine(e.Tool.Name), oneLine(e.Fingerprint)))
	}
	found := fmt.Sprintf("%d upstream(s) answered, %d tool(s) listed, %d classified, %d unclassified",
		len(d.cfg.Upstreams), len(entries), len(entries)-unclassified, unclassified)
	if withheld > 0 {
		found += fmt.Sprintf(", %d withheld", withheld)
	}
	if d.cfg.Pause.File != "" {
		found += fmt.Sprintf("; %d pause entry(ies) name a tool its upstream does not list", d.strayTools(entries))
	}
	if unclassified > 0 && d.cfg.ModeName != "OBSERVE" {
		return verdictUnknown, "upstreams", found + "; outside OBSERVE a call to an unclassified tool is blocked with ACTION_UNCLASSIFIED"
	}
	return verdictOK, "upstreams", found
}

// report prints one check's line. What the check found passes through
// oneLine, since it names settings and what files hold.
func report(w io.Writer, verdict, name, found string) {
	writeLine(w, fmt.Sprintf("%-7s %-13s %s", verdict, name, oneLine(found)))
}
