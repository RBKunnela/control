package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/gatewayconfig"
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
// A checked plane that does not close is a failure too, after every check, and
// so is a report stdout did not take whole: a pass nobody could read is none.
func doctor(ctx context.Context, path string, stdout, stderr io.Writer) int {
	out := &reportWriter{w: stdout}
	status := examine(ctx, path, out, stderr)
	if out.err != nil {
		writeLine(stderr, "doctor: writing the report: "+oneLine(out.err.Error()))
		return exitFail
	}
	return status
}

// reportWriter keeps the first error a write of the report met and refuses
// every later write with it.
type reportWriter struct {
	w   io.Writer
	err error
}

func (r *reportWriter) Write(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	n, err := r.w.Write(p)
	if err == nil && n < len(p) {
		err = io.ErrShortWrite
	}
	r.err = err
	return n, err
}

func examine(ctx context.Context, path string, stdout, stderr io.Writer) int {
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
	if d.cfg.Listener.Kind != gatewayconfig.ListenerEnforceAPI {
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

// report prints one check's line. What the check found passes through
// oneLine, since it names settings and what files hold.
func report(w io.Writer, verdict, name, found string) {
	writeLine(w, fmt.Sprintf("%-7s %-13s %s", verdict, name, oneLine(found)))
}
