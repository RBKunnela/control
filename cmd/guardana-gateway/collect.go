package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/guardana/control/adapters/otel"
	"github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/loopback"
	"github.com/guardana/control/internal/trailfile"
)

// logsPath is where OTLP/HTTP sends logs, and the one path collect answers.
const logsPath = "/v1/logs"

// The collector's HTTP bounds. A request is one batch the exporter holds
// until it is answered, and an answer waits on the file's sync.
const (
	collectReadHeaderTimeout = 10 * time.Second
	collectReadTimeout       = time.Minute
	collectIdleTimeout       = 2 * time.Minute
	collectShutdown          = 10 * time.Second
)

// The collector's byte bounds when not told: a segment is sealed at
// defaultSegmentBytes, and appends are refused once the segments not pruned
// hold defaultMaxBytes.
const (
	defaultSegmentBytes int64 = 64 << 20
	defaultMaxBytes     int64 = 1 << 30
)

const collectForm = "--listen <addr>|unix:///<path> --dir <dir> --tenant <id> --project <id> --credential-file <file> " +
	"[--segment-bytes <n>] [--max-bytes <n>]"

// collectorConfig is what a collector keeps and whom it takes it from.
type collectorConfig struct {
	dir, tenant, project   string
	cred                   otel.Credential
	segmentBytes, maxBytes int64
}

func declareCollect(flags *flag.FlagSet) commandFunc {
	listen := flags.String("listen", "", "the loopback address to listen on, host:port, where port 0 takes a free one; "+
		"or unix:///<path>, a socket created there that a plane reaches with export.collector_uid set to this account")
	dir := flags.String("dir", "", "the directory of trail segments to append what arrives to, created when absent")
	tenant := flags.String("tenant", "", "the tenant the trail is bound to; an event of another is refused")
	project := flags.String("project", "", "the project the trail is bound to; an event of another is refused")
	credFile := flags.String("credential-file", "", "the file holding the credential every request carries as "+
		"Authorization: Bearer <credential>; mode 0600 or narrower, of this account")
	segmentBytes := flags.Int64("segment-bytes", defaultSegmentBytes, "the bytes a segment holds before it is sealed")
	maxBytes := flags.Int64("max-bytes", defaultMaxBytes, "the bytes the segments not pruned may hold; past them "+
		"every request is answered 503 until an operator prunes, and nothing is pruned automatically")
	return func(ctx context.Context, args []string, stdout, stderr io.Writer) int {
		for _, f := range []struct{ value, name, says string }{
			{*listen, "listen", "the loopback address or the unix socket to listen on"},
			{*dir, "dir", "the directory of trail segments to append to"},
			{*tenant, "tenant", "the tenant the trail is bound to"},
			{*project, "project", "the project the trail is bound to"},
			{*credFile, "credential-file", "the file holding the credential every request carries"},
		} {
			if f.value == "" {
				writeLine(stderr, flags.Name()+": --"+f.name+" names "+f.says)
				return exitUsage
			}
		}
		if len(args) > 0 {
			writeLine(stderr, flags.Name()+": unexpected argument "+oneLine(args[0]))
			return exitUsage
		}
		if err := checkBounds(*segmentBytes, *maxBytes); err != nil {
			writeLine(stderr, flags.Name()+": "+err.Error())
			return exitUsage
		}
		cred, err := readCredential(*credFile)
		if err != nil {
			return fail(stderr, "collect", fmt.Errorf("--credential-file %w", err))
		}
		return collect(ctx, *listen, collectorConfig{dir: *dir, tenant: *tenant, project: *project, cred: cred,
			segmentBytes: *segmentBytes, maxBytes: *maxBytes}, stdout, stderr)
	}
}

// checkBounds refuses a segment bound below the largest request a plane
// sends, so no one request goes alone into a segment past it and leaves a
// full log with nothing sealed to prune, and a log bound below twice it.
func checkBounds(segmentBytes, maxBytes int64) error {
	switch {
	case segmentBytes < otel.MaxRequestBytes:
		return fmt.Errorf("--segment-bytes is at least %d, the largest request a plane sends", otel.MaxRequestBytes)
	case maxBytes/2 < segmentBytes:
		return fmt.Errorf("--max-bytes is at least twice --segment-bytes, so a full log holds a sealed segment to prune")
	}
	return nil
}

// readCredential reads the credential a collector requires from a file of
// this account that the group and others cannot read. One line ending is
// taken off its end, as an editor or echo leaves one.
func readCredential(path string) (otel.Credential, error) {
	raw, err := files.ReadOwned(path, otel.MaxCredentialBytes+2, 0o077, os.Geteuid())
	if err != nil {
		return otel.Credential{}, fmt.Errorf("%s: %w", strconv.Quote(path), err)
	}
	token := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	cred, err := otel.NewCredential(token)
	if err != nil {
		return otel.Credential{}, fmt.Errorf("%s: %w", strconv.Quote(path), err)
	}
	return cred, nil
}

// collect receives OTLP/HTTP logs on a loopback address or a unix socket and
// appends the evidence each one carries to the trail segments in cfg.dir,
// until ctx ends. A plane reaches a plaintext collector only under
// export.allow_plaintext and only on a loopback IP literal, so nothing else
// is listened on; the credential keeps any other local account from writing
// to the trail or filling its bound.
func collect(ctx context.Context, listen string, cfg collectorConfig, stdout, stderr io.Writer) int {
	ln, err := collectListener(ctx, listen)
	if err != nil {
		return fail(stderr, "collect", err)
	}
	c, err := startCollector(ln, cfg, stderr)
	if err != nil {
		return fail(stderr, "collect", fmt.Errorf("--dir %w", err))
	}
	if _, err := fmt.Fprintf(stdout, "collect: listening on %s\ncollect: appending to %s for tenant %s, project %s\n"+
		"collect: a plane sends here with export.endpoint: %s, %s and "+
		"export.headers.Authorization: Bearer <the credential>\n",
		c.url, oneLine(cfg.dir), shown(cfg.tenant), shown(cfg.project), c.url, c.planeSetting); err != nil {
		return fail(stderr, "collect", errors.Join(fmt.Errorf("writing to standard output: %w", err), c.stop()))
	}
	select {
	case err := <-c.served:
		return fail(stderr, "collect", errors.Join(err, c.trail.Close()))
	case <-ctx.Done():
	}
	if err := c.stop(); err != nil {
		return fail(stderr, "collect", err)
	}
	return exitOK
}

// collector is a collect serving on a listener it was handed: the server,
// the trail file it appends to, the URL a plane sends to, and what Serve
// returned once it stops.
type collector struct {
	srv   *http.Server
	trail *trailfile.Log
	url   string
	// planeSetting is the key beside export.endpoint a plane needs to send
	// here.
	planeSetting string
	served       chan error
}

// startCollector opens the trail segments in cfg.dir and serves ln until
// stop. It takes ln over: a refusal closes it, and names the directory.
func startCollector(ln net.Listener, cfg collectorConfig, stderr io.Writer) (*collector, error) {
	w, err := trailfile.OpenLog(trailfile.LogConfig{Dir: cfg.dir, Tenant: cfg.tenant, Project: cfg.project,
		SegmentBytes: cfg.segmentBytes, MaxBytes: cfg.maxBytes})
	if err != nil {
		return nil, errors.Join(fmt.Errorf("%s: %w", strconv.Quote(cfg.dir), err), ln.Close())
	}
	log := slog.New(printableLog(slog.NewTextHandler(stderr, nil)))
	receiver, err := otel.NewReceiver(w, log, cfg.cred)
	if err != nil {
		return nil, errors.Join(err, w.Close(), ln.Close())
	}
	mux := http.NewServeMux()
	mux.Handle(logsPath, receiver)
	c := &collector{
		srv: &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: collectReadHeaderTimeout,
			ReadTimeout:       collectReadTimeout,
			IdleTimeout:       collectIdleTimeout,
			ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
		},
		trail:        w,
		url:          "http://" + ln.Addr().String() + logsPath,
		planeSetting: "export.allow_plaintext: true",
		served:       make(chan error, 1),
	}
	if ln.Addr().Network() == "unix" {
		c.url, c.planeSetting = "unix://"+ln.Addr().String(), "export.collector_uid: "+strconv.Itoa(os.Geteuid())
	}
	go func() { c.served <- c.srv.Serve(ln) }()
	return c, nil
}

// stop waits for the requests in flight, each of which answers only after
// the trail holds its records or refuses them, and closes the trail.
func (c *collector) stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), collectShutdown)
	defer cancel()
	err := c.srv.Shutdown(ctx)
	if err != nil {
		err = fmt.Errorf("stopping: %w", err)
	}
	return errors.Join(err, c.trail.Close())
}

// loopbackOnly refuses a --listen that is not host:port with a loopback IP
// literal as its host.
func loopbackOnly(addr string) error {
	if err := loopback.Check(addr); err != nil {
		return fmt.Errorf("--listen %w; collect listens on the loopback or a unix socket only", err)
	}
	return nil
}
