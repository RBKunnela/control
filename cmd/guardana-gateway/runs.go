package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/guardana/control/internal/adapterkit"
	"github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/runs"
)

// maxRunTokenBytes bounds the run token file: a token is a run id, a dot and
// a secret, well under it, and a final newline.
const maxRunTokenBytes = 256

// runsDir serves the pipeline and the listener from a runs directory
// (ADR-0034), translating its types; the directory imports no gateway.
type runsDir struct{ plane *runs.Plane }

var _ gateway.Runs = runsDir{}

func (d runsDir) Resolve(ctx context.Context, token string, who gateway.RunIdentity, now time.Time) (gateway.OpenedRun, error) {
	run, err := d.plane.Resolve(ctx, token, runs.Identity(who), now)
	if err != nil {
		var refusal *runs.Refusal
		if errors.As(err, &refusal) {
			return gateway.OpenedRun{}, &gateway.RunRefusal{Cause: gateway.RunCause(refusal.Cause), Err: err}
		}
		return gateway.OpenedRun{}, err
	}
	return gateway.OpenedRun{ID: run.ID, Root: run.Root, Who: gateway.RunIdentity(run.Who), Expires: run.Expires}, nil
}

func (d runsDir) State(ctx context.Context, root string) (gateway.RunState, error) {
	s, err := d.plane.State(ctx, root)
	if err != nil {
		return gateway.RunState{}, err
	}
	return toGateway(s), nil
}

func (d runsDir) Raise(ctx context.Context, root string, join func(gateway.RunState) gateway.RunState) error {
	return d.plane.Raise(ctx, root, func(s runs.State) runs.State {
		raised := join(toGateway(s))
		return runs.State{Untrusted: !raised.Trusted, MaxRead: raised.MaxRead}
	})
}

func toGateway(s runs.State) gateway.RunState {
	return gateway.RunState{Trusted: !s.Untrusted, MaxRead: s.MaxRead}
}

// openRuns opens the runs directory a serving plane is configured with, or
// returns nil where none is. A stdio plane reads its one token from
// tokenPath, and a token that does not resolve for the listener's identity
// refuses the start; an HTTP plane reads a token from each request, so a
// token file there is refused.
func openRuns(cfg *gatewayconfig.Config, tokenPath string) (*runs.Plane, string, error) {
	stdio := cfg.Listener.Kind == gatewayconfig.ListenerStdio
	switch {
	case cfg.Runs.Dir == "" && tokenPath != "":
		return nil, "", fmt.Errorf("--run-token-file: runs.dir is not set, so this plane serves local runs and reads no token")
	case cfg.Runs.Dir == "":
		return nil, "", nil
	case !stdio && tokenPath != "":
		return nil, "", fmt.Errorf("--run-token-file: an HTTP listener reads each request's token from its %s header", adapterkit.RunTokenHeader)
	case stdio && tokenPath == "":
		return nil, "", fmt.Errorf("--run-token-file: a stdio plane with runs.dir serves the one run whose token this file holds, and none is named")
	}
	plane, err := runs.OpenPlane(cfg.Resolve(cfg.Runs.Dir))
	if err != nil {
		return nil, "", fmt.Errorf("runs.dir: %w", err)
	}
	if !stdio {
		return plane, "", nil
	}
	token, err := readRunToken(tokenPath)
	if err == nil {
		_, err = runsDir{plane}.Resolve(context.Background(), token, listenerRunIdentity(cfg), time.Now())
	}
	if err != nil {
		return nil, "", errors.Join(fmt.Errorf("--run-token-file: %w", err), plane.Close())
	}
	return plane, token, nil
}

// readRunToken reads a token file the way a key file is read (ADR-0018): a
// regular file this user owns that nobody else may read or write. One final
// newline is dropped; anything else around the token is refused. No refusal
// repeats the path, since a token pasted where the path belongs would be
// printed with it.
func readRunToken(path string) (string, error) {
	raw, err := files.ReadOwned(path, maxRunTokenBytes, 0o077, os.Geteuid())
	if err != nil {
		var pathErr *fs.PathError
		if errors.As(err, &pathErr) {
			return "", fmt.Errorf("%s: %w", pathErr.Op, pathErr.Err)
		}
		return "", err
	}
	token := strings.TrimSuffix(string(raw), "\n")
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", fmt.Errorf("the token file holds no token on one line")
	}
	return token, nil
}

// listenerRunIdentity is who a run of this listener is for, as the adapter
// resolves it without an authenticator.
func listenerRunIdentity(cfg *gatewayconfig.Config) gateway.RunIdentity {
	return gateway.RunIdentity{
		TenantID:      listenerTenant(cfg),
		PrincipalType: cfg.Listener.PrincipalType,
		PrincipalID:   cfg.Listener.PrincipalID,
		AgentID:       cfg.Listener.AgentID,
	}
}

// runs reports where the plane's runs come from. A plane takes no lock on a
// runs directory and writes no record there, so opening it here, as run
// does, changes nothing in it.
func (d *examination) runs(context.Context) (string, string, string) {
	if d.cfg.Runs.Dir == "" {
		return verdictOK, "runs", "local: one run per principal and agent, kept in memory, so a new process starts clean (ADR-0021)"
	}
	path := filepath.ToSlash(d.cfg.Resolve(d.cfg.Runs.Dir))
	plane, err := runs.OpenPlane(d.cfg.Resolve(d.cfg.Runs.Dir))
	if err != nil {
		return verdictFail, "runs", fmt.Sprintf("runs.dir: %v", err)
	}
	if err := plane.Close(); err != nil {
		return verdictFail, "runs", fmt.Sprintf("runs.dir: %v", err)
	}
	how := "each HTTP request presents its token in the " + adapterkit.RunTokenHeader + " header"
	if d.cfg.Listener.Kind == gatewayconfig.ListenerStdio {
		how = "run takes the one run's token from --run-token-file"
	}
	return verdictOK, "runs", fmt.Sprintf("opened in %s: every call needs a run the operator opened there; %s (ADR-0034)", path, how)
}
