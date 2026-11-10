package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/guardana/control/adapters/otel"
	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/policykey"
)

// devDrain bounds how long a stopping dev plane waits for its exporter to
// ship what the spool holds to the collector.
const devDrain = 5 * time.Second

// What a dev state directory holds, each named from the directory.
const (
	stateApprovals = "approvals"
	stateHolds     = "holds"
	stateSpool     = "spool"
	stateTrail     = "trail"
	stateBundle    = "policy.bundle"
	stateStatement = "policy.statement"
	stateFloors    = "floors"
	statePause     = "pause/pause.json"
	statePauseFlr  = "pausefloor"
	stateSettings  = "settings.txt"
)

// A dev plane's collector socket is in a directory of its own under the
// system's temporary directory, apart from the state, whose path grows with
// --state and a scenario's name while a socket's path is bounded.
const (
	collectDirPrefix = "gd"
	collectSocket    = "c.sock"
)

// devState is a directory dev created for one plane, holding everything
// that plane writes.
type devState struct{ dir string }

func (s devState) path(name string) string { return filepath.Join(s.dir, name) }

// makeState creates dir, which must not exist, or a new directory under the
// system's temporary directory when dir is empty, with the directories the
// plane locks inside it, each mode 0700.
func makeState(dir string) (devState, error) {
	var err error
	if dir == "" {
		dir, err = os.MkdirTemp("", brand.Gateway+"-dev-")
	} else {
		err = os.Mkdir(dir, 0o700)
	}
	if err != nil {
		return devState{}, fmt.Errorf("--state: %w", err)
	}
	// Every path dev prints or hands to the approver is absolute, so none
	// can be read as a flag or against another working directory.
	if dir, err = filepath.Abs(dir); err != nil {
		return devState{}, err
	}
	st := devState{dir: dir}
	for _, sub := range []string{stateApprovals, stateHolds, stateSpool} {
		if err := os.Mkdir(st.path(sub), 0o700); err != nil {
			return devState{}, err
		}
	}
	return st, nil
}

// refuseState refuses a --state that exists. makeState refuses it too; this
// runs before anything is created or bound.
func refuseState(dir string) error {
	if dir == "" {
		return nil
	}
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("--state %s: it exists, and dev lays out a new directory", dir)
	}
	return nil
}

// devPlane is one plane dev laid out and serves in its own process: the
// state, the collector and the plane on listeners dev bound itself.
type devPlane struct {
	state devState
	cfg   *gatewayconfig.Config
	plane *plane
	coll  *collector
	keyID string
	// signer renews the statement; it holds the only key dev keeps. renewal
	// says how often.
	signer  *devSigner
	renewal string
	// done is closed once the plane's run returned ran; stop ends the run.
	done chan struct{}
	ran  error
	stop context.CancelFunc
	// silent is the decision point's listener, which nothing ever accepts on,
	// or nil.
	silent net.Listener
	// collectDir holds the collector's socket, and goes when the plane does.
	collectDir string
}

// devInputs is what every plane of one dev run is made from.
type devInputs struct {
	config   string
	document []byte
	control  sibling
	silent   bool
}

// newKey draws the signing key, which is never written.
func newKey() (ed25519.PrivateKey, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	return key, err
}

// checkDemo refuses the demo's configuration before anything is created or
// bound, holding it to the layer a plane under dir would get. With no dir it
// stands in a path nothing creates, named at random so that no other account
// can plant a link there ahead of dev. The collector socket stands in a path
// as long as the longest os.MkdirTemp draws for it, so its bound is held as
// dev's own socket will be.
func checkDemo(in devInputs, dir string) error {
	bundleKey, err := newKey()
	if err != nil {
		return err
	}
	defer clear(bundleKey)
	freshnessKey, err := newKey()
	if err != nil {
		return err
	}
	defer clear(freshnessKey)
	if dir == "" {
		dir = filepath.Join(os.TempDir(), brand.Gateway+"-dev-"+rand.Text())
	}
	const unbound = "127.0.0.1:0"
	silent := ""
	if in.silent {
		silent = unbound
	}
	keys := devKeys{bundle: publicHalf(bundleKey), freshness: publicHalf(freshnessKey)}
	socket := filepath.Join(os.TempDir(), collectDirPrefix+strings.Repeat("0", maxTempSuffix), collectSocket)
	_, err = resolveDemo(in.config, newLayer(devState{dir: dir}, keys, unbound, unbound, socket, newToken(), silent))
	return err
}

// maxTempSuffix is the longest name os.MkdirTemp puts after its pattern, a
// 32-bit number in decimal.
const maxTempSuffix = 10

// newToken is a credential drawn for one dev plane and its collector, held
// in this process only.
func newToken() string { return rand.Text() + rand.Text() }

// publicHalf is key's public half.
func publicHalf(key ed25519.PrivateKey) ed25519.PublicKey {
	pub, _ := key.Public().(ed25519.PublicKey)
	return pub
}

// checkSignable refuses a document the signer refuses, by signing it once
// under a key drawn for that and dropped, before anything is created.
func checkSignable(document []byte) error {
	key, err := newKey()
	if err != nil {
		return err
	}
	defer clear(key)
	_, _, err = policykey.SignBundle(document, key, time.Now())
	return err
}

// startDevPlane lays out a new state under dir, signs the document into it
// under a key that lives only here, binds the collector's socket and, on the
// loopback, the agents, the health answers and a silent decision
// point when asked, and starts the collector and then the plane the way run
// starts one. The silent listener is never accepted on: the kernel completes
// a connection into its backlog, the question is written and no answer ever
// comes, so the plane's ask ends on its own deadline. Whatever it made is
// released when it refuses; the directory stays, as the record of what was
// tried.
func startDevPlane(ctx context.Context, in devInputs, dir string, log io.Writer) (_ *devPlane, err error) {
	st, err := makeState(dir)
	if err != nil {
		return nil, err
	}
	d := &devPlane{state: st}
	bundleKey, err := d.signBundle(in.document)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			d.signer.halt()
			err = errors.Join(err, os.RemoveAll(d.collectDir))
		}
	}()
	if err := d.layOut(ctx, in.control); err != nil {
		return nil, err
	}
	var listeners []net.Listener
	if d.collectDir, listeners, err = bindDevListeners(ctx, in.silent); err != nil {
		return nil, err
	}
	addr := func(i int) string { return listeners[i].Addr().String() }
	keys := devKeys{bundle: bundleKey, freshness: d.signer.public()}
	token := newToken()
	cred, err := otel.NewCredential(token)
	if err != nil {
		return nil, errors.Join(err, closeAll(listeners))
	}
	if err = d.configure(ctx, in, newLayer(st, keys, addr(1), addr(2), addr(0), token, d.takeSilent(listeners))); err != nil {
		return nil, errors.Join(err, closeAll(listeners))
	}
	coll := collectorConfig{dir: st.path(stateTrail), tenant: d.cfg.TenantID, project: d.cfg.ProjectID, cred: cred,
		segmentBytes: defaultSegmentBytes, maxBytes: defaultMaxBytes}
	if d.coll, err = startCollector(listeners[0], coll, log); err != nil {
		return nil, errors.Join(err, closeAll(listeners[1:]))
	}
	if d.plane, err = startDevSigned(ctx, d.cfg, log, devSignedStart(st)); err != nil {
		return nil, errors.Join(silentAdvice(err, in.silent), closeAll(listeners[1:]), d.coll.stop())
	}
	d.signer.start(ctx, log)
	d.plane.settle(ctx, log)
	runCtx, stop := context.WithCancel(ctx)
	d.done, d.stop = make(chan struct{}), stop
	handed := map[string]net.Listener{addr(1): listeners[1], addr(2): listeners[2]}
	go func() {
		defer close(d.done)
		d.ran = d.plane.run(runCtx, log, func(a string) (net.Listener, error) {
			ln, ok := handed[a]
			if !ok {
				return nil, fmt.Errorf("dev bound nothing at %s", a)
			}
			delete(handed, a)
			return ln, nil
		}, devDrain)
		// A run that stopped before it took every listener leaves the rest
		// to be closed here.
		for _, ln := range handed {
			_ = ln.Close()
		}
	}()
	return d, nil
}

// bindDevListeners makes the collector's socket directory and binds, first,
// the collector's socket in it, then the loopback listeners the plane takes.
// On a refusal it leaves nothing bound and no directory behind.
func bindDevListeners(ctx context.Context, silent bool) (dir string, _ []net.Listener, err error) {
	if dir, err = os.MkdirTemp("", collectDirPrefix); err != nil {
		return "", nil, fmt.Errorf("making the collector's socket directory: %w", err)
	}
	socket, err := listenCollectSocket(filepath.Join(dir, collectSocket))
	if err != nil {
		return "", nil, errors.Join(fmt.Errorf("binding the collector's socket: %w", err), os.RemoveAll(dir))
	}
	listeners, err := bindLoopback(ctx, devListeners(silent)-1)
	if err != nil {
		return "", nil, errors.Join(err, socket.Close(), os.RemoveAll(dir))
	}
	return dir, append([]net.Listener{socket}, listeners...), nil
}

// configure resolves the demo's configuration under the layer, lays out the
// signed authority for its tenant and project, sets how often the statement
// is renewed for it, and writes the settings it resolved.
func (d *devPlane) configure(ctx context.Context, in devInputs, l devLayer) error {
	cfg, err := resolveDemo(in.config, l)
	if err != nil {
		return err
	}
	if err := d.layOutTrust(ctx, in.control, cfg.TenantID, cfg.ProjectID); err != nil {
		return err
	}
	if d.renewal, err = d.signer.schedule(cfg); err != nil {
		return err
	}
	d.cfg = cfg
	return writeSettings(d.state.path(stateSettings), cfg)
}

// devListeners is how many listeners a dev plane takes: the collector's
// socket, the agents', the health answers' and, when asked, a silent decision
// point's.
func devListeners(silent bool) int {
	if silent {
		return 4
	}
	return 3
}

// takeSilent keeps the silent decision point's listener, the fourth, and
// returns its address, or "" when there is none.
func (d *devPlane) takeSilent(listeners []net.Listener) string {
	if len(listeners) < 4 {
		return ""
	}
	d.silent = listeners[3]
	return d.silent.Addr().String()
}

// signBundle signs the document into the state's bundle file under a key
// drawn for it and cleared once it signed, and draws the freshness key apart
// from it. It returns the bundle key's public half, which the plane pins.
func (d *devPlane) signBundle(document []byte) (ed25519.PublicKey, error) {
	key, err := newKey()
	if err != nil {
		return nil, err
	}
	defer clear(key)
	b, snap, err := policykey.SignBundle(document, key, time.Now())
	if err != nil {
		return nil, fmt.Errorf("--policy: %w", err)
	}
	d.keyID = b.GetKeyId()
	if err := policykey.WriteBundle(d.state.path(stateBundle), b); err != nil {
		return nil, err
	}
	if d.signer, err = newDevSigner(b, snap.Serial(), snap.MaxStale(), d.state.path(stateStatement)); err != nil {
		return nil, err
	}
	return publicHalf(key), nil
}

// layOut makes, through the approver's binary, the one that holds the code
// that makes it, the plane's floor directory, and writes the first statement
// before the plane starts. The pause file is signed, so it is made with the
// signed authority, in layOutTrust.
func (d *devPlane) layOut(ctx context.Context, control sibling) error {
	floors := d.state.path(stateFloors)
	if _, err := control.run(ctx, "policy", "state", "init", "--kind", "plane", "--bundle-id", d.signer.id, floors); err != nil {
		return fmt.Errorf("creating the floor directory: %w", err)
	}
	if err := d.signer.renew(time.Now()); err != nil {
		return fmt.Errorf("writing the first freshness statement: %w", err)
	}
	return nil
}

// bindLoopback binds n ports the system picks on 127.0.0.1, so no port is
// chosen and then bound by someone else first.
func bindLoopback(ctx context.Context, n int) ([]net.Listener, error) {
	var out []net.Listener
	for range n {
		ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", "127.0.0.1:0")
		if err != nil {
			return nil, errors.Join(err, closeAll(out))
		}
		out = append(out, ln)
	}
	return out, nil
}

func closeAll(listeners []net.Listener) error {
	var errs []error
	for _, ln := range listeners {
		errs = append(errs, ln.Close())
	}
	return errors.Join(errs...)
}

// halt stops the statement's renewals, then the plane's listeners, and gives
// its exporter devDrain to ship what the spool holds, then stops the
// collector, releases the plane and closes the silent decision point. It
// returns what is left unacknowledged in the spool, which the trail file may
// lack, and whether a part had stopped with an error; a closing record lost
// after the plane's run returned is one.
func (d *devPlane) halt() (left int64, failed error) {
	d.signer.halt()
	d.stop()
	<-d.done
	failed = d.ran
	st, err := d.plane.spool.Stats()
	left = st.Unacknowledged
	var silent error
	if d.silent != nil {
		silent = d.silent.Close()
	}
	collector := d.coll.stop()
	closed := d.plane.close()
	return left, errors.Join(failed, err, collector, os.RemoveAll(d.collectDir), closed, d.plane.lostClosings(), silent)
}

// silentAdvice says what to change when the plane refuses the decision point
// dev --decision-point=silent set: under the flag pdp.identifier is dev's, so
// unsetting it, which the refusal suggests, is not the operator's to do.
func silentAdvice(err error, silent bool) error {
	if !silent || !errors.Is(err, gateway.ErrDecisionPointUnused) {
		return err
	}
	return fmt.Errorf("%w; under --decision-point=silent dev sets pdp.identifier itself, so drop the flag for a policy that asks no decision point", err)
}
