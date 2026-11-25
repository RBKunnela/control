package policykey

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/protobuf/proto"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
)

// keyPairSteps are the file system steps writeKeyPair takes, apart so a test
// can stand in for a race won between them or for a step that fails.
type keyPairSteps struct {
	mkdir    func(dir string, perm fs.FileMode) error
	openRoot func(dir string) (*os.Root, error)
	create   func(root *os.Root, name string, body []byte, perm fs.FileMode) error
	chmod    func(d *os.File, perm fs.FileMode) error
}

// osSteps are the steps WriteKeyPair takes. A test starts from this value and
// replaces one step, so the others it drives are the ones keygen runs.
var osSteps = keyPairSteps{mkdir: os.Mkdir, openRoot: os.OpenRoot, create: files.CreateNoReplaceIn, chmod: (*os.File).Chmod}

// WriteKeyPair creates dir with mode 0700 and writes key's two halves into it:
// PrivateFile (0600) and PublicFile (0644, the public line and a newline).
// Creating the directory is what refuses an existing path, a file, a directory
// or a link alike, so nothing is ever written beside or over another key.
// Everything after it goes through a handle to the directory at the path
// once it was opened and judged, and a path that stops naming that directory
// is refused. An empty directory of this account swapped in before that open
// cannot be told from the one created, and is taken. When any later step
// fails, what was written is removed.
func WriteKeyPair(dir string, key ed25519.PrivateKey) error {
	return writeKeyPair(dir, key, osSteps)
}

func writeKeyPair(dir string, key ed25519.PrivateKey, steps keyPairSteps) error {
	if err := CheckPlatform(); err != nil {
		return err
	}
	private, err := MarshalPrivate(key)
	if err != nil {
		return err
	}
	defer clear(private)
	pub, _ := key.Public().(ed25519.PublicKey)
	dir = filepath.Clean(dir)
	if err := steps.mkdir(dir, 0o700); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s: %w", dir, ErrKeyPairExists)
		}
		return err
	}
	made, err := takeMade(dir, steps.chmod)
	if err != nil {
		return err
	}
	root, err := steps.openRoot(dir)
	if err != nil {
		return errors.Join(err, unmake(nil, dir, made, nil))
	}
	written, err := writeHalves(root, dir, made, steps, private, pub)
	if err == nil {
		err = files.SyncDir(filepath.Dir(dir))
	}
	if err != nil {
		err = errors.Join(err, unmake(root, dir, made, written))
	}
	return errors.Join(err, root.Close())
}

// writeHalves writes the two files through root, between two checks that dir
// still names the directory made, and returns the names it wrote.
func writeHalves(root *os.Root, dir string, made fs.FileInfo, steps keyPairSteps, private []byte, pub ed25519.PublicKey) ([]string, error) {
	if err := stillMade(root, dir, made); err != nil {
		return nil, err
	}
	var written []string
	for _, f := range []struct {
		name string
		body []byte
		perm fs.FileMode
	}{
		{PrivateFile, private, 0o600},
		{PublicFile, []byte(FormatPublic(pub) + "\n"), 0o644},
	} {
		if err := steps.create(root, f.name, f.body, f.perm); err != nil {
			return written, err
		}
		written = append(written, f.name)
	}
	return written, stillMade(root, dir, made)
}

// takeMade opens the directory just made at dir, holds that it is the one
// made, and sets its mode through the descriptor: Mkdir's mode passed through
// the umask, which could leave the owner unable to write into it. The open
// neither follows a link nor waits on a named pipe. What it returns is that
// directory, which every later check compares against. A directory refused
// with ErrKeyDirMoved is left as it is; any other failure, a failed open
// included, removes the empty directory at dir, which after a swap can be one
// this run did not make.
func takeMade(dir string, chmod func(*os.File, fs.FileMode) error) (fs.FileInfo, error) {
	d, err := files.OpenDir(dir)
	if err != nil {
		return nil, errors.Join(err, removeUntaken(dir))
	}
	made, err := holdMade(d, dir)
	if err == nil {
		err = chmod(d, 0o700)
	}
	switch err = errors.Join(err, d.Close()); {
	case err == nil:
		return made, nil
	case errors.Is(err, ErrKeyDirMoved):
		return nil, err
	}
	return nil, errors.Join(err, removeUntaken(dir))
}

// holdMade refuses, with ErrKeyDirMoved, unless the directory d holds is the
// one this run made: dir names it and not a link, the effective user owns it,
// and it is empty. A directory put at the path after Mkdir that another
// account owns or that holds entries is neither written into nor changed; an
// empty one this account owns cannot be told from the one made, and is taken.
func holdMade(d *os.File, dir string) (fs.FileInfo, error) {
	made, err := d.Stat()
	if err != nil {
		return nil, err
	}
	if err := isAt(made, dir); err != nil {
		return nil, err
	}
	if err := files.CheckOwnedBy(made, effectiveUID()); err != nil {
		return nil, fmt.Errorf("%s: %w (%w)", dir, ErrKeyDirMoved, err)
	}
	switch _, err := d.Readdirnames(1); {
	case err == nil:
		return nil, fmt.Errorf("%s holds entries keygen did not make: %w", dir, ErrKeyDirMoved)
	case !errors.Is(err, io.EOF):
		return nil, err
	}
	return made, nil
}

// removeUntaken removes the directory Mkdir made when it cannot be taken, as
// under a umask that leaves it no permission bit. rmdir needs no permission
// on the directory itself, removes only an empty one, which a directory nobody
// could write into is, and never follows a link, so no mode has to be given
// back by a path a link could redirect. A link, a file or a pipe put at the
// path is left there; an empty directory put there instead of the one made is
// removed like it.
func removeUntaken(dir string) error {
	at, err := os.Lstat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return err
	case !at.IsDir():
		return fmt.Errorf("%s: %w", dir, ErrKeyDirMoved)
	}
	return os.Remove(dir)
}

// stillMade refuses unless root holds made and dir still names it.
func stillMade(root *os.Root, dir string, made fs.FileInfo) error {
	held, err := root.Stat(".")
	if err != nil {
		return err
	}
	if !os.SameFile(held, made) {
		return fmt.Errorf("%s: %w", dir, ErrKeyDirMoved)
	}
	return isAt(made, dir)
}

// isAt refuses unless dir is, right now, the directory made and not a link.
func isAt(made fs.FileInfo, dir string) error {
	at, err := os.Lstat(dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err != nil || !at.IsDir() || !os.SameFile(at, made) {
		return fmt.Errorf("%s: %w", dir, ErrKeyDirMoved)
	}
	return nil
}

// unmake removes the files writeKeyPair wrote, through root, and then the
// directory at dir when that is still the one made. root may be nil when
// nothing was written.
func unmake(root *os.Root, dir string, made fs.FileInfo, written []string) error {
	var errs []error
	for _, name := range written {
		errs = append(errs, root.Remove(name))
	}
	if isAt(made, dir) == nil {
		errs = append(errs, os.Remove(dir))
	}
	return errors.Join(errs...)
}

// SignBundle signs document with key under the key's derived id, and loads
// the result under the key's own public half at now. A bundle Load refuses is
// never returned. A plane can still refuse the one returned, since it also
// pins a bundle id, a key and a staleness budget.
func SignBundle(document []byte, key ed25519.PrivateKey, now time.Time) (*controlv1.PolicyBundle, *policy.Snapshot, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("policykey: a private key of %d bytes, want %d", len(key), ed25519.PrivateKeySize)
	}
	pub, _ := key.Public().(ed25519.PublicKey)
	id := KeyID(pub)
	b, err := policy.Sign(document, key, id)
	if err != nil {
		return nil, nil, err
	}
	snap, err := policy.Load(b, bundle.Keyring{id: pub}, now)
	if err != nil {
		return nil, nil, err
	}
	return b, snap, nil
}

// IsBundle reports whether raw is a serialized policy bundle: it decodes, its
// signature_alg is the one value, and it holds canonical bytes. It checks no
// signature; it tells a bundle from another file, a key among them.
func IsBundle(raw []byte) bool {
	var b controlv1.PolicyBundle
	if err := proto.Unmarshal(raw, &b); err != nil {
		return false
	}
	return b.GetSignatureAlg() == bundle.SignatureAlg && len(b.GetCanonical()) != 0
}

// WriteBundle writes b to path, replacing what is there, with mode 0644: a
// bundle is public, and a plane running as another account has to read it.
// The bytes are deterministic for one build of the protobuf runtime.
func WriteBundle(path string, b *controlv1.PolicyBundle) error {
	raw, err := marshalBundle(b)
	if err != nil {
		return err
	}
	path = filepath.Clean(path)
	return files.Replace(filepath.Dir(path), filepath.Base(path), raw, 0o644)
}

// WriteBundleOver is WriteBundle that replaces only the entry judged
// describes, as files.ReplaceJudgedIn does, and with a nil judged writes only
// where nothing stands at path. It waits for a lock of the file another
// process holds until ctx ends.
func WriteBundleOver(ctx context.Context, path string, b *controlv1.PolicyBundle, judged fs.FileInfo) error {
	raw, err := marshalBundle(b)
	if err != nil {
		return err
	}
	path = filepath.Clean(path)
	return files.ReplaceJudged(ctx, filepath.Dir(path), filepath.Base(path), raw, 0o644, judged)
}

func marshalBundle(b *controlv1.PolicyBundle) ([]byte, error) {
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("policykey: serializing the bundle: %w", err)
	}
	return raw, nil
}
