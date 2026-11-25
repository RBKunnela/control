package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"time"

	ondisk "github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/policy/match"
	"github.com/guardana/control/internal/policy/rules"
	"github.com/guardana/control/internal/policykey"
)

// The names these commands report themselves under, and how the help spells
// what follows them. Flags come first because the flag package stops reading
// them at the first argument that is not one.
const (
	keygenName = "policy keygen"
	signName   = "policy sign"
	keygenForm = "--out <dir>"
	signForm   = "--key <file> --out <file> <document>"
)

func keygenFlags(command string, out io.Writer) (*flag.FlagSet, *string) {
	flags := commandFlags(command, out)
	dir := flags.String("out", "", "the directory to create, which must not exist")
	return flags, dir
}

func keygenFlagSet(command string, out io.Writer) *flag.FlagSet {
	flags, _ := keygenFlags(command, out)
	return flags
}

// signPaths is what sign is told besides the document.
type signPaths struct{ key, out string }

func signFlags(command string, out io.Writer) (*flag.FlagSet, *signPaths) {
	flags := commandFlags(command, out)
	var p signPaths
	flags.StringVar(&p.key, "key", "", "the private key file keygen wrote")
	flags.StringVar(&p.out, "out", "", "the bundle file to write, replacing what is there")
	return flags, &p
}

func signFlagSet(command string, out io.Writer) *flag.FlagSet {
	flags, _ := signFlags(command, out)
	return flags
}

// keygenCommand checks its own arguments for key text, as the dispatcher
// does, so an entry point that skips the dispatcher cannot skip the check.
func keygenCommand(args []string, stdout, stderr io.Writer) int {
	if err := policykey.CheckArguments(args); err != nil {
		return usageError(stderr, keygenName, err.Error())
	}
	flags, dir := keygenFlags(keygenName, io.Discard)
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *dir == "" {
		return usageError(stderr, keygenName, "takes --out naming the directory to create, and no argument")
	}
	return keygen(*dir, rand.Reader, stdout, stderr)
}

// keygen draws a key from random, writes both halves into the directory it
// creates, and prints the two lines the configuration's policy group takes.
// The private key reaches no output: it goes to the file and nowhere else.
func keygen(dir string, random io.Reader, stdout, stderr io.Writer) int {
	if err := policykey.CheckPlatform(); err != nil {
		return fail(stderr, keygenName, err)
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(random, seed); err != nil {
		return fail(stderr, keygenName, fmt.Errorf("drawing a key: %w", err))
	}
	key := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	defer clear(key)
	if err := policykey.WriteKeyPair(dir, key); err != nil {
		return fail(stderr, keygenName, err)
	}
	pub, _ := key.Public().(ed25519.PublicKey)
	if _, err := io.WriteString(stdout, policykey.ConfigLines(pub)); err != nil {
		return fail(stderr, keygenName, fmt.Errorf("writing to standard output: %w; the key pair was written to %s", err, dir))
	}
	return exitOK
}

// signCommand checks its own arguments for key text, as keygenCommand does.
func signCommand(args []string, stdout, stderr io.Writer) int {
	if err := policykey.CheckArguments(args); err != nil {
		return usageError(stderr, signName, err.Error())
	}
	flags, p := signFlags(signName, io.Discard)
	if err := flags.Parse(args); err != nil || flags.NArg() != 1 || p.key == "" || p.out == "" {
		return usageError(stderr, signName, "takes --key and --out, then one document, with every flag before it")
	}
	return sign(p.key, p.out, flags.Arg(0), time.Now(), stdout, stderr)
}

// sign refuses in a fixed order and writes nothing on any refusal: the output
// path, then the document, then the key, then the signed bundle as the loader
// reads it. A document that does not parse, fails the obligation parameter
// check or does not compile is refused before the key file is opened. No
// refusal prints the --key value.
func sign(keyPath, out, document string, now time.Time, stdout, stderr io.Writer) int {
	if err := policykey.CheckPlatform(); err != nil {
		return fail(stderr, signName, err)
	}
	// The kernel resolves "link/.." through the link and the write cleans by
	// text, so the path is cleaned once and every check sees the file written.
	out = filepath.Clean(out)
	judged, err := checkOut(out, keyPath, document)
	if err != nil {
		return fail(stderr, signName, err)
	}
	raw, err := ondisk.ReadRegular(document, maxReadBytes, 0)
	if err != nil {
		return fail(stderr, signName, fmt.Errorf("document %s: %w", document, err))
	}
	doc, _, err := rules.Parse(raw)
	if err != nil {
		return fail(stderr, signName, err)
	}
	if err := rules.CheckObligations(doc); err != nil {
		return fail(stderr, signName, err)
	}
	if _, err := match.Compile(doc); err != nil {
		return fail(stderr, signName, err)
	}
	key, err := policykey.ReadPrivate(keyPath)
	if err != nil {
		return fail(stderr, signName, fmt.Errorf("--key: %w", err))
	}
	defer clear(key)
	b, snap, err := policykey.SignBundle(raw, key, now)
	if err != nil {
		return fail(stderr, signName, err)
	}
	beforeOutReplaced(out)
	ctx, cancel := context.WithTimeout(context.Background(), outLockWait)
	defer cancel()
	if err := policykey.WriteBundleOver(ctx, out, b, judged); err != nil {
		return fail(stderr, signName, fmt.Errorf("--out %s: %w", out, err))
	}
	lines := "bundle_id: " + oneLine(snap.Ref().GetBundleId()) + "\n" +
		"version: " + oneLine(snap.Ref().GetVersion()) + "\n" +
		"serial: " + strconv.FormatInt(snap.Serial(), 10) + "\n" +
		"digest: " + snap.Ref().GetDigest() + "\n" +
		"key_id: " + b.GetKeyId() + "\n" +
		"out: " + oneLine(out) + "\n"
	if _, err := io.WriteString(stdout, lines); err != nil {
		return fail(stderr, signName, fmt.Errorf("writing to standard output: %w; the bundle was written to %s", err, out))
	}
	return exitOK
}

// beforeOutReplaced, when a test sets it, runs once a command judged its
// output for the last time, just before the new file takes the name.
var beforeOutReplaced = func(string) {}

// outLockWait bounds how long policy sign, route sign and supervise --view
// wait for another holder's lock of the output file they replace. A test
// shortens it.
var outLockWait = 10 * time.Second

// checkOut refuses an output path whose directory is missing, one that would
// replace the key or the document, by whatever spelling or link reaches the
// same file, and one that exists and is not a regular file holding a policy
// bundle: sign replaces an earlier bundle and nothing else. It returns the
// entry at out as it judged it, nil where none stands, for the write to
// replace that entry and no other.
func checkOut(out, keyPath, document string) (fs.FileInfo, error) {
	info, err := os.Stat(out)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := ondisk.CheckDir(filepath.Dir(filepath.Clean(out)), 0); err != nil {
			return nil, fmt.Errorf("--out %s: %w", out, err)
		}
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("--out %s: %w", out, err)
	}
	for _, other := range []struct{ name, path string }{{"--key", keyPath}, {"the document", document}} {
		if o, err := os.Stat(other.path); err == nil && os.SameFile(info, o) {
			return nil, fmt.Errorf("--out %s is the same file as %s, which the bundle would replace", out, other.name)
		}
	}
	named, err := os.Lstat(out)
	if err != nil {
		return nil, fmt.Errorf("--out %s: %w", out, err)
	}
	var raw []byte
	if named.Mode()&fs.ModeSymlink != 0 {
		raw, err = ondisk.ReadRegular(out, maxReadBytes, 0)
	} else {
		raw, err = ondisk.ReadRegularOf(out, maxReadBytes, named)
	}
	if err != nil {
		return nil, fmt.Errorf("--out %s: %w", out, err)
	}
	if !policykey.IsBundle(raw) {
		return nil, fmt.Errorf("--out %s exists and is not a policy bundle, and sign replaces nothing else", out)
	}
	return named, nil
}
