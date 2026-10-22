package main

import (
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"time"

	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policykey"
)

// The name renew reports itself under, and how the help spells what follows
// it. The form carries no value placeholders, since every flag names a file
// or a directory and with them the line is wider than a terminal.
const (
	renewName = "policy renew"
	renewForm = "--key --bundle --bundle-public-key --floor --out"
)

// renew's refusals of what it was given, beside those of the packages it
// calls.
const (
	// errNotABundle is a --bundle file that is not a serialized policy bundle.
	errNotABundle = "not a serialized policy bundle"
	// errFloorDirectory is an --out in a floor directory, a signer's or a
	// plane's, which holds nothing but its own files.
	errFloorDirectory = "the directory is a floor directory, which holds no statement"
	// errOneKey is a freshness key whose public half is the bundle's, or its
	// negation: the key that vouches for bundles would vouch for those it
	// signs itself.
	errOneKey = "--key and --bundle-public-key are one key pair; the freshness key is kept apart from the bundle key"
	// errRaceLost is an --out holding a newer statement for the bundle id
	// than the one the floor took, which no renew under this floor
	// directory's lock wrote.
	errRaceLost = "it holds a newer statement for the bundle id, which another renew wrote meanwhile; it was left as it is"
)

// floorMarker is the name internal/policystate gives a floor directory's
// marker, by which renew knows a floor directory before it opens one.
const floorMarker = "floors.meta"

// afterRaise runs between the raise and the write, under the floor
// directory's lock. A test starts a renew that runs meanwhile from it.
var afterRaise = func() {}

// maxPublicKeyFileBytes bounds the public key file: one line of base64 and a
// newline, with room to spare.
const maxPublicKeyFileBytes = 1 << 10

// publicLineBytes is the length of the public key line: standard base64 of
// 32 bytes.
const publicLineBytes = 44

// floorLockWait bounds how long a command waits for another holder of the
// floor directory's lock. A test shortens it.
var floorLockWait = 10 * time.Second

// renewPaths is what renew is told.
type renewPaths struct{ key, bundle, bundlePublicKey, floor, out string }

func renewFlags(command string, out io.Writer) (*flag.FlagSet, *renewPaths) {
	flags := commandFlags(command, out)
	var p renewPaths
	flags.StringVar(&p.key, "key", "", "the freshness private key file keygen wrote")
	flags.StringVar(&p.bundle, "bundle", "", "the authority's own copy of the bundle the statement vouches for")
	flags.StringVar(&p.bundlePublicKey, "bundle-public-key", "", "the public key file of the key that signed the bundle")
	flags.StringVar(&p.floor, "floor", "", "the signer's floor directory, made by policy state init --kind signer")
	flags.StringVar(&p.out, "out", "", "the statement file to write, replacing only a statement")
	return flags, &p
}

func renewFlagSet(command string, out io.Writer) *flag.FlagSet {
	flags, _ := renewFlags(command, out)
	return flags
}

// renewCommand checks its own arguments for key text, as keygenCommand does.
func renewCommand(args []string, stdout, stderr io.Writer) int {
	if err := policykey.CheckArguments(args); err != nil {
		return usageError(stderr, renewName, err.Error())
	}
	flags, p := renewFlags(renewName, io.Discard)
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 ||
		p.key == "" || p.bundle == "" || p.bundlePublicKey == "" || p.floor == "" || p.out == "" {
		return usageError(stderr, renewName, "takes --key, --bundle, --bundle-public-key, --floor and --out, and no argument")
	}
	return renew(*p, time.Now(), stdout, stderr)
}

// renew refuses in a fixed order and writes nothing on any refusal: the
// output path, the two keys, the bundle under its public key, the signer's
// floor. It raises the floor before it writes the statement, so no statement
// is ever written that the floor did not take, and holds the floor
// directory's lock until the statement is written, so two renews under one
// floor write in the order they raised. A write that fails after the raise
// leaves the floor at a statement nobody holds, which only refuses what it
// would have refused anyway, and a second run at the same or a later second
// is taken.
func renew(p renewPaths, now time.Time, stdout, stderr io.Writer) int {
	if err := policykey.CheckPlatform(); err != nil {
		return fail(stderr, renewName, err)
	}
	issuedAt := now.UTC().Truncate(time.Second)
	out := filepath.Clean(p.out)
	if err := checkStatementOut(out); err != nil {
		return fail(stderr, renewName, err)
	}
	s, err := signedStatement(p, issuedAt)
	if err != nil {
		return fail(stderr, renewName, err)
	}
	if err := raiseAndWrite(p.floor, out, s, issuedAt); err != nil {
		return fail(stderr, renewName, err)
	}
	lines := "bundle_id: " + oneLine(s.st.BundleID()) + "\n" +
		"serial: " + strconv.FormatInt(s.st.Serial(), 10) + "\n" +
		"digest: " + s.st.Digest() + "\n" +
		"issued_at: " + policy.FormatIssuedAt(s.st.IssuedAt()) + "\n"
	if _, err := io.WriteString(stdout, lines); err != nil {
		return fail(stderr, renewName, fmt.Errorf("writing to standard output: %w; the statement was written to %s", err, out))
	}
	return exitOK
}

// signed is a freshness statement renew signed, its envelope, and the public
// half of the key that signed it.
type signed struct {
	env      policy.StatementEnvelope
	st       policy.Statement
	freshPub ed25519.PublicKey
}

// signedStatement reads both keys and the bundle, refusing in renew's order,
// and signs a statement for the bundle at issuedAt. The private key is
// cleared before it returns.
func signedStatement(p renewPaths, issuedAt time.Time) (signed, error) {
	bundlePub, err := readPublicKey("--bundle-public-key", p.bundlePublicKey)
	if err != nil {
		return signed{}, err
	}
	key, err := policykey.ReadPrivate(p.key)
	if err != nil {
		return signed{}, fmt.Errorf("--key: %w", err)
	}
	defer clear(key)
	freshPub, _ := key.Public().(ed25519.PublicKey)
	if policykey.SameKey(freshPub, bundlePub) {
		return signed{}, errors.New(errOneKey)
	}
	snap, err := verifiedBundle(p.bundle, bundlePub, issuedAt)
	if err != nil {
		return signed{}, err
	}
	env, st, err := signStatement(snap, key, issuedAt)
	if err != nil {
		return signed{}, err
	}
	return signed{env: env, st: st, freshPub: freshPub}, nil
}

// raiseAndWrite raises the signer floor to s and, still holding the floor
// directory's lock, checks out for a newer statement and writes s there. An
// error after the write says the statement was written.
func raiseAndWrite(floor, out string, s signed, issuedAt time.Time) error {
	written := false
	err := raiseSignerFloor(floor, s.st, issuedAt, func() error {
		afterRaise()
		if err := checkNotNewer(out, s.st, s.freshPub); err != nil {
			return err
		}
		if err := policykey.WriteStatement(out, s.env); err != nil {
			return fmt.Errorf("--out %s: %w; the signer floor was raised to the statement", out, err)
		}
		written = true
		return nil
	})
	if err != nil && written {
		return fmt.Errorf("%w; the statement was written to %s", err, out)
	}
	return err
}
