package runs

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/guardana/control/internal/files"
)

const (
	markerFile   = "runs.meta"
	recordSuffix = ".run.json"
	recordTemp   = ".run.tmp"
	stateSuffix  = ".state.json"
	stateTemp    = ".state.tmp"
	lockSuffix   = ".lock"

	idPrefix  = "run-"
	idHexLen  = 32
	secretLen = 32
	// secretTextLen is secretLen bytes in base64url without padding.
	secretTextLen = 43
)

// suffixes is every name a run id may carry. Nothing else under the
// directory is the directory's.
var suffixes = [...]string{recordSuffix, recordTemp, stateSuffix, stateTemp, lockSuffix}

type kind uint8

const (
	kindForeign kind = iota
	kindMarker
	kindRecord
	kindOther
)

// classify says what a name under the directory is, and for a record the run
// id it holds. A temporary name of internal/files is what a crash while the
// marker was created leaves, and nothing reads it.
func classify(name string) (kind, string) {
	if name == markerFile {
		return kindMarker, ""
	}
	if files.IsTemp(name) {
		return kindOther, ""
	}
	for _, s := range suffixes {
		if id, ok := strings.CutSuffix(name, s); ok && checkRunID(id) == nil {
			if s == recordSuffix {
				return kindRecord, id
			}
			return kindOther, id
		}
	}
	return kindForeign, ""
}

// CheckRunID refuses, with ErrRunID, an id that is not "run-" and 32
// lower-case hex digits, the one form a run is named by.
func CheckRunID(id string) error { return checkRunID(id) }

// checkRunID holds an id to "run-" and 32 lower-case hex digits. The id names
// files, so the rule leaves no separator, dot or case variant to pass.
func checkRunID(id string) error {
	hexPart, ok := strings.CutPrefix(id, idPrefix)
	if !ok || len(hexPart) != idHexLen {
		return fmt.Errorf("%w: %q", ErrRunID, clip(id))
	}
	if !lowerHex(hexPart) {
		return fmt.Errorf("%w: %q", ErrRunID, clip(id))
	}
	return nil
}

func lowerHex(s string) bool {
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func newRunID() (string, error) {
	var b [idHexLen / 2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return idPrefix + hex.EncodeToString(b[:]), nil
}

// newSecret returns a fresh secret as it travels in a token, and the hash a
// record keeps of it.
func newSecret() (text, hash string, err error) {
	var b [secretLen]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), hashSecret(b[:]), nil
}

// hashSecret is what a record keeps of a secret: the hex SHA-256 of its 32
// bytes, never the bytes.
func hashSecret(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// parseToken splits a token into its run id and its secret's bytes. The
// strict decoder refuses padding and stray bits, so one secret has exactly
// one spelling.
func parseToken(token string) (string, []byte, error) {
	id, secret, ok := strings.Cut(token, ".")
	if !ok {
		return "", nil, fmt.Errorf("%w: no separator", ErrMalformed)
	}
	if checkRunID(id) != nil {
		// The refusal names no part of the token: a secret pasted where the id
		// belongs would otherwise be repeated.
		return "", nil, fmt.Errorf("%w: no run id before the separator", ErrMalformed)
	}
	if len(secret) != secretTextLen {
		return "", nil, fmt.Errorf("%w: a secret of %d characters", ErrMalformed, len(secret))
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(secret)
	if err != nil || len(b) != secretLen {
		return "", nil, fmt.Errorf("%w: the secret is not base64url", ErrMalformed)
	}
	return id, b, nil
}

// secretMatches compares in constant time, so how long a refusal takes says
// nothing about how much of a guess was right.
func secretMatches(secret []byte, recorded string) bool {
	return subtle.ConstantTimeCompare([]byte(hashSecret(secret)), []byte(recorded)) == 1
}

// maxClip bounds how much of a refused value an error repeats.
const maxClip = 64

// clip shortens a value a refusal repeats and replaces control characters, so
// an error printed to a terminal cannot be steered by what it quotes.
func clip(s string) string {
	if len(s) > maxClip {
		s = s[:maxClip] + "..."
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}
