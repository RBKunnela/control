package observe

import (
	"errors"
	"fmt"
	"strings"
)

// The record schemas this package writes. A record is SchemaVersion02
// exactly when it carries a member SchemaVersion does not have, which only an
// import report naming runs in doubt does.
const (
	SchemaVersion   = "0.1"
	SchemaVersion02 = "0.2"
)

// minors is the table of 0.N record versions this package reads. An alpha
// minor promises nothing about the next one, so a minor outside it is refused
// rather than read as the nearest known one.
var minors = map[string]bool{"1": true, "2": true}

// descriptorMinors is the table of 0.N source descriptor versions.
var descriptorMinors = map[string]bool{"1": true}

// maxVersionBytes bounds how much of a refused version a refusal quotes.
const maxVersionBytes = 16

// ErrVersion reports a schema_version this package does not read.
var ErrVersion = errors.New("observe: unsupported schema_version")

// CheckVersion accepts exactly the record versions in the table and refuses
// an absent, malformed or other-major one.
func CheckVersion(v string) error { return checkVersion(v, minors) }

func checkVersion(v string, minors map[string]bool) error {
	if v == "" {
		return fmt.Errorf("%w: absent", ErrVersion)
	}
	major, minor, ok := strings.Cut(v, ".")
	if !ok || !versionNumber(major) || !versionNumber(minor) {
		return fmt.Errorf("%w: malformed %s", ErrVersion, quoted(v, maxVersionBytes))
	}
	if major != "0" {
		return fmt.Errorf("%w: major %s, this reader takes 0", ErrVersion, quoted(major, maxVersionBytes))
	}
	if !minors[minor] {
		return fmt.Errorf("%w: minor %s is not in this reader's table", ErrVersion, quoted(v, maxVersionBytes))
	}
	return nil
}

// versionNumber reports a decimal number without a sign or a leading zero.
func versionNumber(s string) bool {
	if s == "" || len(s) > 9 || (len(s) > 1 && s[0] == '0') {
		return false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
