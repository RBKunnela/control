package runs

import (
	"fmt"
	"slices"
	"time"

	"github.com/guardana/control/pkg/contract"
)

// The bounds a run's lifetime is held to, at opening and on every read of its
// record.
const (
	MinTTL = time.Minute
	MaxTTL = 720 * time.Hour
)

// MaxIdentityBytes bounds each field of an identity, which keeps a record
// under the bound every read holds a file to.
const MaxIdentityBytes = 256

// Identity is who a run is for: a project, a tenant, a principal and an
// agent.
type Identity struct {
	ProjectID, TenantID, PrincipalType, PrincipalID, AgentID string
}

// check refuses an identity with an empty field, one over MaxIdentityBytes, or
// one no contract identifier may hold.
func (w Identity) check() error {
	for _, f := range [...]struct{ name, v string }{
		{"project_id", w.ProjectID},
		{"tenant_id", w.TenantID},
		{"principal_type", w.PrincipalType},
		{"principal_id", w.PrincipalID},
		{"agent_id", w.AgentID},
	} {
		if f.v == "" || len(f.v) > MaxIdentityBytes {
			return fmt.Errorf("%w: %s is %d bytes, bound %d", ErrIdentity, f.name, len(f.v), MaxIdentityBytes)
		}
		if err := contract.CheckIdentifier(f.v); err != nil {
			return fmt.Errorf("%w: %s: %w", ErrIdentity, f.name, err)
		}
	}
	return nil
}

// Record is one run as the directory keeps it. It holds the hash of the
// token's secret and never the secret.
type Record struct {
	ID string
	// Who is the identity a token for the run must be presented under.
	Who Identity
	// Root is the run whose state this run shares: its own id for a run
	// opened with no parent, else its parent's root.
	Root string
	// Parent is the run this one was opened under, or empty.
	Parent    string
	OpenedAt  time.Time
	ExpiresAt time.Time
	// ClosedAt is zero while the run is open.
	ClosedAt time.Time
	// SecretSHA256 is the hex SHA-256 of the secret's 32 bytes.
	SecretSHA256 string
}

// Closed reports whether the operator closed the run.
func (r Record) Closed() bool { return !r.ClosedAt.IsZero() }

// check holds a record to what this package writes, on the way out and on the
// way back in: a writer of the directory picks its own bytes, so a bound
// held only at opening would be no bound.
func (r Record) check() error {
	if err := r.checkLineage(); err != nil {
		return err
	}
	if err := r.Who.check(); err != nil {
		return err
	}
	if err := r.checkTimes(); err != nil {
		return err
	}
	if len(r.SecretSHA256) != 64 || !lowerHex(r.SecretSHA256) {
		return fmt.Errorf("%w: secret_sha256 is not 64 lower-case hex digits", ErrMalformed)
	}
	return nil
}

// checkLineage holds the run's id, root and parent to one another.
func (r Record) checkLineage() error {
	if err := checkRunID(r.ID); err != nil {
		return err
	}
	if err := checkRunID(r.Root); err != nil {
		return fmt.Errorf("root: %w", err)
	}
	switch {
	case r.Parent == "" && r.Root != r.ID:
		return fmt.Errorf("%w: a run with no parent is its own root", ErrMalformed)
	case r.Parent != "" && (r.Parent == r.ID || r.Root == r.ID):
		return fmt.Errorf("%w: a run with a parent is neither its parent nor its root", ErrMalformed)
	}
	if r.Parent != "" {
		if err := checkRunID(r.Parent); err != nil {
			return fmt.Errorf("parent: %w", err)
		}
	}
	return nil
}

func (r Record) checkTimes() error {
	if r.OpenedAt.IsZero() {
		return ErrZeroTime
	}
	if err := checkTTL(r.ExpiresAt.Sub(r.OpenedAt)); err != nil {
		return err
	}
	// RFC 3339 spells a year in four digits, so a time outside them would be
	// written and then refused on every read.
	for _, t := range [...]time.Time{r.OpenedAt, r.ExpiresAt, r.ClosedAt} {
		if y := t.UTC().Year(); !t.IsZero() && (y < 1 || y > 9999) {
			return fmt.Errorf("%w: a time a file cannot hold", ErrMalformed)
		}
	}
	return nil
}

func checkTTL(ttl time.Duration) error {
	if ttl < MinTTL || ttl > MaxTTL {
		return fmt.Errorf("%w: %s, bounds %s and %s", ErrTTL, ttl, MinTTL, MaxTTL)
	}
	return nil
}

// recordFile is a record's encoding, in the order a file holds its keys.
type recordFile struct {
	SchemaVersion string `json:"schema_version"`
	RunID         string `json:"run_id"`
	ProjectID     string `json:"project_id"`
	TenantID      string `json:"tenant_id"`
	PrincipalType string `json:"principal_type"`
	PrincipalID   string `json:"principal_id"`
	AgentID       string `json:"agent_id"`
	Root          string `json:"root"`
	Parent        string `json:"parent"`
	OpenedAt      string `json:"opened_at"`
	ExpiresAt     string `json:"expires_at"`
	ClosedAt      string `json:"closed_at"`
	SecretSHA256  string `json:"secret_sha256"`
}

var recordKeys = []string{
	"schema_version", "run_id", "project_id", "tenant_id", "principal_type", "principal_id", "agent_id",
	"root", "parent", "opened_at", "expires_at", "closed_at", "secret_sha256",
}

// recordKeysV1 is what a record of major 1 holds: no project.
var recordKeysV1 = slices.DeleteFunc(slices.Clone(recordKeys), func(k string) bool { return k == "project_id" })

// encodeRecord is a method of the operator's handle and of nothing else, so
// a binary that never names Admin holds no code that writes a record.
func (*Admin) encodeRecord(r Record) ([]byte, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	closed := ""
	if r.Closed() {
		closed = formatTime(r.ClosedAt)
	}
	return encode(recordFile{
		SchemaVersion: RecordVersion,
		RunID:         r.ID,
		ProjectID:     r.Who.ProjectID,
		TenantID:      r.Who.TenantID,
		PrincipalType: r.Who.PrincipalType,
		PrincipalID:   r.Who.PrincipalID,
		AgentID:       r.Who.AgentID,
		Root:          r.Root,
		Parent:        r.Parent,
		OpenedAt:      formatTime(r.OpenedAt),
		ExpiresAt:     formatTime(r.ExpiresAt),
		ClosedAt:      closed,
		SecretSHA256:  r.SecretSHA256,
	})
}

// refuseWithoutProject refuses a record holding the keys of major 1, which
// lack project_id, by its version where that is refused, so the operator
// reads why rather than that a field is missing. It is nil for any other
// file.
func refuseWithoutProject(raw []byte) error {
	old, unlike := fields(raw, recordKeysV1)
	if unlike != nil {
		return nil //nolint:nilerr // a file without major 1's keys is the full decoder's to judge
	}
	v, err := stringField(old, "schema_version")
	if err != nil {
		return err
	}
	if err := checkRecordVersion(v); err != nil {
		return err
	}
	return fmt.Errorf("%w: %q", ErrMissingField, "project_id")
}

// decodeRecord reads one record and holds it to check.
func decodeRecord(raw []byte) (Record, error) {
	if err := refuseWithoutProject(raw); err != nil {
		return Record{}, err
	}
	f, err := fields(raw, recordKeys)
	if err != nil {
		return Record{}, err
	}
	s := make(map[string]string, len(recordKeys))
	for _, k := range recordKeys {
		if s[k], err = stringField(f, k); err != nil {
			return Record{}, err
		}
	}
	if err := checkRecordVersion(s["schema_version"]); err != nil {
		return Record{}, err
	}
	r := Record{
		ID:           s["run_id"],
		Who:          Identity{ProjectID: s["project_id"], TenantID: s["tenant_id"], PrincipalType: s["principal_type"], PrincipalID: s["principal_id"], AgentID: s["agent_id"]},
		Root:         s["root"],
		Parent:       s["parent"],
		SecretSHA256: s["secret_sha256"],
	}
	if r.OpenedAt, err = parseTime("opened_at", s["opened_at"]); err != nil {
		return Record{}, err
	}
	if r.ExpiresAt, err = parseTime("expires_at", s["expires_at"]); err != nil {
		return Record{}, err
	}
	if s["closed_at"] != "" {
		if r.ClosedAt, err = parseTime("closed_at", s["closed_at"]); err != nil {
			return Record{}, err
		}
	}
	if err := r.check(); err != nil {
		return Record{}, err
	}
	return r, nil
}

// readRecord reads the record of id and holds it to its name.
func (d *dir) readRecord(id string) (Record, error) {
	raw, err := d.readFile(id + recordSuffix)
	if err != nil {
		return Record{}, err
	}
	r, err := decodeRecord(raw)
	if err != nil {
		return Record{}, fmt.Errorf("record %s: %w", id, err)
	}
	if r.ID != id {
		return Record{}, fmt.Errorf("%w: %s holds run %s", ErrNameMismatch, id+recordSuffix, r.ID)
	}
	return r, nil
}
