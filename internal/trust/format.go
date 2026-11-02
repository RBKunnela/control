package trust

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policy/strictjson"
	"github.com/guardana/control/internal/policykey"
)

const (
	// DocumentKind is the one kind a roster's body may name.
	DocumentKind = "trust-roster/v1alpha1"
	// PayloadType is the DSSE payload type a roster is signed under. It
	// differs from every other type a key of this project signs, so a
	// signature made for one never verifies as another.
	PayloadType = "application/vnd.agent-trust-roster+json"
	// MaxBodyBytes bounds a roster's body.
	MaxBodyBytes = 65536
	// MaxFileBytes bounds a roster file, the envelope and all: the base64 of
	// a body of MaxBodyBytes and one signature fit within it.
	MaxFileBytes = 98304
	// MaxKeys bounds the keys of one roster.
	MaxKeys = 64
	// MaxGrants bounds the grants of one key.
	MaxGrants = 32
	// MaxLifetime bounds expiresAt after issuedAt. A plane keeps the last
	// roster it verified until it expires, so a revoked key is trusted for at
	// most this long when a newer roster is withheld.
	MaxLifetime = 7 * 24 * time.Hour
	// DefaultLifetime is the lifetime a roster is signed for unless the
	// signer names another.
	DefaultLifetime = 24 * time.Hour
	// MaxRosterIDBytes bounds a roster id, which names the issuer an
	// authenticated operator is recorded under.
	MaxRosterIDBytes = 48
	// MaxSubjectBytes bounds a subject. With MaxRosterIDBytes it keeps the
	// approver id built from the two within its own bound.
	MaxSubjectBytes = 64
)

// Alg is the signature algorithm a key carries. A verifier takes it from the
// key, never from the message it verifies.
type Alg string

// AlgEd25519 is Ed25519 over the DSSE pre-authentication encoding.
const AlgEd25519 Alg = "ed25519"

// Role is the authority a roster names a key for.
type Role string

// RoleOperator is a person's key: it signs what an operator does.
const RoleOperator Role = "operator"

// Level is how much a grant lets its key do. The zero Level grants nothing.
type Level uint8

// The levels, each including the ones before it.
const (
	LevelNone Level = iota
	LevelRead
	LevelOperate
	LevelAdmin
)

var levelNames = map[string]Level{"read": LevelRead, "operate": LevelOperate, "admin": LevelAdmin}

// String is the level's spelling in a roster.
func (l Level) String() string {
	for name, v := range levelNames {
		if v == l {
			return name
		}
	}
	return "none"
}

// Grant is a level over one tenant's one project. Neither is ever empty, and
// neither is a pattern.
type Grant struct {
	Tenant, Project string
	Level           Level
}

var (
	documentMembers = []string{"kind", "rosterId", "serial", "issuedAt", "expiresAt", "keys"}
	keyMembers      = []string{"keyId", "alg", "role", "subject", "publicKey", "grants"}
	grantMembers    = []string{"tenant", "project", "level"}
)

// readDocument reads a roster body, which has to be its own canonical form,
// so a roster has one spelling and one digest.
func readDocument(body []byte) (Document, error) {
	canonical, err := canon.CanonicalizeJSON(body)
	if err != nil {
		return Document{}, fmt.Errorf("%w: not strict JSON", ErrMalformed)
	}
	if !bytes.Equal(canonical, body) {
		return Document{}, ErrNotCanonical
	}
	members, err := object(body, documentMembers)
	if err != nil {
		return Document{}, err
	}
	d := Document{digest: bundle.Digest(body)}
	if d.id, err = text(members["rosterId"], "rosterId"); err != nil {
		return Document{}, err
	}
	if !ValidRosterID(d.id) {
		return Document{}, fmt.Errorf("%w: rosterId", ErrMalformed)
	}
	if d.serial, err = strconv.ParseInt(string(members["serial"]), 10, 64); err != nil || d.serial < 1 || d.serial > policy.MaxSerial {
		return Document{}, fmt.Errorf("%w: serial", ErrMalformed)
	}
	if d.issuedAt, d.expiresAt, err = lifetime(members["issuedAt"], members["expiresAt"]); err != nil {
		return Document{}, err
	}
	if d.keys, err = readKeys(members["keys"], d); err != nil {
		return Document{}, err
	}
	return d, nil
}

// object reads raw as one JSON object holding exactly names. A kind member,
// where the format has one, is judged before the others so that a roster of
// a later kind is refused as one.
func object(raw json.RawMessage, names []string) (strictjson.Object, error) {
	members, err := strictjson.ReadObject(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if kind, ok := members["kind"]; ok {
		if s, isText := strictjson.String(kind); !isText || s != DocumentKind {
			return nil, ErrKind
		}
	}
	if err := members.Only(names...); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if err := members.Require(names...); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return members, nil
}

func text(raw json.RawMessage, member string) (string, error) {
	s, ok := strictjson.String(raw)
	if !ok {
		return "", fmt.Errorf("%w: %s is not a string", ErrMalformed, member)
	}
	return s, nil
}

type field struct {
	member string
	dst    *string
}

// texts reads each field's member as a string, in the order given.
func texts(members strictjson.Object, fields ...field) error {
	for _, f := range fields {
		s, err := text(members[f.member], f.member)
		if err != nil {
			return err
		}
		*f.dst = s
	}
	return nil
}

func lifetime(issuedRaw, expiresRaw json.RawMessage) (issued, expires time.Time, err error) {
	for i, raw := range []json.RawMessage{issuedRaw, expiresRaw} {
		s, ok := strictjson.String(raw)
		if !ok {
			return time.Time{}, time.Time{}, ErrTimes
		}
		t, err := policy.ParseIssuedAt(s)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("%w: %w", ErrTimes, err)
		}
		if i == 0 {
			issued = t
		} else {
			expires = t
		}
	}
	switch life := expires.Sub(issued); {
	case life <= 0:
		return time.Time{}, time.Time{}, fmt.Errorf("%w: it expires before it is issued", ErrTimes)
	case life > MaxLifetime:
		return time.Time{}, time.Time{}, fmt.Errorf("%w: a lifetime of %s, at most %s", ErrTimes, life, MaxLifetime)
	}
	return issued, expires, nil
}

func array(raw json.RawMessage, member string, most int) ([]json.RawMessage, error) {
	var items []json.RawMessage
	if len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &items) != nil {
		return nil, fmt.Errorf("%w: %s is not a list", ErrMalformed, member)
	}
	switch {
	case len(items) == 0:
		return nil, fmt.Errorf("%w: %s is empty", ErrMalformed, member)
	case len(items) > most:
		return nil, fmt.Errorf("%w: %d %s, at most %d", ErrTooMany, len(items), member, most)
	}
	return items, nil
}

func readKeys(raw json.RawMessage, d Document) ([]Key, error) {
	items, err := array(raw, "keys", MaxKeys)
	if err != nil {
		return nil, err
	}
	keys := make([]Key, 0, len(items))
	for i, item := range items {
		k, err := readKey(item)
		if err != nil {
			return nil, fmt.Errorf("key %d: %w", i, err)
		}
		for j, prior := range keys {
			if policykey.SameKey(prior.pub, k.pub) {
				return nil, fmt.Errorf("%w: keys %d and %d", ErrKeyReused, j, i)
			}
		}
		k.rosterID, k.rosterSerial, k.rosterDigest, k.expiresAt = d.id, d.serial, d.digest, d.expiresAt
		keys = append(keys, k)
	}
	return keys, nil
}

func readKey(raw json.RawMessage) (Key, error) {
	members, err := object(raw, keyMembers)
	if err != nil {
		return Key{}, err
	}
	var k Key
	var alg, role, public string
	if err := texts(members, field{"keyId", &k.id}, field{"alg", &alg}, field{"role", &role},
		field{"subject", &k.subject}, field{"publicKey", &public}); err != nil {
		return Key{}, err
	}
	k.alg, k.role = Alg(alg), Role(role)
	switch {
	case k.alg != AlgEd25519:
		return Key{}, fmt.Errorf("%w: the algorithm is not one this build has", ErrKeyEntry)
	case k.role != RoleOperator:
		return Key{}, fmt.Errorf("%w: the role is not one this build has", ErrKeyEntry)
	case !nameRule(k.subject, MaxSubjectBytes, true):
		return Key{}, fmt.Errorf("%w: the subject", ErrKeyEntry)
	}
	if k.pub, err = policykey.ParsePublic(public); err != nil || bundle.WeakKey(k.pub) {
		return Key{}, fmt.Errorf("%w: the public key is not a usable Ed25519 key", ErrKeyEntry)
	}
	if k.id != policykey.KeyID(k.pub) {
		return Key{}, fmt.Errorf("%w: the key id is not its key's", ErrKeyEntry)
	}
	if k.grants, err = readGrants(members["grants"]); err != nil {
		return Key{}, err
	}
	return k, nil
}

func readGrants(raw json.RawMessage) ([]Grant, error) {
	items, err := array(raw, "grants", MaxGrants)
	if err != nil {
		return nil, err
	}
	grants := make([]Grant, 0, len(items))
	for i, item := range items {
		members, err := object(item, grantMembers)
		if err != nil {
			return nil, fmt.Errorf("grant %d: %w", i, err)
		}
		var g Grant
		var level string
		if err := texts(members, field{"tenant", &g.Tenant}, field{"project", &g.Project}, field{"level", &level}); err != nil {
			return nil, fmt.Errorf("grant %d: %w", i, err)
		}
		g.Level = levelNames[level]
		switch {
		case !scopeRule(g.Tenant):
			return nil, fmt.Errorf("%w: grant %d names no one tenant", ErrGrant, i)
		case !scopeRule(g.Project):
			return nil, fmt.Errorf("%w: grant %d names no one project", ErrGrant, i)
		case g.Level == LevelNone:
			return nil, fmt.Errorf("%w: grant %d names no level", ErrGrant, i)
		}
		for j, prior := range grants {
			if prior.Tenant == g.Tenant && prior.Project == g.Project {
				return nil, fmt.Errorf("%w: grants %d and %d name one tenant and project", ErrGrant, j, i)
			}
		}
		grants = append(grants, g)
	}
	return grants, nil
}

// scopeRule holds a tenant or project to the identifier rule, and refuses the
// characters a reader could take for a pattern: a grant names one of each.
func scopeRule(s string) bool {
	return policy.ValidID(s) && !strings.ContainsAny(s, "*?")
}

// ValidRosterID reports whether id is one a roster may carry: lower-case
// ASCII letters and digits first, then those and . _ -, within
// MaxRosterIDBytes. It is stricter than the floor's own check, and every
// caller that names a roster id checks it first.
func ValidRosterID(id string) bool { return nameRule(id, MaxRosterIDBytes, false) }

// nameRule is the rule a roster id and a subject are held to: ASCII letters
// and digits first, then letters, digits and . _ - (and @ + for a subject),
// within most bytes. A roster id is lower case.
func nameRule(s string, most int, subject bool) bool {
	if s == "" || len(s) > most {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !nameByte(s[i], i == 0, subject) {
			return false
		}
	}
	return true
}

func nameByte(c byte, first, subject bool) bool {
	switch {
	case 'a' <= c && c <= 'z', '0' <= c && c <= '9':
		return true
	case 'A' <= c && c <= 'Z':
		return subject
	case first:
		return false
	case c == '.', c == '_', c == '-':
		return true
	}
	return subject && (c == '@' || c == '+')
}

// distinct refuses, with ErrKeyReused, a roster key that is the root or one
// of others as policykey.SameKey compares.
func distinct(d Document, root ed25519.PublicKey, others []ed25519.PublicKey) error {
	for i, k := range d.keys {
		if policykey.SameKey(k.pub, root) {
			return fmt.Errorf("%w: key %d is the root key", ErrKeyReused, i)
		}
		for _, o := range others {
			if policykey.SameKey(k.pub, o) {
				return fmt.Errorf("%w: key %d is a key the plane pins for another authority", ErrKeyReused, i)
			}
		}
	}
	return nil
}

// quoted is a time's spelling as a JSON string; the spelling holds only
// digits and the characters - : T Z, none of which JSON escapes.
func quoted(s string) json.RawMessage { return json.RawMessage(`"` + s + `"`) }

// joinObject writes members back as one JSON object, each value the bytes it
// was read as. The canonical form sorts the names afterwards.
func joinObject(members strictjson.Object) ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	first := true
	for name, value := range members {
		key, err := json.Marshal(name)
		if err != nil {
			return nil, fmt.Errorf("%w: a member name", ErrMalformed)
		}
		if !first {
			b.WriteByte(',')
		}
		first = false
		b.Write(key)
		b.WriteByte(':')
		b.Write(value)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}
