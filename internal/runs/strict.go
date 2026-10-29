package runs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/policy/strictjson"
)

// SchemaVersion is the version this build writes into the marker and into a
// root's state. A reader takes any minor of major 1 and refuses another major.
const SchemaVersion = "1.0"

// RecordVersion is the version this build writes into a run's record. A
// reader takes any minor of major 2 and refuses another major.
const RecordVersion = "2.0"

// fields reads raw as exactly one JSON object holding each of keys once and
// nothing else. Keys are matched exactly: encoding/json would take a key in
// any case, the last of two duplicates, and a missing key as its zero value,
// and each of those lets one file read two ways.
func fields(raw []byte, keys []string) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, fmt.Errorf("%w: not a JSON object", ErrMalformed)
	}
	out := make(map[string]json.RawMessage, len(keys))
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrMalformed, clip(err.Error()))
		}
		key, ok := tok.(string)
		if !ok {
			return nil, fmt.Errorf("%w: a key that is not a string", ErrMalformed)
		}
		if _, seen := out[key]; seen {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateField, clip(key))
		}
		if !slices.Contains(keys, key) {
			return nil, fmt.Errorf("%w: %q", ErrUnknownField, clip(key))
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, fmt.Errorf("%w: %q: %s", ErrMalformed, key, clip(err.Error()))
		}
		out[key] = v
	}
	if err := finish(dec, out, keys); err != nil {
		return nil, err
	}
	return out, nil
}

// finish refuses an object that does not close, anything after it, and a key
// it lacks.
func finish(dec *json.Decoder, out map[string]json.RawMessage, keys []string) error {
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return fmt.Errorf("%w: the object does not close", ErrMalformed)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: data after the object", ErrMalformed)
	}
	for _, k := range keys {
		if _, ok := out[k]; !ok {
			return fmt.Errorf("%w: %q", ErrMissingField, k)
		}
	}
	return nil
}

// stringField reads a key fields found as a JSON string. A null is not a
// string: decoded into one it would read as empty. The canonical reader is
// asked first, since it refuses what encoding/json would decode as U+FFFD.
func stringField(f map[string]json.RawMessage, key string) (string, error) {
	v := f[key]
	if len(v) == 0 || v[0] != '"' {
		return "", fmt.Errorf("%w: %q is not a string", ErrMalformed, key)
	}
	if _, err := canon.CanonicalizeJSON(v); err != nil {
		return "", fmt.Errorf("%w: %q", ErrEncoding, key)
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return "", fmt.Errorf("%w: %q: %s", ErrMalformed, key, clip(err.Error()))
	}
	return s, nil
}

func boolField(f map[string]json.RawMessage, key string) (bool, error) {
	switch string(f[key]) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("%w: %q is not a boolean", ErrMalformed, key)
}

// checkSchemaVersion refuses a version this build does not read. The major
// decides: a later minor may add a field, and the unknown-field rule refuses
// that file too, so nothing is dropped in silence.
func checkSchemaVersion(v string) error {
	if !strictjson.IsVersion(v, "1") {
		return fmt.Errorf("%w: %q", ErrSchemaVersion, clip(v))
	}
	return nil
}

// checkRecordVersion refuses a record whose major this build does not read.
// A record of major 1 names no project, so reading it would hand its run to
// whichever project asked.
func checkRecordVersion(v string) error {
	if !strictjson.IsVersion(v, "2") {
		return fmt.Errorf("%w: %q; a record is read at major 2, and one of major 1 names no project: open the run again",
			ErrSchemaVersion, clip(v))
	}
	return nil
}

// encode writes v as one JSON line. HTML escaping is off: it would only make
// a field longer than the bound it was checked against.
func encode(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// formatTime is the one spelling a time takes in a file.
func formatTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// parseTime reads a time and refuses any spelling but formatTime's, so a file
// that decodes writes back as the same bytes.
func parseTime(key, s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || formatTime(t) != s || t.IsZero() {
		return time.Time{}, fmt.Errorf("%w: %q is not a UTC RFC 3339 time", ErrMalformed, key)
	}
	return t.UTC(), nil
}

// canonTime is t as a file holds it: UTC, with no monotonic reading, so a
// value handed back equals the value read back.
func canonTime(t time.Time) time.Time { return t.Round(0).UTC() }
