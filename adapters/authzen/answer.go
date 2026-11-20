package authzen

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"strings"
	"unicode/utf8"

	"github.com/guardana/control/internal/core"
)

// isJSON reports whether the answer declares exactly one Content-Type,
// application/json, with at most a UTF-8 charset.
func isJSON(values []string) bool {
	if len(values) != 1 {
		return false
	}
	media, params, err := mime.ParseMediaType(values[0])
	if err != nil || media != "application/json" {
		return false
	}
	for name, value := range params {
		if name != "charset" || !strings.EqualFold(value, "utf-8") {
			return false
		}
	}
	return true
}

// readAnswer reads the body of a 200. Its structure is always strict: one
// JSON object in UTF-8, each member once under its exact name, and decision a
// JSON boolean. A false is a denial whatever else the answer holds. A true
// counts only as {decision, context?} whose context holds listed members and
// obligations that are absent or empty; a non-empty list of obligations is a
// denial, and anything else is refused.
func readAnswer(body []byte, listed map[string]bool) core.External {
	// encoding/json replaces a byte that is not UTF-8 inside a string rather
	// than refusing it.
	if !utf8.Valid(body) {
		return core.ExternalAnswerRefused()
	}
	top, err := members(body)
	if err != nil {
		return core.ExternalAnswerRefused()
	}
	switch string(top["decision"]) {
	case "false":
		return core.ExternalDenied()
	case "true":
		return readAllow(top, listed)
	}
	return core.ExternalAnswerRefused()
}

// readAllow reads an answer that said true.
func readAllow(top map[string]json.RawMessage, listed map[string]bool) core.External {
	raw, ok := top["context"]
	if !ok {
		if len(top) != 1 {
			return core.ExternalAnswerRefused()
		}
		return core.ExternalAllowed()
	}
	inner, err := members(raw)
	if err != nil {
		return core.ExternalAnswerRefused()
	}
	if obligations, ok := inner["obligations"]; ok {
		empty, err := emptyArray(obligations)
		switch {
		case err != nil:
			return core.ExternalAnswerRefused()
		case !empty:
			return core.ExternalDeniedObligations()
		}
	}
	if len(top) != 2 {
		return core.ExternalAnswerRefused()
	}
	for name := range inner {
		if name != "obligations" && !listed[name] {
			return core.ExternalAnswerRefused()
		}
	}
	return core.ExternalAllowed()
}

// members reads one JSON object: every member once, and nothing after it.
// Names compare as JSON decodes them, so an escaped spelling of a member is
// the same member.
func members(raw []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil, err
		}
		name, ok := key.(string)
		if !ok {
			return nil, errors.New("a member name that is not a string")
		}
		if _, twice := out[name]; twice {
			return nil, errors.New("a member twice")
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		out[name] = value
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, errors.New("the object does not end")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("more than one document")
	}
	return out, nil
}

// emptyArray reports whether raw is a JSON array with nothing in it, and
// refuses anything that is not an array.
func emptyArray(raw json.RawMessage) (bool, error) {
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil || items == nil {
		return false, errors.New("not an array")
	}
	return len(items) == 0, nil
}
