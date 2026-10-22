package otel

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"unicode/utf8"
)

// class is what an answer means for the records in the request.
type class uint8

const (
	classAccepted class = iota
	// classRefused is 400, 413 and 422: the collector refuses the records.
	classRefused
	classTransport
	classRedirect
	classAuth
	classThrottled
	classServer
	classAnswer
	classStatus
	classes
)

// answer is one request's outcome. It carries no text of the collector's: a
// hostile collector could otherwise reflect an evidence line, or the request's
// own credential, into the operator's log, so a log line names the answer by
// its length and its digest and says in the exporter's own words what was
// wrong with it.
type answer struct {
	class    class
	status   int
	rejected int64
	// why is why an answer with an accepting status is not the protocol's.
	why    string
	bytes  int
	digest string
	err    error
}

// fields is what a log line says about the answer.
func (a answer) fields() []any {
	out := []any{"status", a.status, "answer_bytes", a.bytes, "answer_sha256", a.digest}
	if a.why != "" {
		out = append(out, "answer_refused", a.why)
	}
	return out
}

// classify reads one answer's status and body.
func classify(status int, text []byte, readErr error, batch int) answer {
	sum := sha256.Sum256(text)
	a := answer{status: status, bytes: len(text), digest: hex.EncodeToString(sum[:8]), err: readErr}
	switch status {
	case http.StatusOK, http.StatusAccepted:
		a.class = classAnswer
		switch {
		case readErr != nil:
			a.why = "the answer could not be read"
		default:
			rejected, why := readAnswer(text, batch)
			if why != "" {
				a.why = why
				return a
			}
			a.class, a.rejected = classAccepted, rejected
		}
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
		a.class = classRefused
	default:
		a.class = statusClass(status)
	}
	return a
}

func statusClass(code int) class {
	switch {
	case code >= 300 && code < 400:
		return classRedirect
	case code == http.StatusUnauthorized || code == http.StatusForbidden || code == http.StatusProxyAuthRequired:
		return classAuth
	case code == http.StatusRequestTimeout || code == http.StatusTooManyRequests:
		return classThrottled
	case code >= 500:
		return classServer
	default:
		return classStatus
	}
}

// The members of ExportLogsServiceResponse and of its partial success, each in
// the two spellings the protobuf JSON mapping writes, mapped to one name. A
// member in both spellings is the same member twice.
var (
	answerMembers = map[string]string{
		"partialSuccess":  "partialSuccess",
		"partial_success": "partialSuccess",
	}
	partialMembers = map[string]string{
		"rejectedLogRecords":   "rejectedLogRecords",
		"rejected_log_records": "rejectedLogRecords",
		"errorMessage":         "errorMessage",
		"error_message":        "errorMessage",
	}
)

// readAnswer reads an accepting answer: empty, or the JSON of
// ExportLogsServiceResponse, whose only member is partialSuccess. It returns
// the records the collector reports dropped, at most the batch's length, and
// why the answer is not the protocol's when it is not. protojson refuses a
// member that appears twice, and so does this: encoding/json alone would keep
// the last spelling and read a refusal as an acceptance.
func readAnswer(text []byte, batch int) (int64, string) {
	text = bytes.TrimSpace(text)
	if len(text) == 0 {
		return 0, ""
	}
	members, err := strictMembers(text, answerMembers)
	if err != nil {
		return 0, err.Error()
	}
	raw, ok := members["partialSuccess"]
	if !ok || string(raw) == "null" {
		return 0, ""
	}
	inner, err := strictMembers(raw, partialMembers)
	if err != nil {
		return 0, err.Error()
	}
	rejected, ok := parseCount(inner["rejectedLogRecords"])
	switch {
	case !ok:
		return 0, "the count of rejected records is not a count"
	case !isText(inner["errorMessage"]):
		return 0, "the error message is not a string"
	case rejected > int64(batch):
		return 0, "the count of rejected records is past the records in the request"
	}
	return rejected, ""
}

// strictMembers reads one JSON object: every member once, under a name the
// protocol's answer has, and nothing after the object. The reasons it gives
// name no member, because the names come from the collector.
func strictMembers(raw []byte, names map[string]string) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("the answer is not a JSON object")
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil, errors.New("the answer's members do not parse")
		}
		name, ok := key.(string)
		if !ok {
			return nil, errors.New("the answer's members do not parse")
		}
		canonical, known := names[name]
		if !known {
			return nil, fmt.Errorf("the answer holds a member of %d bytes the protocol's answer does not have", len(name))
		}
		if _, twice := out[canonical]; twice {
			return nil, errors.New("the answer holds one member twice")
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, errors.New("a member of the answer does not parse")
		}
		out[canonical] = value
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, errors.New("the answer's object does not end")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("the answer holds more than one document")
	}
	return out, nil
}

// isText reports whether raw is absent, null or a JSON string of UTF-8 whose
// surrogate escapes come in pairs, the forms the protobuf JSON mapping reads
// a string member from.
func isText(raw json.RawMessage) bool {
	if len(raw) == 0 || string(raw) == "null" {
		return true
	}
	var s string
	return utf8.Valid(raw) && json.Unmarshal(raw, &s) == nil && pairedSurrogates(raw)
}

// parseCount reads an int64 as the protobuf JSON mapping writes it, a decimal
// string, or as a plain number, which it also accepts.
func parseCount(raw json.RawMessage) (int64, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return 0, true
	}
	text := string(raw)
	if unquoted, err := strconv.Unquote(text); err == nil {
		text = unquoted
	}
	n, err := strconv.ParseInt(text, 10, 64)
	return n, err == nil && n >= 0
}
