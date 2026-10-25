package authzen

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// DiscoveryVerdict is what the published metadata says about the
// configuration. The zero value is unknown.
type DiscoveryVerdict uint8

// The verdicts of CheckDiscovery.
const (
	// DiscoveryUnknown is metadata that could not be fetched or read.
	DiscoveryUnknown DiscoveryVerdict = iota
	// DiscoveryAgrees is metadata naming the configured identifier and
	// evaluation endpoint.
	DiscoveryAgrees
	// DiscoveryDisagrees is metadata that names another identifier or
	// endpoint, or leaves one out.
	DiscoveryDisagrees
)

// String names the verdict.
func (v DiscoveryVerdict) String() string {
	switch v {
	case DiscoveryAgrees:
		return "agrees"
	case DiscoveryDisagrees:
		return "disagrees"
	}
	return "unknown"
}

// unverified ends every report: the check reads what the document says, and
// no signature over it.
const unverified = "; signed_metadata is not verified"

// Report is what CheckDiscovery found. Detail is in this client's words and
// quotes nothing of the document.
type Report struct {
	Verdict DiscoveryVerdict
	Detail  string
}

func report(v DiscoveryVerdict, detail string) Report {
	return Report{Verdict: v, Detail: detail + unverified}
}

// CheckDiscovery fetches the decision point's published metadata, once, and
// checks that it names the configured identifier and evaluation endpoint. It
// is a doctor check: neither New nor Ask ever runs it, so the plane never
// waits on it.
func (c *Client) CheckDiscovery(ctx context.Context) Report {
	if c == nil || c.http == nil {
		return report(DiscoveryUnknown, "no decision point is configured")
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL(c), nil)
	if err != nil {
		return report(DiscoveryUnknown, "the metadata request could not be built")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return report(DiscoveryUnknown, "the metadata could not be fetched")
	}
	defer resp.Body.Close() //nolint:errcheck // the document is read; nothing to lose on close
	if resp.StatusCode != http.StatusOK || !isJSON(resp.Header.Values("Content-Type")) {
		return report(DiscoveryUnknown, "the metadata answer is not a 200 of JSON")
	}
	text, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswerBytes+1))
	if err != nil || ctx.Err() != nil || len(text) > maxAnswerBytes {
		return report(DiscoveryUnknown, "the metadata could not be read within the bound")
	}
	return c.compare(text)
}

// compare checks the document's two members against the configuration.
func (c *Client) compare(text []byte) Report {
	doc, err := members(text)
	if err != nil {
		return report(DiscoveryUnknown, "the metadata is not one JSON object with each member once")
	}
	id, idOK := stringMember(doc["policy_decision_point"])
	endpoint, endpointOK := stringMember(doc["access_evaluation_endpoint"])
	switch {
	case !idOK || !endpointOK:
		return report(DiscoveryUnknown, "the metadata's identifier or endpoint is not a string")
	case id != c.cfg.raw:
		return report(DiscoveryDisagrees, "the metadata's policy_decision_point is not the configured identifier")
	case endpoint != c.cfg.endpoint:
		return report(DiscoveryDisagrees, "the metadata's access_evaluation_endpoint is not the configured endpoint")
	}
	return report(DiscoveryAgrees, "the metadata names the configured identifier and endpoint")
}

// stringMember reads a member that is a JSON string; an absent one reads as
// empty, which no configuration equals. A null one is not a string, though
// json.Unmarshal reads it into one without an error.
func stringMember(raw json.RawMessage) (string, bool) {
	if raw == nil {
		return "", true
	}
	if string(raw) == "null" {
		return "", false
	}
	var s string
	err := json.Unmarshal(raw, &s)
	return s, err == nil
}

// discoveryURL is where the identifier's metadata is published: the
// well-known path inserted between the host and the identifier's path.
func discoveryURL(c *Client) string {
	u := *c.cfg.identifier
	u.Path = "/.well-known/authzen-configuration" + strings.TrimSuffix(u.Path, "/")
	u.RawPath = ""
	return u.String()
}
