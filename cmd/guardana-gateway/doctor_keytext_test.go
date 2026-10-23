package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/policykey"
)

// forgedCheck is a check line a value would forge if doctor printed it raw.
const forgedCheck = "ok      upstreams     all reachable"

// fixtureKeyText is the fixture key's file and its body line.
func fixtureKeyText(t *testing.T) (pemFile, body string) {
	t.Helper()
	raw, err := policykey.MarshalPrivate(fixtureKey())
	if err != nil {
		t.Fatal(err)
	}
	return string(raw), strings.Split(string(raw), "\n")[1]
}

// doctorOutput runs doctor over the configuration and returns both streams.
func doctorOutput(t *testing.T, config string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	run(context.Background(), []string{"doctor", "--config", config}, &stdout, &stderr)
	return stdout.String() + stderr.String()
}

// checkNoKeyTextOrForgedLine fails the test when doctor's output repeats any
// of the key file or starts a line with the forged check.
func checkNoKeyTextOrForgedLine(t *testing.T, out, body string) {
	t.Helper()
	if strings.Contains(out, body[:21]) || strings.Contains(out, "-----") {
		t.Errorf("doctor repeated key text:\n%s", out)
	}
	if strings.Contains(out, "\n"+forgedCheck) {
		t.Errorf("doctor printed a forged check line:\n%s", out)
	}
}

// TestDoctorRepeatsNoKeyTextAndForgesNoLine: a key's body line given for a
// path is refused by its key, a whole PEM given for another key is withheld
// from the settings, and a line break in a value is quoted, in the settings
// and in a check's line, so none reaches either stream and no forged check
// line appears.
func TestDoctorRepeatsNoKeyTextAndForgesNoLine(t *testing.T) {
	pemFile, body := fixtureKeyText(t)
	for name, c := range map[string]struct{ key, value, want string }{
		"body line as pause.file":         {"pause.file", body, "pause.file: holds a PEM marker"},
		"body line as policy.bundle_file": {"policy.bundle_file", body, "policy.bundle_file: holds a PEM marker"},
		"whole PEM as project_id":         {"project_id", pemFile, `"[key text withheld]\n"`},
		"forged ok line in environment":   {"environment", "dev\n" + forgedCheck, `"dev\n` + forgedCheck + `"`},
		"forged ok line in pause.file":    {"pause.file", "pause\n" + forgedCheck, `pause\n` + forgedCheck + ` cannot be read`},
	} {
		t.Run(name, func(t *testing.T) {
			tr := newTree(t)
			setEnv(t, c.key, c.value)
			out := doctorOutput(t, tr.config)
			checkNoKeyTextOrForgedLine(t, out, body)
			if !strings.Contains(out, c.want) {
				t.Errorf("doctor's output does not hold %q:\n%s", c.want, out)
			}
		})
	}
}

// TestDoctorWithholdsKeyTextInAnUnclassifiedTool: the line naming a tool no
// override classifies names its upstream, and an upstream named by a key's
// body line is withheld there as in the settings list.
func TestDoctorWithholdsKeyTextInAnUnclassifiedTool(t *testing.T) {
	_, body := fixtureKeyText(t)
	tr := newTree(t)
	setEnv(t, "upstreams.0.endpoint", upstream(t))
	setEnv(t, "upstreams.0.name", body)
	out := doctorOutput(t, tr.config)
	if want := policykey.KeyTextWithheld + "/read_order is unclassified"; !strings.Contains(out, want) {
		t.Errorf("doctor's output does not hold %q:\n%s", want, out)
	}
	checkNoKeyTextOrForgedLine(t, out, body)
	if holdsKeyWindow(out, body) {
		t.Errorf("doctor repeated key text:\n%s", out)
	}
}

// TestDoctorPrintsNoKeyTextFromAnUpstreamOrAnOverride: an upstream's
// argument may carry a certificate and loads, and an override may name key
// text; the settings list prints no argument at all, only how many there
// are, and withholds the override's key text, keeping the rest of its line.
// A pointer that is key text and not RFC 6901 is refused at load, and the
// refusal names the key without repeating the value.
func TestDoctorPrintsNoKeyTextFromAnUpstreamOrAnOverride(t *testing.T) {
	_, body := fixtureKeyText(t)
	tr := newTree(t)
	raw, err := os.ReadFile(tr.config)
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.Replace(string(raw), "    endpoint: http://127.0.0.1:1/mcp\n",
		"    command: server\n    args:\n      - --ca=-----BEGIN CERTIFICATE-----x-----END CERTIFICATE-----\n"+
			`      - "a\n`+forgedCheck+`"`+"\n", 1)
	override := func(from string) string {
		return "\noverrides:\n  - upstream: orders\n    tool: " + body + "\n    fingerprint: abc\n" +
			"    effect: READ\n    resource_type: order\n    resource_from: " + from + "\n"
	}
	for _, c := range []struct {
		from  string
		wants []string
	}{
		{"/" + body, []string{`orders -> command server (2 arguments)`, `orders/[key text withheld] is READ on order from "[key text withheld]"`}},
		{body, []string{`overrides.0.resource_from: classify: the resource pointer is not RFC 6901`}},
	} {
		if err := os.WriteFile(tr.config, []byte(doc+override(c.from)), 0o600); err != nil { //nolint:gosec // G703: the configuration copy under the test's temp dir
			t.Fatal(err)
		}
		out := doctorOutput(t, tr.config)
		checkNoKeyTextOrForgedLine(t, out, body)
		for _, want := range c.wants {
			if !strings.Contains(out, want) {
				t.Errorf("doctor's output does not hold %q:\n%s", want, out)
			}
		}
	}
}

// endpointMarker stands for a credential in an upstream's endpoint or in
// what a hostile upstream reflects; no stream of doctor's or run's holds it.
const endpointMarker = "endpoint-private-marker"

// refusingUpstream answers every tools/list with a wire error whose message
// reflects endpointMarker, and returns its URL.
func refusingUpstream(t *testing.T) string {
	t.Helper()
	server := sdk.NewServer(&sdk.Implementation{Name: "refusing-upstream", Version: "0"}, nil)
	server.AddReceivingMiddleware(func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			if method == "tools/list" {
				return nil, &jsonrpc.Error{Code: -32042, Message: "reflected " + endpointMarker}
			}
			return next(ctx, method, req)
		}
	})
	ts := httptest.NewServer(sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server }, &sdk.StreamableHTTPOptions{Stateless: true}))
	t.Cleanup(ts.Close)
	return ts.URL
}

// TestNoUpstreamFailureRepeatsACredential: an upstream run and doctor cannot
// reach, through a query or a username holding a credential, and one whose
// tools/list reflects a credential in its error, are named in both commands'
// output by the upstream and what failed, and the credential is in neither.
func TestNoUpstreamFailureRepeatsACredential(t *testing.T) {
	gone := httptest.NewServer(http.NotFoundHandler())
	host := strings.TrimPrefix(gone.URL, "http://")
	gone.Close()
	for name, c := range map[string]struct{ endpoint, cause string }{
		"a query":         {"http://" + host + "/mcp?token=" + endpointMarker, "mcp: connect orders: Post: dial tcp"},
		"a username":      {"http://" + endpointMarker + ":pw@" + host + "/mcp", "mcp: connect orders: Post: dial tcp"},
		"a reflected one": {refusingUpstream(t) + "/mcp", "mcp: tools/list from orders: JSON-RPC error -32042"},
	} {
		t.Run(name, func(t *testing.T) {
			tr := newTree(t)
			setEnv(t, "upstreams.0.endpoint", c.endpoint)
			setEnv(t, "listener.address", "127.0.0.1:0")
			setEnv(t, "health.address", "")
			var stdout, stderr bytes.Buffer
			if status := serve(context.Background(), tr.config, "", &stdout, &stderr); status != exitFail {
				t.Fatalf("run answered %d over an upstream it cannot list; it must refuse to start", status)
			}
			for command, out := range map[string]string{"run": stdout.String() + stderr.String(), "doctor": doctorOutput(t, tr.config)} {
				if strings.Contains(out, endpointMarker) || !strings.Contains(out, c.cause) {
					t.Errorf("%s says:\n%s\nwant %q and no credential", command, out, c.cause)
				}
			}
		})
	}
}

// echoingUpstream answers every request with a status line that is not one,
// spelled from the request line and every header it was sent, and returns its
// host:port.
func echoingUpstream(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close() //nolint:errcheck // the answer is written; nothing reads the close
				req, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					return
				}
				var echo strings.Builder
				echo.WriteString(req.Method + " " + req.RequestURI + " " + req.Proto + " ")
				_ = req.Header.Write(&echo)
				_, _ = io.WriteString(conn, strings.NewReplacer(" ", "_", "\r\n", "_").Replace(echo.String())+"\r\n\r\n")
			}()
		}
	}()
	return ln.Addr().String()
}

// TestAnUpstreamEchoingTheRequestRepeatsNoCredential: an upstream answering
// with a malformed status line that quotes the request line and the
// Authorization header gets the HTTP client to quote them back; run and
// doctor name the upstream, the operation and a fixed cause, and neither the
// query's credential nor the userinfo, raw or as the header encodes it.
func TestAnUpstreamEchoingTheRequestRepeatsNoCredential(t *testing.T) {
	tr := newTree(t)
	setEnv(t, "upstreams.0.endpoint", "http://basic-user:"+endpointMarker+"@"+echoingUpstream(t)+"/mcp?token="+endpointMarker)
	setEnv(t, "listener.address", "127.0.0.1:0")
	setEnv(t, "health.address", "")
	var stdout, stderr bytes.Buffer
	if status := serve(context.Background(), tr.config, "", &stdout, &stderr); status != exitFail {
		t.Fatalf("run answered %d over an upstream that answers no status line; it must refuse to start", status)
	}
	basic := base64.StdEncoding.EncodeToString([]byte("basic-user:" + endpointMarker))
	const cause = "mcp: connect orders: Post: the transport failed; its text is withheld"
	for command, out := range map[string]string{"run": stdout.String() + stderr.String(), "doctor": doctorOutput(t, tr.config)} {
		if strings.Contains(out, endpointMarker) || strings.Contains(out, basic) || !strings.Contains(out, cause) {
			t.Errorf("%s says:\n%s\nwant %q and no credential", command, out, cause)
		}
	}
}

// sessionStreamCutter speaks an older protocol revision, so the client opens a
// standalone stream after initialize, and cuts every such stream. It assigns
// a session id that reflects endpointMarker and never answers a request, so
// the session fails on the stream. It returns its URL.
func sessionStreamCutter(t *testing.T) string {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if conn, _, err := http.NewResponseController(w).Hijack(); err == nil {
				_ = conn.Close()
			}
			return
		}
		answerOldRevision(w, r)
	}))
	t.Cleanup(ts.Close)
	return ts.URL
}

func answerOldRevision(w http.ResponseWriter, r *http.Request) {
	var msg struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	_ = json.Unmarshal(raw, &msg)
	w.Header().Set("Content-Type", "application/json")
	switch {
	case msg.Method == "server/discover":
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+string(msg.ID)+`,"error":{"code":-32601,"message":"no"}}`)
	case msg.Method == "initialize":
		w.Header().Set("Mcp-Session-Id", "reflected-"+endpointMarker)
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+string(msg.ID)+`,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"cutter","version":"0"}}}`)
	case len(msg.ID) == 0:
		w.WriteHeader(http.StatusAccepted)
	default:
		<-r.Context().Done()
	}
}

// TestASessionStreamFailureRepeatsNoCredential: the library words a failed
// session stream with the endpoint it dialled and the session id the upstream
// chose, neither through an error type. doctor names the upstream and what
// failed, and neither the endpoint's credential nor what the upstream
// reflected. The library's own reconnect backoff makes this take some 20s.
func TestASessionStreamFailureRepeatsNoCredential(t *testing.T) {
	endpoint := strings.Replace(sessionStreamCutter(t), "http://", "http://"+endpointMarker+":pw@", 1) + "/mcp?token=" + endpointMarker
	tr := newTree(t)
	setEnv(t, "upstreams.0.endpoint", endpoint)
	setEnv(t, "listener.address", "127.0.0.1:0")
	setEnv(t, "health.address", "")
	out := doctorOutput(t, tr.config)
	if strings.Contains(out, endpointMarker) || !strings.Contains(out, "orders") {
		t.Errorf("doctor says:\n%s\nwant the upstream named and no credential", out)
	}
}

// basicPassword is a password whose base64 with its user differs between the
// standard and the URL-safe alphabets, and is padded.
const basicPassword = "~~~marker"

// TestARefusalQuotingAWithheldEndpointIsNotPrinted: should a refusal from the
// adapter still quote the userinfo, query or fragment of an endpoint doctor
// withholds, the refusal names the key instead; one that quotes none of them,
// or comes over an endpoint that carries none, is printed as it is.
func TestARefusalQuotingAWithheldEndpointIsNotPrinted(t *testing.T) {
	host := "http://127.0.0.1:1"
	for name, c := range map[string]struct {
		endpoint, text string
		withheld       bool
	}{
		"a query":             {host + "/mcp?token=" + endpointMarker, "dial " + endpointMarker, true},
		"a decoded query":     {host + "/mcp?token=a%2F" + endpointMarker, "dial a/" + endpointMarker, true},
		"a username":          {"http://" + endpointMarker + ":pw@127.0.0.1:1/mcp", "Get " + endpointMarker + ":***@", true},
		"a password":          {"http://user:" + endpointMarker + "@127.0.0.1:1/mcp", "auth " + endpointMarker, true},
		"a fragment":          {host + "/mcp#" + endpointMarker, "at " + endpointMarker, true},
		"a raw password":      {"http://user:" + endpointMarker + "%2fpw@127.0.0.1:1/mcp/at@path", "auth " + endpointMarker + "%2fpw", true},
		"a raw username":      {"http://tok%2f" + endpointMarker + ":pw@127.0.0.1:1/mcp", "Get tok%2f" + endpointMarker, true},
		"a decoded username":  {"http://a%2F" + endpointMarker + ":pw@127.0.0.1:1/mcp", "user a/" + endpointMarker, true},
		"a decoded password":  {"http://user:a%2F" + endpointMarker + "@127.0.0.1:1/mcp", "auth a/" + endpointMarker, true},
		"an escaped username": {"http://tok%2f" + endpointMarker + ":pw@127.0.0.1:1/mcp", "Get tok%2F" + endpointMarker, true},
		"basic, standard":     {"http://basic-user:" + basicPassword + "@127.0.0.1:1/mcp", "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("basic-user:"+basicPassword)), true},
		"basic, URL-safe":     {"http://basic-user:" + basicPassword + "@127.0.0.1:1/mcp", "Basic_" + base64.URLEncoding.EncodeToString([]byte("basic-user:"+basicPassword)), true},
		"none quoted":         {host + "/mcp?token=" + endpointMarker, "connect orders: connection refused", false},
		"nothing to quote":    {host + "/" + endpointMarker, "dial " + endpointMarker, false},
	} {
		t.Run(name, func(t *testing.T) {
			ups := []gatewayconfig.UpstreamConfig{{Name: "orders", Endpoint: c.endpoint}}
			got := withheldRefusal(errors.New(c.text), ups).Error()
			if c.withheld && (strings.Contains(got, endpointMarker) || !strings.Contains(got, "upstreams.0.endpoint")) {
				t.Errorf("printed %q, want the key named in place of the text", got)
			}
			if !c.withheld && got != c.text {
				t.Errorf("printed %q, want %q as it is", got, c.text)
			}
		})
	}
}
