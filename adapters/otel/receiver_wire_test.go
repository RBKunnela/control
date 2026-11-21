package otel_test

import (
	"bufio"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/adapters/otel"
)

// wireReceiver serves a receiver into sink over HTTP/1.1 until the test ends
// and returns what sends it a request head declaring body, with the
// Authorization line given, and the connection's answers.
func wireReceiver(t *testing.T, sink *memorySink, body string) func(authorization string) (net.Conn, *bufio.Reader) {
	t.Helper()
	h, err := otel.NewReceiver(sink, slog.New(slog.DiscardHandler), testCredential(t))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return func(authorization string) (net.Conn, *bufio.Reader) {
		t.Helper()
		conn, err := net.DialTimeout("tcp", srv.Listener.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		head := "POST /v1/logs HTTP/1.1\r\nHost: collector\r\nContent-Type: application/json\r\n" + authorization +
			"Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n"
		if _, err := conn.Write([]byte(head)); err != nil {
			t.Fatal(err)
		}
		return conn, bufio.NewReader(conn)
	}
}

// TestARefusalWithoutTheCredentialIsSentBeforeTheBody: over HTTP/1.1, a
// request without the credential declaring a small body it has not sent is
// answered 401 at once and the connection closed.
func TestARefusalWithoutTheCredentialIsSentBeforeTheBody(t *testing.T) {
	sink := &memorySink{}
	conn, answers := wireReceiver(t, sink, base())("")
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(answers, nil)
	if err != nil {
		t.Fatalf("no answer to a request without the credential while its body is unsent: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || !resp.Close || sink.appends() != 0 {
		t.Errorf("answered %d, closing %v, with %d append(s); want 401, the connection closed and none",
			resp.StatusCode, resp.Close, sink.appends())
	}
}

// TestARequestWithTheCredentialIsAnsweredAfterItsBody: the same request
// carrying the credential is waited on until its body arrives, and then
// taken.
func TestARequestWithTheCredentialIsAnsweredAfterItsBody(t *testing.T) {
	sink := &memorySink{}
	body := base()
	conn, answers := wireReceiver(t, sink, body)("Authorization: Bearer " + testToken + "\r\n")
	if err := conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := answers.Peek(1); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a request with the credential was answered before its body: %v", err)
	}
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(answers, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || sink.appends() != 1 {
		t.Errorf("answered %d with %d append(s), want 200 and one", resp.StatusCode, sink.appends())
	}
}

// TestEveryContentEncodingIsRead: a coding in a second Content-Encoding
// field is refused 415 as one in the first is, and the sink is not reached;
// identity in both is taken.
func TestEveryContentEncodingIsRead(t *testing.T) {
	for name, c := range map[string]struct {
		codings []string
		status  int
	}{
		"identity, then gzip": {[]string{"identity", "gzip"}, http.StatusUnsupportedMediaType},
		"gzip, then identity": {[]string{"gzip", "identity"}, http.StatusUnsupportedMediaType},
		"identity twice":      {[]string{"identity", "Identity"}, http.StatusOK},
	} {
		sink := &memorySink{}
		req := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader(base()))
		req.Header.Set("Content-Type", "application/json")
		for _, coding := range c.codings {
			req.Header.Add("Content-Encoding", coding)
		}
		rec := httptest.NewRecorder()
		newReceiver(t, sink).ServeHTTP(rec, req)
		want := 0
		if c.status == http.StatusOK {
			want = 1
		}
		if rec.Code != c.status || sink.appends() != want {
			t.Errorf("%s: answered %d with %d append(s), want %d and %d", name, rec.Code, sink.appends(), c.status, want)
		}
	}
}

// TestASecondContentTypeIsRefused: a request with two Content-Type fields
// names no one media type, even when both are JSON, and is refused 415
// without the sink being reached; one field is taken.
func TestASecondContentTypeIsRefused(t *testing.T) {
	for name, c := range map[string]struct {
		types  []string
		status int
	}{
		"JSON twice":      {[]string{"application/json", "application/json"}, http.StatusUnsupportedMediaType},
		"JSON, then text": {[]string{"application/json", "text/plain"}, http.StatusUnsupportedMediaType},
		"text, then JSON": {[]string{"text/plain", "application/json"}, http.StatusUnsupportedMediaType},
		"JSON in one":     {[]string{"application/json"}, http.StatusOK},
	} {
		sink := &memorySink{}
		req := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader(base()))
		for _, media := range c.types {
			req.Header.Add("Content-Type", media)
		}
		rec := httptest.NewRecorder()
		newReceiver(t, sink).ServeHTTP(rec, req)
		want := 0
		if c.status == http.StatusOK {
			want = 1
		}
		if rec.Code != c.status || sink.appends() != want {
			t.Errorf("%s: answered %d with %d append(s), want %d and %d", name, rec.Code, sink.appends(), c.status, want)
		}
	}
}
