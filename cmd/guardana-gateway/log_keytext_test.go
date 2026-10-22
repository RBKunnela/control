package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/policykey"
)

// holdsKeyWindow reports whether out holds any 21 characters of body in a
// row, the length of the start every key file's body line begins with.
func holdsKeyWindow(out, body string) bool {
	const window = 21
	for i := 0; i+window <= len(body); i++ {
		if strings.Contains(out, body[i:i+window]) {
			return true
		}
	}
	return false
}

// TestTheLogWithholdsKeyTextInEveryValue: the message, a string, each
// element of a []string, a []byte, a byte slice of another type, a byte
// array, an error, another value, a value inside a group, one given to With,
// a key, a group's key and a group's name all reach the line with their key
// text withheld, and the rest of the line stays.
func TestTheLogWithholdsKeyTextInEveryValue(t *testing.T) {
	_, body := fixtureKeyText(t)
	for name, log := range map[string]func(*slog.Logger){
		"message":        func(l *slog.Logger) { l.Info("read " + body) },
		"string":         func(l *slog.Logger) { l.Info("m", "detail", "near "+body) },
		"[]string":       func(l *slog.Logger) { l.Info("m", "added", []string{"ok", body}) },
		"error":          func(l *slog.Logger) { l.Info("m", "err", fmt.Errorf("open %s: denied", body)) },
		"joined errors":  func(l *slog.Logger) { l.Info("m", "err", errors.Join(errors.New("a"), errors.New(body))) },
		"another value":  func(l *slog.Logger) { l.Info("m", "entry", struct{ ID string }{body}) },
		"a group":        func(l *slog.Logger) { l.Info("m", slog.Group("g", "id", body)) },
		"With":           func(l *slog.Logger) { l.With("id", body).Info("m") },
		"WithGroup":      func(l *slog.Logger) { l.WithGroup("g").Info("m", "id", body) },
		"a log.Logger":   func(l *slog.Logger) { slog.NewLogLogger(l.Handler(), slog.LevelWarn).Print("http: " + body) },
		"a LogValuer":    func(l *slog.Logger) { l.Info("m", "v", keyValuer(body)) },
		"[]byte":         func(l *slog.Logger) { l.Info("m", "raw", []byte("near "+body)) },
		"a named []byte": func(l *slog.Logger) { l.Info("m", "raw", namedBytes("near "+body)) },
		"[N]byte": func(l *slog.Logger) {
			var raw [64]byte
			copy(raw[:], body)
			l.Info("m", "raw", raw)
		},
		"a key":         func(l *slog.Logger) { l.Info("m", body, 1) },
		"a group's key": func(l *slog.Logger) { l.Info("m", slog.Group(body, "id", 1)) },
		"a group name":  func(l *slog.Logger) { l.WithGroup(body).Info("m", "id", 1) },
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			log(slog.New(printableLog(slog.NewTextHandler(&out, nil))))
			if holdsKeyWindow(out.String(), body) {
				t.Errorf("the log line repeats key text: %s", out.String())
			}
			if !strings.Contains(out.String(), policykey.KeyTextWithheld) {
				t.Errorf("the log line does not say it withheld key text: %s", out.String())
			}
		})
	}
}

// TestTheLogKeepsWhatHoldsNoKeyText: a line with no key text is the text
// handler's own line, level and values as they were: a byte type that
// formats itself as its own text, a byte array as the text it holds.
func TestTheLogKeepsWhatHoldsNoKeyText(t *testing.T) {
	var out bytes.Buffer
	l := slog.New(printableLog(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelWarn})))
	l.Info("dropped below the level")
	l.With("path", "/srv/pause.json").Warn("pause state changed", "entries", 2, "added", []string{"a", "b"}, "err", errors.New("gone"),
		"peer", net.IPv4(127, 0, 0, 1), "raw", [2]byte{'o', 'k'})
	got := strings.TrimSpace(out.String())
	got = got[strings.Index(got, " level="):]
	want := ` level=WARN msg="pause state changed" path=/srv/pause.json entries=2 added="[a b]" err=gone peer=127.0.0.1 raw=ok`
	if got != want {
		t.Errorf("the line is\n%s\nwant\n%s", got, want)
	}
}

// namedBytes is a byte slice of its own type, with no method to format it.
type namedBytes []byte

// keyValuer logs as the text it holds.
type keyValuer string

func (k keyValuer) LogValue() slog.Value { return slog.StringValue(string(k)) }

// TestRunLogWithholdsAPauseIDHoldingKeyText: an entry id added to the pause
// file while the plane serves is named in the change it logs, withheld.
func TestRunLogWithholdsAPauseIDHoldingKeyText(t *testing.T) {
	_, body := fixtureKeyText(t)
	tr := newTree(t)
	collector := newAcceptingCollector(t)
	setEnv(t, "upstreams.0.endpoint", upstream(t))
	setEnv(t, "export.endpoint", collector.url)
	setEnv(t, "listener.address", "127.0.0.1:0")
	setEnv(t, "health.address", "")
	path := tr.withPauseFile(t, pauseClear, servePoll)
	_, stderr := serveInProcess(t, tr)
	changes := strings.Count(stderr.String(), "pause state changed")
	entry := pause.Entry{ID: body, Scope: pause.Scope{Kind: pause.ScopeProvider, Provider: "billing"}, CreatedAt: time.Now(), Reason: "r"}
	if err := pause.Add(context.Background(), path, entry); err != nil {
		t.Fatalf("Add: %v", err)
	}
	waitForChange(t, stderr, changes+1, `added="[`+policykey.KeyTextWithheld+`]"`)
	if holdsKeyWindow(stderr.String(), body) {
		t.Errorf("the plane's log repeats key text read from the pause file:\n%s", stderr.String())
	}
}

// TestRunLogWithholdsKeyTextFromThePauseFile: a member named by a key's body
// line, a schema version that is one and an entry id that is one each reach
// the line the plane logs for the change, withheld.
func TestRunLogWithholdsKeyTextFromThePauseFile(t *testing.T) {
	_, body := fixtureKeyText(t)
	for name, c := range map[string]struct{ doc, line string }{
		"unknown member": {`{"schema_version":"1","entries":[],"` + body + `":1}`, "pause state unknown"},
		"version":        {`{"schema_version":"` + body + `","entries":[]}`, "pause state unknown"},
		"entry id":       {pauseDocument(pauseEntry(body, scopeElsewhere)), "pause state changed"},
	} {
		t.Run(name, func(t *testing.T) {
			tr := newTree(t)
			collector := newAcceptingCollector(t)
			setEnv(t, "upstreams.0.endpoint", upstream(t))
			setEnv(t, "export.endpoint", collector.url)
			setEnv(t, "listener.address", "127.0.0.1:0")
			setEnv(t, "health.address", "")
			path := tr.withPauseFile(t, pauseClear, servePoll)
			_, stderr := serveInProcess(t, tr)
			before := strings.Count(stderr.String(), c.line)
			writePauseFile(t, path, c.doc)
			deadline := time.Now().Add(servePoll + biteMargin)
			for time.Now().Before(deadline) && strings.Count(stderr.String(), c.line) == before {
				time.Sleep(5 * time.Millisecond)
			}
			out := stderr.String()
			if strings.Count(out, c.line) == before {
				t.Fatalf("within %v of the write the plane logged no %q:\n%s", servePoll+biteMargin, c.line, out)
			}
			if holdsKeyWindow(out, body) {
				t.Errorf("run's log repeats key text:\n%s", out)
			}
			if !strings.Contains(out, policykey.KeyTextWithheld) {
				t.Errorf("run's log does not say it withheld key text:\n%s", out)
			}
		})
	}
}

// TestCollectLogWithholdsKeyTextFromARequest: the refusal collect logs for
// a request quotes what the request carried, a record body's unknown field,
// a record body that is not an event and an envelope's unknown member among
// it, with key text withheld.
func TestCollectLogWithholdsKeyTextFromARequest(t *testing.T) {
	_, body := fixtureKeyText(t)
	record := func(line string) string {
		return `{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"body":{"stringValue":` + strconv.Quote(line) + `}}]}]}]}`
	}
	for name, req := range map[string]string{
		"record body unknown field": record(`{"` + body + `":1}`),
		"record body bad value":     record(body),
		"envelope unknown member":   `{"resourceLogs":[],"` + body + `":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			c := startCollect(t, filepath.Join(t.TempDir(), "trail.jsonl"))
			resp, err := http.Post(c.url, "application/json", strings.NewReader(req))
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			c.stop(t)
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("collect answered %d, want %d", resp.StatusCode, http.StatusBadRequest)
			}
			stderr := c.stderr.String()
			if !strings.Contains(stderr, "request refused") {
				t.Fatalf("collect logged no refusal: %s", stderr)
			}
			if holdsKeyWindow(stderr, body) {
				t.Errorf("collect's log repeats key text: %s", stderr)
			}
		})
	}
}
