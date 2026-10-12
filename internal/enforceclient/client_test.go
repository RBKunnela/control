package enforceclient_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	"github.com/guardana/control/internal/enforceclient"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	execute  = `{"outcome":"OUTCOME_EXECUTE","execution":{"handle":"h-1","authorizedArguments":"eyJhIjoxfQ=="}}`
	recorded = `{"ending":"ENDING_RECORDED"}`
)

func answer(path string, status int, raw string) scripted {
	return scripted{For: path, Status: status, Raw: &raw}
}

func client(t *testing.T, socket string, timeout time.Duration) *enforceclient.Client {
	t.Helper()
	c, err := enforceclient.New(enforceclient.Config{Socket: socket, Token: "tok", Timeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func scriptedClient(t *testing.T, answers ...scripted) (*enforceclient.Client, *receiver) {
	t.Helper()
	r := &receiver{answers: answers, cancel: func() {}}
	return client(t, serve(t, r), 5*time.Second), r
}

func untouched(t *testing.T) enforceclient.Exec {
	return func(context.Context, []byte) (enforceclient.Result, error) {
		t.Error("the tool was run")
		return enforceclient.Result{}, nil
	}
}

func succeed(context.Context, []byte) (enforceclient.Result, error) {
	return enforceclient.Result{Status: enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_SUCCESS}, nil
}

func TestNewRefusesAnIncompleteConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  enforceclient.Config
		want error
	}{
		{"no socket", enforceclient.Config{Token: "t", Timeout: time.Second}, enforceclient.ErrNoSocket},
		{"no token", enforceclient.Config{Socket: "s", Timeout: time.Second}, enforceclient.ErrNoToken},
		{"no timeout", enforceclient.Config{Socket: "s", Token: "t"}, enforceclient.ErrNoTimeout},
		{"negative timeout", enforceclient.Config{Socket: "s", Token: "t", Timeout: -time.Second}, enforceclient.ErrNoTimeout},
		{"shortest timeout", enforceclient.Config{Socket: "s", Token: "t", Timeout: time.Nanosecond}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := enforceclient.New(tc.cfg)
			if !errors.Is(err, tc.want) || (err == nil) != (c != nil) {
				t.Fatalf("New = %v, %v; want %v", c, err, tc.want)
			}
		})
	}
}

func TestAnAnswerPastItsBoundIsNotRead(t *testing.T) {
	if enforceclient.MaxAnswerBytes != 262144 {
		t.Fatalf("MaxAnswerBytes = %d, want 262144", enforceclient.MaxAnswerBytes)
	}
	padded := func(n int) string { return execute + strings.Repeat(" ", n-len(execute)) }

	c, _ := scriptedClient(t, answer(enforceclient.PathAdmit, 200, padded(262144)), answer(enforceclient.PathComplete, 200, recorded))
	if a, err := c.Call(context.Background(), "t", []byte(`{"a":1}`), succeed); err != nil || !a.Ran {
		t.Fatalf("an answer at the bound: ran %v, %v", a.Ran, err)
	}

	c, r := scriptedClient(t, answer(enforceclient.PathAdmit, 200, padded(262145)))
	a, err := c.Call(context.Background(), "t", []byte(`{"a":1}`), untouched(t))
	if !errors.Is(err, enforceclient.ErrMalformedAnswer) || a.Ran || len(r.requests()) != 1 {
		t.Fatalf("an answer one byte past the bound: ran %v, %d requests, %v", a.Ran, len(r.requests()), err)
	}
}

func TestARequestIsBoundedByTheTimeout(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	silent := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release })
	c := client(t, serve(t, silent), 100*time.Millisecond)

	done := make(chan error, 1)
	go func() {
		_, err := c.Call(context.Background(), "t", []byte(`{"a":1}`), untouched(t))
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, enforceclient.ErrTransport) {
			t.Fatalf("Call = %v, want ErrTransport", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Call still waiting for a receiver that never answers")
	}
}

func TestARedirectIsNotFollowed(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	h := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		paths = append(paths, req.URL.Path)
		mu.Unlock()
		if req.URL.Path == enforceclient.PathAdmit {
			http.Redirect(w, req, "/elsewhere", http.StatusTemporaryRedirect)
			return
		}
		_, _ = io.WriteString(w, execute)
	})
	c := client(t, serve(t, h), 5*time.Second)
	_, err := c.Call(context.Background(), "t", []byte(`{"a":1}`), untouched(t))
	mu.Lock()
	defer mu.Unlock()
	if !errors.Is(err, enforceclient.ErrMalformedAnswer) || len(paths) != 1 {
		t.Fatalf("Call = %v after requests to %v; want ErrMalformedAnswer after one", err, paths)
	}
}

func TestAnExecuteTheClientCannotActOnSendsNothing(t *testing.T) {
	for name, body := range map[string]string{
		"no handle":               `{"outcome":"OUTCOME_EXECUTE","execution":{"authorizedArguments":"eyJhIjoxfQ=="}}`,
		"no execution":            `{"outcome":"OUTCOME_EXECUTE"}`,
		"an error body under 200": `{"code":"ERROR_CODE_UNAVAILABLE"}`,
	} {
		t.Run(name, func(t *testing.T) {
			c, r := scriptedClient(t, answer(enforceclient.PathAdmit, 200, body))
			a, err := c.Call(context.Background(), "t", []byte(`{"a":1}`), untouched(t))
			if !errors.Is(err, enforceclient.ErrMalformedAnswer) || a.Ran || len(r.requests()) != 1 {
				t.Fatalf("ran %v, %d requests, %v", a.Ran, len(r.requests()), err)
			}
		})
	}
}

func TestAStatusIsReportedOnlyWhenTheToolCouldTell(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status enforcev1alpha1.CompletionStatus
		err    error
		want   string
	}{
		{"declared", enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_CANCELLED, nil, "COMPLETION_STATUS_CANCELLED"},
		{"undeclared number", 42, nil, "COMPLETION_STATUS_UNKNOWN"},
		{"unspecified", 0, nil, "COMPLETION_STATUS_UNKNOWN"},
		{"success with an error", enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_SUCCESS, errors.New("lost"), "COMPLETION_STATUS_UNKNOWN"},
		{"timeout with an error", enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_TIMEOUT, errors.New("lost"), "COMPLETION_STATUS_TIMEOUT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, r := scriptedClient(t, answer(enforceclient.PathAdmit, 200, execute), answer(enforceclient.PathComplete, 200, recorded))
			_, err := c.Call(context.Background(), "t", []byte(`{"a":1}`), func(context.Context, []byte) (enforceclient.Result, error) {
				return enforceclient.Result{Status: tc.status}, tc.err
			})
			if !errors.Is(err, tc.err) {
				t.Fatalf("Call = %v, want the tool's error %v", err, tc.err)
			}
			got := r.requests()
			if len(got) != 2 || !strings.Contains(string(got[1].body), `"`+tc.want+`"`) {
				t.Fatalf("requests %q, want a complete with %s", got, tc.want)
			}
		})
	}
}

func TestTheToolCannotChangeWhatCompleteReportsAsSent(t *testing.T) {
	c, r := scriptedClient(t, answer(enforceclient.PathAdmit, 200, execute), answer(enforceclient.PathComplete, 200, recorded))
	_, err := c.Call(context.Background(), "t", []byte(`{"a":1}`), func(_ context.Context, b []byte) (enforceclient.Result, error) {
		copy(b, "XXXXXXX")
		return enforceclient.Result{Status: enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_SUCCESS}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var sent enforcev1alpha1.CompleteRequest
	if err := protojson.Unmarshal(r.requests()[1].body, &sent); err != nil {
		t.Fatal(err)
	}
	if string(sent.GetSentArguments()) != `{"a":1}` {
		t.Fatalf("sent_arguments %q, want the authorized bytes", sent.GetSentArguments())
	}
}

func TestOnlyRecordedSaysTheRecordLanded(t *testing.T) {
	for _, ending := range []string{`"ENDING_UNRECORDED"`, `"ENDING_ABANDONED"`, `9`, `"ENDING_UNSPECIFIED"`} {
		t.Run(ending, func(t *testing.T) {
			c, _ := scriptedClient(t, answer(enforceclient.PathAdmit, 200, execute), answer(enforceclient.PathComplete, 200, `{"ending":`+ending+`}`))
			a, err := c.Call(context.Background(), "t", []byte(`{"a":1}`), succeed)
			if !errors.Is(err, enforceclient.ErrNotRecorded) || !a.Ran {
				t.Fatalf("ran %v, %v; want ErrNotRecorded after the tool ran", a.Ran, err)
			}
		})
	}
}

func TestARefusedAbortStillReportsTheAbort(t *testing.T) {
	c, r := scriptedClient(t,
		answer(enforceclient.PathAdmit, 200, `{"outcome":"OUTCOME_EXECUTE","execution":{"handle":"h-1","authorizedArguments":"eyJhIjoxfQ==","obligations":[{"type":"x"}]}}`),
		answer(enforceclient.PathAbort, 404, `{"code":"ERROR_CODE_HANDLE_UNKNOWN"}`))
	a, err := c.Call(context.Background(), "t", []byte(`{"a":1}`), untouched(t))
	var refusal *enforceclient.RefusalError
	if !errors.Is(err, enforceclient.ErrAborted) || !errors.As(err, &refusal) || refusal.Code != enforcev1alpha1.ErrorCode_ERROR_CODE_HANDLE_UNKNOWN || a.Ran || len(r.requests()) != 2 {
		t.Fatalf("ran %v, %d requests, %v", a.Ran, len(r.requests()), err)
	}
}

func TestAnEndedContextSendsNothing(t *testing.T) {
	c, r := scriptedClient(t, answer(enforceclient.PathAdmit, 200, execute))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Call(ctx, "t", []byte(`{"a":1}`), untouched(t)); !errors.Is(err, context.Canceled) || len(r.requests()) != 0 {
		t.Fatalf("Call = %v after %d requests", err, len(r.requests()))
	}
}

func TestOneClientServesConcurrentCalls(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		switch req.URL.Path {
		case enforceclient.PathAdmit:
			var in enforcev1alpha1.AdmitRequest
			if err := protojson.Unmarshal(body, &in); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = fmt.Fprintf(w, `{"outcome":"OUTCOME_EXECUTE","execution":{"handle":%q,"authorizedArguments":%q}}`,
				in.GetTool(), base64.StdEncoding.EncodeToString(in.GetArguments()))
		case enforceclient.PathComplete:
			_, _ = io.WriteString(w, recorded)
		}
	})
	c := client(t, serve(t, h), 5*time.Second)
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			want := fmt.Sprintf(`{"n":%d}`, i)
			_, err := c.Call(context.Background(), fmt.Sprint(i), []byte(want), func(_ context.Context, b []byte) (enforceclient.Result, error) {
				if string(b) != want {
					t.Errorf("call %d got %q", i, b)
				}
				return enforceclient.Result{Status: enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_SUCCESS}, nil
			})
			if err != nil {
				t.Errorf("call %d: %v", i, err)
			}
		}()
	}
	wg.Wait()
}
