package otel_test

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guardana/control/adapters/otel"
)

// TestTheExportersOwnClientSendsNothingToAnUntrustedCollector: with no client
// of the caller's, as a plane builds it for an https endpoint, the exporter
// sends no request, and so no credential, to a collector whose certificate
// the system does not trust.
func TestTheExportersOwnClientSendsNothingToAnUntrustedCollector(t *testing.T) {
	var seen atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		seen.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	s := openSpool(t, 1<<20)
	mustAppend(t, s, event(1))
	e, err := otel.New(fast(otel.Options{Endpoint: srv.URL + "/v1/logs", InFlight: 1, Timeout: 2 * time.Second,
		Headers: map[string]string{"Authorization": "Bearer s3cret"}}), reader(t, s))
	if err != nil {
		t.Fatal(err)
	}
	runUntil(t, e, func() bool { return e.Stats().RetriedTransport >= 2 })
	if n := seen.Load(); n != 0 {
		t.Errorf("an untrusted collector received %d requests", n)
	}
}
