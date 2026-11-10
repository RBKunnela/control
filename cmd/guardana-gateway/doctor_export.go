package main

import (
	"context"
	"fmt"
	"net/url"

	"github.com/guardana/control/internal/gatewayconfig"
)

// export reads the endpoint and says where records will go. It sends
// nothing: a collector that is down must not stop a gateway from starting,
// so its reachability is not a check this makes. The loader refused any
// endpoint but a unix socket and an https URL.
func (d *examination) export(context.Context) (string, string, string) {
	if socket, ok := gatewayconfig.UnixEndpoint(d.cfg.Export.Endpoint); ok {
		return verdictOK, "export", fmt.Sprintf("OTLP/HTTP JSON logs to the unix socket %s, sent only to a collector running as uid %d, %d header(s), at most %d record(s) per request, %d in flight",
			socket, d.cfg.Export.CollectorUID.ID, len(d.cfg.Export.Headers), d.cfg.Export.MaxBatch, d.cfg.Export.InFlight)
	}
	u, err := url.Parse(d.cfg.Export.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return verdictFail, "export", "the endpoint is neither a unix socket nor an https URL"
	}
	return verdictOK, "export", fmt.Sprintf("OTLP/HTTP JSON logs over TLS to %s://%s%s, %d header(s), at most %d record(s) per request, %d in flight",
		u.Scheme, u.Host, u.EscapedPath(), len(d.cfg.Export.Headers), d.cfg.Export.MaxBatch, d.cfg.Export.InFlight)
}

// collectorUID is the account a unix endpoint's collector runs as, or nil
// where the configuration names none.
func collectorUID(cfg *gatewayconfig.Config) *uint32 {
	if !cfg.Export.CollectorUID.Set {
		return nil
	}
	id := cfg.Export.CollectorUID.ID
	return &id
}
