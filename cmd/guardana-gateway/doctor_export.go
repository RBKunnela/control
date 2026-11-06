package main

import (
	"context"
	"fmt"
	"net/url"

	"github.com/guardana/control/internal/gatewayconfig"
)

// export reads the endpoint and says where records will go. It sends
// nothing: a collector that is down must not stop a gateway from starting,
// so its reachability is not a check this makes. A TCP endpoint is warned
// of, since TCP export goes in 0.17; a plaintext one also hands the
// credential to whoever holds its port while the collector is down.
func (d *examination) export(context.Context) (string, string, string) {
	if socket, ok := gatewayconfig.UnixEndpoint(d.cfg.Export.Endpoint); ok {
		return verdictOK, "export", fmt.Sprintf("OTLP/HTTP JSON logs to the unix socket %s, sent only to a collector running as uid %d, %d header(s), at most %d record(s) per request, %d in flight",
			socket, d.cfg.Export.CollectorUID.ID, len(d.cfg.Export.Headers), d.cfg.Export.MaxBatch, d.cfg.Export.InFlight)
	}
	u, err := url.Parse(d.cfg.Export.Endpoint)
	if err != nil || u.Host == "" {
		return verdictFail, "export", fmt.Sprintf("%q is not a URL", d.cfg.Export.Endpoint)
	}
	found := fmt.Sprintf("OTLP/HTTP JSON logs to %s://%s%s, %d header(s), at most %d record(s) per request, %d in flight",
		u.Scheme, u.Host, u.EscapedPath(), len(d.cfg.Export.Headers), d.cfg.Export.MaxBatch, d.cfg.Export.InFlight)
	warning := "       warning: TCP export goes in 0.17; export.endpoint: unix:///path with export.collector_uid sends the credential only to the collector's account"
	if u.Scheme == "http" {
		warning += ", and a plaintext TCP collector hands it to whoever holds " + oneLine(u.Host) + " while it is down"
	}
	writeLine(d.out, warning)
	return verdictOK, "export", found
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
