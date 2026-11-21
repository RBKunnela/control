package trailfile

import (
	"fmt"
	"strconv"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// queryRecord is the query as the export's header repeats it.
type queryRecord struct {
	After    string   `json:"after,omitempty"`
	Limit    int      `json:"limit"`
	MaxBytes int64    `json:"max_bytes,omitempty"`
	Request  []string `json:"request,omitempty"`
	Run      []string `json:"run,omitempty"`
	Tenant   []string `json:"tenant,omitempty"`
	Project  []string `json:"project,omitempty"`
	Kind     []string `json:"kind,omitempty"`
}

func (q Query) echo() queryRecord {
	return queryRecord{After: q.After, Limit: q.Limit, MaxBytes: q.MaxBytes, Request: q.Requests,
		Run: q.Runs, Tenant: q.Tenants, Project: q.Projects, Kind: q.Kinds}
}

// filter is a query's filters as sets. An empty set passes every value.
type filter struct {
	requests, runs, tenants, projects map[string]bool
	kinds                             map[controlv1.EventKind]bool
	// bound is the log's binding, which every event is of.
	bound binding
}

func (f filter) match(ev *controlv1.Event) bool {
	in := func(set map[string]bool, v string) bool { return len(set) == 0 || set[v] }
	return in(f.requests, ev.GetRequestId()) && in(f.runs, ev.GetRunId()) && in(f.tenants, ev.GetTenantId()) &&
		in(f.projects, ev.GetProjectId()) && (len(f.kinds) == 0 || f.kinds[ev.GetKind()])
}

// filter checks the query and returns its filters. A kind is named as the
// contract spells it, and the unspecified one names no event anyone means.
func (q Query) filter() (filter, error) {
	switch {
	case q.Limit < 1 || q.Limit > MaxExportLimit:
		return filter{}, fmt.Errorf("%w: limit %d, want 1 to %d", ErrQuery, q.Limit, MaxExportLimit)
	case q.MaxBytes < 0:
		return filter{}, fmt.Errorf("%w: byte bound %d", ErrQuery, q.MaxBytes)
	}
	var f filter
	for _, set := range []struct {
		name   string
		values []string
		into   *map[string]bool
	}{{"request", q.Requests, &f.requests}, {"run", q.Runs, &f.runs}, {"tenant", q.Tenants, &f.tenants}, {"project", q.Projects, &f.projects}} {
		for _, v := range set.values {
			if v == "" {
				return filter{}, fmt.Errorf("%w: an empty %s", ErrQuery, set.name)
			}
			if *set.into == nil {
				*set.into = map[string]bool{}
			}
			(*set.into)[v] = true
		}
	}
	for _, name := range q.Kinds {
		n, ok := controlv1.EventKind_value[name]
		if !ok || n == int32(controlv1.EventKind_EVENT_KIND_UNSPECIFIED) {
			return filter{}, fmt.Errorf("%w: kind %s is not one the contract names", ErrQuery, strconv.Quote(name))
		}
		if f.kinds == nil {
			f.kinds = map[controlv1.EventKind]bool{}
		}
		f.kinds[controlv1.EventKind(n)] = true
	}
	return f, nil
}
