package coverage

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/observe"
)

const (
	// MaxUndeclared bounds the undeclared hosts a report names; the rest
	// are counted.
	MaxUndeclared = 256
	// maxPortsPrinted bounds the ports one source's part of a row names.
	maxPortsPrinted = 16
)

// UndeclaredDestination is a host egress sources observed that no egress
// path declares, and each source that did, by source id.
type UndeclaredDestination struct {
	Host    string
	Sources []UndeclaredSource
}

// UndeclaredSource is what one egress source holds of an undeclared host:
// its own connections to it, live or not, since a past connection is still
// one.
type UndeclaredSource struct {
	SourceID string
	// Trust is the weaker of the descriptor's and its connections' trust.
	Trust observev1.Trust
	// Sampled is a source whose descriptor does not say it samples
	// completely.
	Sampled bool
	// Liveness is the source's at the map's time; LastHeard is meaningful
	// unless it is NeverHeard.
	Liveness         observe.Liveness
	LastHeard        time.Time
	HeartbeatSeconds uint32
	Connections      int
	// Ports are the distinct ports seen, ascending; 0 is a connection whose
	// port the log did not give.
	Ports []uint32
}

// undeclared is every host the egress sources given observed that no egress
// path declares to them, sorted by bytes and cut at MaxUndeclared, and how
// many were cut.
func (in Input) undeclared() ([]UndeclaredDestination, int) {
	byHost := map[string][]UndeclaredSource{}
	for i := range in.Sources {
		src := &in.Sources[i]
		if src.Descriptor.GetKind() != observe.KindEgressAccessLog {
			continue
		}
		declared := declaredTo(in.Inventory, src.Descriptor.GetSourceId())
		for host, u := range in.connections(src) {
			if !declared[host] {
				byHost[host] = append(byHost[host], u)
			}
		}
	}
	hosts := slices.Sorted(maps.Keys(byHost))
	cut := max(len(hosts)-MaxUndeclared, 0)
	hosts = hosts[:len(hosts)-cut]
	out := make([]UndeclaredDestination, 0, len(hosts))
	for _, h := range hosts {
		srcs := byHost[h]
		slices.SortFunc(srcs, func(a, b UndeclaredSource) int { return cmp.Compare(a.SourceID, b.SourceID) })
		out = append(out, UndeclaredDestination{Host: h, Sources: srcs})
	}
	return out, cut
}

// declaredTo is the hosts the inventory declares to a source: every egress
// path's host, and the name each egress path naming the source gives it.
func declaredTo(inv *Inventory, sourceID string) map[string]bool {
	declared := map[string]bool{}
	for _, p := range inv.Paths {
		if p.Kind != KindEgress {
			continue
		}
		declared[p.Host] = true
		for _, ps := range p.Sources {
			if ps.SourceID == sourceID {
				declared[ps.Name] = true
			}
		}
	}
	return declared
}

// connections is, per host, what the source's own connections say of it.
func (in Input) connections(src *Source) map[string]UndeclaredSource {
	d := src.Descriptor
	last, heard := observe.LastHeard(d, src.Records)
	base := UndeclaredSource{
		SourceID: d.GetSourceId(), Trust: observe.TrustOf(d.GetTrust()),
		Sampled:  observe.SamplingOf(d.GetSampling()) != observev1.Sampling_SAMPLING_COMPLETE,
		Liveness: observe.LivenessAt(last, heard, d.GetHeartbeatSeconds(), in.Now), LastHeard: last,
		HeartbeatSeconds: d.GetHeartbeatSeconds(),
	}
	out := map[string]UndeclaredSource{}
	ports := map[string]map[uint32]bool{}
	for _, r := range src.Records {
		o := r.GetObservation()
		if o == nil || o.GetSubject().GetKind() != observev1.SubjectKind_SUBJECT_KIND_CONNECTION ||
			!ownedBy(src, o.GetSource().GetSourceId(), o.GetTenantId(), o.GetProjectId()) {
			continue
		}
		host := o.GetSubject().GetName()
		u, ok := out[host]
		if !ok {
			u, ports[host] = base, map[uint32]bool{}
		}
		u.Trust = weaker(u.Trust, o.GetSource().GetTrust())
		u.Connections++
		ports[host][o.GetConnection().GetPort()] = true
		out[host] = u
	}
	for host, u := range out {
		u.Ports = slices.Sorted(maps.Keys(ports[host]))
		out[host] = u
	}
	return out
}

// undeclaredLines prints a row per undeclared host, and one line counting
// the hosts cut.
func undeclaredLines(rows []UndeclaredDestination, cut int) []string {
	out := make([]string, 0, len(rows)+1)
	for _, d := range rows {
		parts := make([]string, 0, len(d.Sources))
		for _, u := range d.Sources {
			parts = append(parts, "by "+printable(u.SourceID)+": "+undeclaredSource(u))
		}
		out = append(out, fmt.Sprintf("undeclared egress %s: observed %s; %s", printable(d.Host), strings.Join(parts, "; "), NoPlaneDecidesEgress))
	}
	if cut > 0 {
		out = append(out, fmt.Sprintf("undeclared egress: %d more hosts not printed", cut))
	}
	return out
}

func undeclaredSource(u UndeclaredSource) string {
	s := trustName(u.Trust) + sampledWord(u.Sampled) + ", " + livenessText(u.Liveness, u.LastHeard, u.HeartbeatSeconds)
	noun := "connections"
	if u.Connections == 1 {
		noun = "connection"
	}
	return fmt.Sprintf("%s; %d %s, %s", s, u.Connections, noun, portList(u.Ports))
}

func portList(ports []uint32) string {
	shown := ports[:min(len(ports), maxPortsPrinted)]
	names := make([]string, 0, len(shown))
	for _, p := range shown {
		if p == 0 {
			names = append(names, "unknown")
			continue
		}
		names = append(names, fmt.Sprint(p))
	}
	word := "ports "
	if len(ports) == 1 {
		word = "port "
	}
	s := word + strings.Join(names, ", ")
	if more := len(ports) - len(shown); more > 0 {
		s += fmt.Sprintf(" and %d more", more)
	}
	return s
}
