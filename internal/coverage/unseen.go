package coverage

import (
	"fmt"
	"time"

	"github.com/guardana/control/internal/observe"
)

// UnseenSource is an egress source given that is not live at the map's time:
// the connections since its last import are ones nobody saw, whether a path
// names the source or not.
type UnseenSource struct {
	SourceID string
	// Liveness is the source's at the map's time, never Live; LastHeard is
	// meaningful unless it is NeverHeard.
	Liveness         observe.Liveness
	LastHeard        time.Time
	HeartbeatSeconds uint32
}

// unseen is a row for every egress source given that is not live, in the
// order the sources were given.
func (in Input) unseen() []UnseenSource {
	var out []UnseenSource
	for i := range in.Sources {
		d := in.Sources[i].Descriptor
		if d.GetKind() != observe.KindEgressAccessLog {
			continue
		}
		last, heard := observe.LastHeard(d, in.Sources[i].Records)
		if l := observe.LivenessAt(last, heard, d.GetHeartbeatSeconds(), in.Now); l != observe.Live {
			out = append(out, UnseenSource{SourceID: d.GetSourceId(), Liveness: l, LastHeard: last, HeartbeatSeconds: d.GetHeartbeatSeconds()})
		}
	}
	return out
}

// unseenLines prints a row per unseen source.
func unseenLines(rows []UnseenSource) []string {
	out := make([]string, 0, len(rows))
	for _, u := range rows {
		out = append(out, fmt.Sprintf("unseen egress by %s: %s; connections since its last import are unseen; %s",
			printable(u.SourceID), livenessText(u.Liveness, u.LastHeard, u.HeartbeatSeconds), NoPlaneDecidesEgress))
	}
	return out
}

// livenessText is a source's liveness as a row prints it.
func livenessText(l observe.Liveness, last time.Time, heartbeatSeconds uint32) string {
	when := heardAt(last, heartbeatSeconds)
	switch l {
	case observe.NeverHeard:
		return "never heard"
	case observe.Lapsed:
		return "past its heartbeat: " + when
	case observe.Ahead:
		return when + ": after now, so the clocks disagree"
	}
	return when
}
