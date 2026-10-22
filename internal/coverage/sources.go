package coverage

import (
	"fmt"
	"slices"
	"strings"
	"time"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/observe"
)

// trustOrder is the trusts from the weakest.
var trustOrder = []observev1.Trust{
	observev1.Trust_TRUST_SELF_REPORTED, observev1.Trust_TRUST_PLATFORM, observev1.Trust_TRUST_INDEPENDENT,
}

// weaker is the weaker of two trusts, each read as observe reads a record's.
func weaker(a, b observev1.Trust) observev1.Trust {
	a, b = observe.TrustOf(a), observe.TrustOf(b)
	if slices.Index(trustOrder, b) < slices.Index(trustOrder, a) {
		return b
	}
	return a
}

func trustName(t observev1.Trust) string {
	return strings.ToLower(strings.TrimPrefix(observe.TrustOf(t).String(), "TRUST_"))
}

// ownedBy reports whether a record naming source, tenant and project is the
// source's own, as its descriptor names them.
func ownedBy(src *Source, source, tenant, project string) bool {
	d := src.Descriptor
	return source == d.GetSourceId() && tenant == d.GetTenantId() && project == d.GetProjectId()
}

// observationsOf are the source's own observations that name the path as ps
// says: a tool of that name, at that server address when one is given.
func observationsOf(src *Source, ps PathSource) []*observev1.Observation {
	var out []*observev1.Observation
	for _, r := range src.Records {
		o := r.GetObservation()
		subject := o.GetSubject()
		if o == nil || !ownedBy(src, o.GetSource().GetSourceId(), o.GetTenantId(), o.GetProjectId()) ||
			subject.GetKind() != observev1.SubjectKind_SUBJECT_KIND_TOOL || subject.GetName() != ps.Name ||
			ps.ServerAddress != "" && subject.GetServerAddress() != ps.ServerAddress {
			continue
		}
		out = append(out, o)
	}
	return out
}

// sourceLine is one source's state for a path: observed when it is live
// within its heartbeat of now and holds an observation of the path, unknown
// when it is not live, not covered when it was not given or saw nothing.
func sourceLine(ps PathSource, src *Source, now time.Time, absent []string) SourceLine {
	line := SourceLine{SourceID: ps.SourceID}
	if src == nil {
		line.Basis = notGiven(absent)
		return line
	}
	last, heard := observe.LastHeard(src.Descriptor, src.Records)
	when := fmt.Sprintf("last heard %s, heartbeat %d s", last.UTC().Format(time.RFC3339), src.Descriptor.GetHeartbeatSeconds())
	switch observe.LivenessAt(last, heard, src.Descriptor.GetHeartbeatSeconds(), now) {
	case observe.NeverHeard:
		line.State, line.Basis = Unknown, "never heard: no import report with an event time"
		return line
	case observe.Ahead:
		line.State, line.Basis = Unknown, when+": after now, so the clocks disagree"
		return line
	case observe.Lapsed:
		line.State, line.Basis = Unknown, "past its heartbeat: "+when
		return line
	}
	seen := observationsOf(src, ps)
	if len(seen) == 0 {
		line.Basis = "live, and no observation of the path: " + when
		return line
	}
	line.State, line.Basis = Observed, when
	line.Sampled = observe.SamplingOf(src.Descriptor.GetSampling()) != observev1.Sampling_SAMPLING_COMPLETE
	line.Trust = observe.TrustOf(src.Descriptor.GetTrust())
	for _, o := range seen {
		line.Trust = weaker(line.Trust, o.GetSource().GetTrust())
	}
	return line
}

// notGiven is why a source no Source carries covers nothing: no descriptor
// was given for it, or, when some were absent, it may be one of those.
func notGiven(absent []string) string {
	if len(absent) == 0 {
		return "no --source given for it"
	}
	names := make([]string, 0, len(absent))
	for _, a := range absent {
		names = append(names, printable(a))
	}
	return "no --source given for it, or its descriptor is absent: " + strings.Join(names, ", ") +
		"; a removed descriptor covers nothing"
}

// sourceCoverage is the strongest of the path's source lines, the weakest
// trust among the sources that observed it, and whether every one of them
// samples.
func sourceCoverage(lines []SourceLine) (State, observev1.Trust, bool, []string) {
	state := NotCovered
	var trust observev1.Trust
	sampled := true
	var by []string
	for _, l := range lines {
		if l.State > state {
			state, by = l.State, nil
		}
		if l.State == state && state != NotCovered {
			by = append(by, printable(l.SourceID))
		}
		if l.State == Observed {
			if trust == observev1.Trust_TRUST_UNSPECIFIED {
				trust = l.Trust
			}
			trust = weaker(trust, l.Trust)
			sampled = sampled && l.Sampled
		}
	}
	return state, trust, sampled, by
}
