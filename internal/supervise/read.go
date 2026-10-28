package supervise

import (
	"fmt"
	"strconv"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/observe"
	"google.golang.org/protobuf/proto"
)

// Why an event or an observation was read and left out.
const (
	outNotRecord      = "not a record"
	outAnotherRun     = "another run"
	outAnotherTenant  = "another tenant"
	outAnotherProject = "another project"
	outAnotherSource  = "another source"
	outNotClaimed     = "basis not claimed"
	outNotTool        = "not a tool call"
	outDuplicate      = "duplicate"
	outConflict       = "conflicting id"
)

// read is what belongs to the run, and what was left out of it.
type read struct {
	events []*controlv1.Event
	// exportOf is the place in the input of the export each event was taken
	// from.
	exportOf map[*controlv1.Event]int
	// doubtful holds the request ids an event id with two contents names, and
	// those of the run's project an event left out for its run names.
	doubtful map[string]bool
	project  string
	obs      []*observev1.Observation
	// obsSource is each taken observation's source, by observation id.
	obsSource map[string]*Source
	// obsDoubt holds the observation ids read with two contents.
	obsDoubt map[string]bool
	// spans holds, by source, the observations a span graph is built from:
	// those taken, and the run's observations of a subject other than a tool.
	spans  map[*Source][]*observev1.Observation
	counts *findingv1alpha1.ReadCounts
	// runs are the runs read, all of tenant.
	runs   map[string]bool
	tenant string
}

func newRead(runs map[string]bool, tenant string) *read {
	return &read{
		runs: runs, tenant: tenant,
		doubtful: map[string]bool{}, exportOf: map[*controlv1.Event]int{}, obsSource: map[string]*Source{}, obsDoubt: map[string]bool{},
		spans:  map[*Source][]*observev1.Observation{},
		counts: &findingv1alpha1.ReadCounts{EventsLeftOut: map[string]uint64{}, ObservationsLeftOut: map[string]uint64{}},
	}
}

// takeEvents keeps the events of the runs read in their tenant, each event
// id once. A second copy of an event is left out; a second content under one
// event id puts both requests in doubt, and so does an event of the tenant
// left out for its run: the events of its request that are taken would read
// as a whole trail.
func (r *read) takeEvents(exports []Export) error {
	seen := map[string]*controlv1.Event{}
	elsewhere := map[projectRequest]bool{}
	for i, x := range exports {
		if x.Whole {
			r.counts.ExportsWhole++
		} else {
			r.counts.ExportsNotWhole++
		}
		for _, ev := range x.Events {
			why := r.eventOutside(ev)
			if first, ok := seen[ev.GetEventId()]; ok && why == "" {
				why = outDuplicate
				if !proto.Equal(first, ev) {
					why = outConflict
					r.doubtful[first.GetRequestId()], r.doubtful[ev.GetRequestId()] = true, true
				}
			}
			if why == outAnotherRun && ev.GetTenantId() == r.tenant {
				elsewhere[projectRequest{ev.GetProjectId(), ev.GetRequestId()}] = true
			}
			if why != "" {
				r.counts.EventsLeftOut[why]++
				continue
			}
			seen[ev.GetEventId()] = ev
			r.events = append(r.events, ev)
			r.exportOf[ev] = i
		}
	}
	r.counts.EventsTaken = uint64(len(r.events))
	if err := r.takeProject(); err != nil {
		return err
	}
	r.doubtElsewhere(elsewhere)
	return nil
}

// projectRequest names one request: a request id is unique only within a
// project.
type projectRequest struct{ project, request string }

// doubtElsewhere puts in doubt each request of the run's project that an
// event left out for its run names.
func (r *read) doubtElsewhere(elsewhere map[projectRequest]bool) {
	for k := range elsewhere {
		if k.project == r.project {
			r.doubtful[k.request] = true
		}
	}
}

func (r *read) eventOutside(ev *controlv1.Event) string {
	switch {
	case ev == nil:
		return outNotRecord
	case !r.runs[ev.GetRunId()]:
		return outAnotherRun
	case ev.GetTenantId() != r.tenant:
		return outAnotherTenant
	}
	return ""
}

// takeProject names the one project the run's events were recorded in. A
// finding and a report name one project, so a run recorded in two is refused
// rather than judged as one, and so is an event that names none, which would
// otherwise take whichever project another event names.
func (r *read) takeProject() error {
	for _, ev := range r.events {
		switch p := ev.GetProjectId(); {
		case p == "":
			return ErrInput.with("an event of the run names no project")
		case r.project == "":
			r.project = p
		case p != r.project:
			return ErrInput.with("the run's events name more than one project")
		}
	}
	return nil
}

// checkSources refuses a source whose tenant is not the run's, or whose
// project is not the one the run's events name: observations are taken
// under the run's identity and liveness and doubt read under the source's,
// so the two must be one. With no event read no rule is checked, and only
// the tenant is held.
func (r *read) checkSources(sources []Source) error {
	for _, s := range sources {
		switch {
		case s.Tenant != r.tenant:
			return ErrInput.with(fmt.Sprintf("source %s is of tenant %s, the run of tenant %s",
				strconv.Quote(s.SourceID), strconv.Quote(s.Tenant), strconv.Quote(r.tenant)))
		case len(r.events) > 0 && s.Project != r.project:
			return ErrInput.with(fmt.Sprintf("source %s is of project %s, the run's events of project %s",
				strconv.Quote(s.SourceID), strconv.Quote(s.Project), strconv.Quote(r.project)))
		}
	}
	return nil
}

// takeObservations keeps the tool observations that claim a run read, in
// its tenant and project, each observation id once.
func (r *read) takeObservations(sources []Source) {
	digests := map[string]string{}
	for i := range sources {
		src := &sources[i]
		for _, o := range src.Observations {
			why := r.observationOutside(o, src)
			if why == outNotTool {
				r.spans[src] = append(r.spans[src], o)
			}
			id := o.GetObservationId()
			if d, ok := digests[id]; ok && why == "" {
				why = outDuplicate
				if d != observe.ContentDigest(o) || d == "" {
					why = outConflict
					r.obsDoubt[id] = true
				}
			}
			if why != "" {
				r.counts.ObservationsLeftOut[why]++
				continue
			}
			digests[id] = observe.ContentDigest(o)
			r.obsSource[id] = src
			r.obs = append(r.obs, o)
			r.spans[src] = append(r.spans[src], o)
		}
	}
	r.counts.ObservationsTaken = uint64(len(r.obs))
}

// observationOutside says why o is not a tool observation of a run read.
// The subject is judged last, so an observation outside only by it is the
// run's.
func (r *read) observationOutside(o *observev1.Observation, src *Source) string {
	c := o.GetCorrelation()
	switch {
	case o == nil:
		return outNotRecord
	case o.GetSource().GetSourceId() != src.SourceID:
		return outAnotherSource
	case observe.BasisOf(c.GetBasis()) != observev1.Basis_BASIS_CLAIMED:
		return outNotClaimed
	case !r.runs[c.GetRunId()]:
		return outAnotherRun
	case o.GetTenantId() != r.tenant:
		return outAnotherTenant
	case o.GetProjectId() != r.project:
		return outAnotherProject
	case o.GetSubject().GetKind() != observev1.SubjectKind_SUBJECT_KIND_TOOL:
		return outNotTool
	}
	return ""
}
