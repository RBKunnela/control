package supervise

import (
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"google.golang.org/protobuf/proto"
)

// place is where an export holds an event: the export's place in the input
// and the event's in the export.
type place struct{ export, index int }

// placesOf is, by event id, where each export holds the event the run read
// under that id, once per export. A copy of other content is no copy of it.
func (e *evaluation) placesOf() map[string][]place {
	if e.places != nil {
		return e.places
	}
	taken := make(map[string]*controlv1.Event, len(e.rd.events))
	for _, ev := range e.rd.events {
		taken[ev.GetEventId()] = ev
	}
	e.places = map[string][]place{}
	for i, x := range e.in.Exports {
		for j, ev := range x.Events {
			id := ev.GetEventId()
			t, ok := taken[id]
			ps := e.places[id]
			if !ok || len(ps) > 0 && ps[len(ps)-1].export == i || t != ev && !proto.Equal(t, ev) {
				continue
			}
			e.places[id] = append(ps, place{export: i, index: j})
		}
	}
	return e.places
}
