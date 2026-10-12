package enforce

import (
	"sync"
	"sync/atomic"

	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	"github.com/guardana/control/internal/adapterkit"
)

// counters are the adapter's own counts. Refusals are kept by the position
// of their code in the contract's enumeration and of their cause in
// gateway.RunCauses, so no label ever names a run, a key or a handle.
type counters struct {
	executed, blocked, pending    atomic.Uint64
	completed, aborted, abandoned atomic.Uint64
	recordsFailed                 atomic.Uint64
	codes                         []atomic.Uint64
	runs                          *adapterkit.RunCounter
}

func newCounters() *counters {
	return &counters{codes: make([]atomic.Uint64, len(enforcev1alpha1.ErrorCode_name)), runs: adapterkit.NewRunCounter()}
}

func (c *counters) refused(code enforcev1alpha1.ErrorCode) {
	if int(code) >= 0 && int(code) < len(c.codes) {
		c.codes[code].Add(1)
	}
}

func (c *counters) snapshot() Stats {
	s := Stats{
		Executed: c.executed.Load(), Blocked: c.blocked.Load(), Pending: c.pending.Load(),
		Completed: c.completed.Load(), Aborted: c.aborted.Load(), Abandoned: c.abandoned.Load(),
		RecordsFailed: c.recordsFailed.Load(),
		RunsRefused:   c.runs.Snapshot(), Refused: map[enforcev1alpha1.ErrorCode]uint64{},
	}
	for i := range c.codes {
		s.Refused[enforcev1alpha1.ErrorCode(i)] = c.codes[i].Load()
	}
	return s
}

// flights counts the requests a Shutdown waits for. Once shut it lets none
// in, so a request cannot slip in after the wait read zero.
type flights struct {
	mu   sync.Mutex
	n    int64
	idle chan struct{}
}

func (f *flights) enter() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.idle != nil {
		return false
	}
	f.n++
	return true
}

func (f *flights) leave() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n--
	if f.n == 0 && f.idle != nil {
		close(f.idle)
	}
}

func (f *flights) shut() <-chan struct{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.idle == nil {
		f.idle = make(chan struct{})
		if f.n == 0 {
			close(f.idle)
		}
	}
	return f.idle
}
