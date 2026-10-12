package enforce

import (
	"crypto/rand"
	"encoding/hex"
	"slices"
	"sync"
	"time"

	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	"github.com/guardana/control/internal/gateway"
)

// handleBytes is a handle's length before encoding: 128 bits.
const handleBytes = 16

type state uint8

const (
	// stateMinting is an execution whose EXECUTE is being written. Only its
	// client can take it, so no sweep or shutdown abandons an execution
	// before its client is told of it; the admit settles it once the answer
	// is out.
	stateMinting state = iota
	stateOpen
	// stateClosing is an execution a complete, an abort, the sweep or a
	// shutdown took and has not yet finished closing.
	stateClosing
	stateSpent
)

// entry is one handle: the execution it names, whose run it is, and how it
// ended once it did. A spent entry keeps its run, expiry and ending only.
type entry struct {
	run     string
	d       gateway.Disposition
	expires time.Time
	key     string
	state   state
	ending  enforcev1alpha1.Ending
}

type keyRef struct{ run, key string }

// taken is an execution handed to whoever closes it.
type taken struct {
	id string
	e  *entry
}

// handles is the adapter's record of every handle it minted, every request
// key it holds and how many executions each run holds open. A spent handle
// is kept, up to maxSpent of them, to answer HANDLE_SPENT; the oldest one
// past the bound is forgotten and answers HANDLE_UNKNOWN, which refuses as
// firmly.
type handles struct {
	mu        sync.Mutex
	maxSpent  int
	maxPerRun int
	byID      map[string]*entry
	keys      map[keyRef]bool
	perRun    map[string]int
	spent     []string
	shut      bool
}

func newHandles(maxSpent, maxPerRun int) *handles {
	return &handles{
		maxSpent: maxSpent, maxPerRun: maxPerRun,
		byID: map[string]*entry{}, keys: map[keyRef]bool{}, perRun: map[string]int{},
	}
}

// reserve takes one of run's open slots and its request key before the
// pipeline is asked. It refuses with DUPLICATE_REQUEST a key a request in
// flight or an open execution of run holds, and with UNAVAILABLE a run that
// holds maxPerRun slots, its admits in flight included. No key reserves no
// key.
func (h *handles) reserve(run, key string) enforcev1alpha1.ErrorCode {
	h.mu.Lock()
	defer h.mu.Unlock()
	ref := keyRef{run, key}
	switch {
	case key != "" && h.keys[ref]:
		return enforcev1alpha1.ErrorCode_ERROR_CODE_DUPLICATE_REQUEST
	case h.perRun[run] >= h.maxPerRun:
		return enforcev1alpha1.ErrorCode_ERROR_CODE_UNAVAILABLE
	}
	if key != "" {
		h.keys[ref] = true
	}
	h.perRun[run]++
	return 0
}

// release gives back what reserve took for an admit that handed out nothing.
func (h *handles) release(run, key string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.free(run, key)
}

func (h *handles) free(run, key string) {
	if key != "" {
		delete(h.keys, keyRef{run, key})
	}
	if h.perRun[run]--; h.perRun[run] <= 0 {
		delete(h.perRun, run)
	}
}

// mint records e, minting, under a fresh handle from the operating system's
// random source, never from anything in the request. It refuses once
// shutdown began, so nothing is handed out that nobody would abandon.
func (h *handles) mint(e *entry) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.shut {
		return "", false
	}
	e.state = stateMinting
	var raw [handleBytes]byte
	for {
		_, _ = rand.Read(raw[:]) // crypto/rand.Read never returns an error and always fills raw
		id := hex.EncodeToString(raw[:])
		if _, taken := h.byID[id]; !taken {
			h.byID[id] = e
			return id, true
		}
	}
}

// take hands the open execution id names to the caller, which closes it and
// then calls spend. A handle unknown, of another run or expired at now is
// HANDLE_UNKNOWN, whatever else is true of it; a spent one is HANDLE_SPENT
// with its ending, and one being closed is HANDLE_SPENT with no ending yet.
func (h *handles) take(id, run string, now time.Time) (*entry, enforcev1alpha1.ErrorCode, enforcev1alpha1.Ending) {
	h.mu.Lock()
	defer h.mu.Unlock()
	e, ok := h.byID[id]
	switch {
	case !ok || e.run != run || !now.Before(e.expires):
		return nil, enforcev1alpha1.ErrorCode_ERROR_CODE_HANDLE_UNKNOWN, 0
	case e.state != stateOpen && e.state != stateMinting:
		return nil, enforcev1alpha1.ErrorCode_ERROR_CODE_HANDLE_SPENT, e.ending
	}
	e.state = stateClosing
	return e, 0, 0
}

// settle opens e once its EXECUTE is out, unless its client took it already.
// It reports whether a shutdown began meanwhile, in which case e is taken
// for the caller to abandon, as the shutdown abandoned every open one.
func (h *handles) settle(e *entry) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if e.state != stateMinting {
		return false
	}
	if h.shut {
		e.state = stateClosing
		return true
	}
	e.state = stateOpen
	return false
}

// spend records how the execution of id ended, lets go of the execution,
// frees its request key and its run's slot, and forgets the oldest spent
// handle past the bound.
func (h *handles) spend(id string, e *entry, ending enforcev1alpha1.Ending) {
	h.mu.Lock()
	defer h.mu.Unlock()
	e.state, e.ending, e.d = stateSpent, ending, gateway.Disposition{}
	h.free(e.run, e.key)
	h.spent = append(h.spent, id)
	for len(h.spent) > h.maxSpent {
		delete(h.byID, h.spent[0])
		h.spent = h.spent[1:]
	}
}

// expired takes up to limit open executions expired at now, earliest expiry
// first, and forgets every spent handle expired at now.
func (h *handles) expired(now time.Time, limit int) []taken {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.spent = slices.DeleteFunc(h.spent, func(id string) bool {
		if e, ok := h.byID[id]; !ok || !now.Before(e.expires) {
			delete(h.byID, id)
			return true
		}
		return false
	})
	var out []taken
	for id, e := range h.byID {
		if e.state == stateOpen && !now.Before(e.expires) {
			out = append(out, taken{id, e})
		}
	}
	slices.SortFunc(out, func(a, b taken) int { return a.e.expires.Compare(b.e.expires) })
	if len(out) > limit {
		out = out[:limit]
	}
	for _, t := range out {
		t.e.state = stateClosing
	}
	return out
}

// shutdown refuses every later mint and takes every open execution; one
// being minted is left to its admit, which settles it.
func (h *handles) shutdown() []taken {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.shut = true
	var out []taken
	for id, e := range h.byID {
		if e.state == stateOpen {
			e.state = stateClosing
			out = append(out, taken{id, e})
		}
	}
	return out
}

func (h *handles) open() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	var n int
	for _, e := range h.byID {
		if e.state != stateSpent {
			n++
		}
	}
	return n
}
