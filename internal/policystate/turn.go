package policystate

import (
	"context"
	"sync"
)

// turns holds one turn per directory this process locks, by device and inode,
// so every Store of one directory shares it. Entries are never removed: a
// process locks a handful of directories, and a directory that takes over a
// removed one's inode shares only the order of its calls.
var turns sync.Map

type turnKey struct{ dev, ino uint64 }

// turn lets a writer of a directory go before the reads of this process that
// start while it waits. Without it a reader that just released the lock can
// take it again before a waiting writer next tries.
type turn struct {
	mu      sync.Mutex
	writers int
	// free is closed when writers falls to zero.
	free chan struct{}
}

func turnOf(id fileID) *turn {
	t, _ := turns.LoadOrStore(turnKey{dev: id.dev, ino: id.ino}, &turn{})
	return t.(*turn)
}

// read waits until no writer of this process waits for or holds the
// directory, or until ctx ends.
func (t *turn) read(ctx context.Context) error {
	for {
		t.mu.Lock()
		if t.writers == 0 {
			t.mu.Unlock()
			return nil
		}
		free := t.free
		t.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-free:
		}
	}
}

// write counts a writer waiting for or holding the directory and returns
// what ends that, to be called once.
func (t *turn) write() func() {
	t.mu.Lock()
	if t.writers == 0 {
		t.free = make(chan struct{})
	}
	t.writers++
	t.mu.Unlock()
	return func() {
		t.mu.Lock()
		t.writers--
		if t.writers == 0 {
			close(t.free)
		}
		t.mu.Unlock()
	}
}
