package policystate

import (
	"context"
	"errors"
	"os"
	"time"
)

// lockRetry is how often a lock another open file holds is tried again.
const lockRetry = 2 * time.Millisecond

// begin holds the directory open for one call, refusing a closed handle, an
// ended context and a directory that changed, and returns what ends the call.
func (d *dir) begin(ctx context.Context) (func(), error) {
	if d == nil {
		return nil, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d.mu.RLock()
	if !d.open {
		d.mu.RUnlock()
		return nil, ErrClosed
	}
	if err := d.judge(); err != nil {
		d.mu.RUnlock()
		return nil, err
	}
	return d.mu.RUnlock, nil
}

// lock takes the directory's exclusive lock for a read, so a read never sees
// a file between a write's look and its rename. It first waits while a writer
// of this process waits for the lock or holds it, so reads that follow one
// another never keep it from a raise here, and writes that follow one another
// can hold reads off until their contexts end; across processes the lock
// favours no one. It returns what releases the lock.
func (d *dir) lock(ctx context.Context) (func() error, error) {
	if err := turnOf(d.opened).read(ctx); err != nil {
		return nil, err
	}
	return d.take(ctx)
}

// lockToWrite takes the directory's exclusive lock for a write, ahead of the
// reads of this process that start while it waits.
func (d *dir) lockToWrite(ctx context.Context) (func() error, error) {
	done := turnOf(d.opened).write()
	unlock, err := d.take(ctx)
	if err != nil {
		done()
		return nil, err
	}
	return func() error {
		defer done()
		return unlock()
	}, nil
}

// take takes the directory's exclusive lock, trying again while another open
// file holds it, until ctx ends, and judges the directory again once it holds
// it, since the wait can last as long as ctx allows. It returns what releases
// the lock.
func (d *dir) take(ctx context.Context) (func() error, error) {
	f, err := d.root.Open(".")
	if err != nil {
		return nil, err
	}
	if err := lockWaiting(ctx, f); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	if err := d.judge(); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f.Close, nil
}

// lockWaiting takes f's exclusive lock, trying again while another open file
// holds it, until ctx ends. A platform with no lock answers at once.
func lockWaiting(ctx context.Context, f *os.File) error {
	timer := time.NewTimer(lockRetry)
	defer timer.Stop()
	for {
		ok, err := tryLock(f)
		if err != nil || ok {
			return err
		}
		timer.Reset(lockRetry)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
}
