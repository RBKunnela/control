package spool

// DrainStoppedAfterWrite is Drain with written called once the drained file
// is on disk and before the quarantine is truncated.
func DrainStoppedAfterWrite(dir, out string, written func() error) (Drained, error) {
	return drain(dir, out, written)
}
