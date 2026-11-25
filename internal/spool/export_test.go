package spool

// DrainStoppedAfterWrite is Drain with written called once the drained file
// is on disk and before the quarantine is truncated.
func DrainStoppedAfterWrite(dir, out string, written func() error) (Drained, error) {
	return drain(dir, out, drainHooks{written: written})
}

// DrainAfterCheck is Drain with checked called once the drained file's
// directory was judged and before the file is created.
func DrainAfterCheck(dir, out string, checked func() error) (Drained, error) {
	return drain(dir, out, drainHooks{checked: checked})
}
