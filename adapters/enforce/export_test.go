package enforce

// Minting counts the executions whose EXECUTE is still being written.
func Minting(a *Adapter) int {
	a.handles.mu.Lock()
	defer a.handles.mu.Unlock()
	n := 0
	for _, e := range a.handles.byID {
		if e.state == stateMinting {
			n++
		}
	}
	return n
}
