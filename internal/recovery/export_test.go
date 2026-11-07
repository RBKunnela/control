package recovery

// SetKillPoint makes kill the seam every restore write passes through until
// the returned function puts the real one back.
func SetKillPoint(kill func(step string) error) (restore func()) {
	saved := killPoint
	killPoint = kill
	return func() { killPoint = saved }
}

// Classified is every configuration key a backup copies, and every key it
// leaves out with why.
func Classified() (copied []string, never map[string]string) {
	for _, c := range classes {
		copied = append(copied, c.key)
	}
	return copied, neverBackedUp
}
