package policykey

// BeforeStatementReplaced sets what runs once a statement write judged its
// output and before it replaces it, for the test's length.
func BeforeStatementReplaced(t interface{ Cleanup(func()) }, f func()) {
	saved := beforeStatementReplaced
	beforeStatementReplaced = f
	t.Cleanup(func() { beforeStatementReplaced = saved })
}
