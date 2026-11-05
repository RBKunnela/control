// Package inbox reads and writes the directory a signed plane takes its
// approvals' answers from: one signed answer per file, bounded per approval and
// in all.
package inbox

// Error is a sentinel the inbox returns, compared with errors.Is.
type Error string

func (e Error) Error() string { return string(e) }
