package reaction

import "time"

// Matches is the kinds of the entries of s that name a call of who, read as
// ForSubject reads them with no age rule.
func Matches(s Snapshot, who Subject, now, floor time.Time) StopMatch {
	return s.matches(who, now, floor)
}
