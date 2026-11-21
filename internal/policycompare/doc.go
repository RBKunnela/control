// Package policycompare evaluates each case under a current and a candidate
// policy through the kernel's own evaluation and reports, per case, the
// decision before and after and how it changed, with every unknown counted
// and named rather than guessed. It sends no call, reads no approval and
// writes no policy: the caller reads every file and writes the report.
// See ADR-0087.
package policycompare
