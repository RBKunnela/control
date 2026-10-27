// Package testreport turns the event stream of `go test -json` into a
// transcript: each passing package's result line; for a failing one, its own
// lines and the output of each test that failed; then one line per skipped test
// and the skip count, so that every skip is visible in the gate's output. A
// skip the repository's list of expected skips does not name fails the run.
//
// Summarize answers with an error whenever the stream does not prove a pass: no
// event at all, a line that is not an event, a package without a result, a
// passing package with a test that started and reached no result, a failed
// build, package or test, a package whose test files ran no test, a package
// with no test files outside the generated code, a skip that is not expected.
// A failed test fails the run even in a package whose result is a pass, as when
// its TestMain exits 0 after the failure, where plain `go test` reports the
// package ok.
//
// The stream is the test binary's own output, so code under test can write any
// event into it. A test that writes its own result and then ends the process
// with exit status 0 passes here, and the tests after it in its package never
// start and are never named. Review of the test code is what catches that.
package testreport
