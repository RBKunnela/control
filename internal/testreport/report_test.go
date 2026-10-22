package testreport_test

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/guardana/control/internal/testreport"
)

// generated is the import path prefix of the generated packages the fixtures
// name; a package under it may have no test files.
const generated = "example.com/fixture/api/gen/"

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := fs.ReadFile(os.DirFS("testdata"), name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSummarizeRecordedStreams(t *testing.T) {
	cases := []struct {
		name    string
		want    testreport.Summary
		wantErr error
	}{
		{"passing", testreport.Summary{Events: 18, Packages: 1}, nil},
		{"skipping", testreport.Summary{Events: 32, Packages: 1, Skipped: 3}, nil},
		{"notests", testreport.Summary{Events: 3, Packages: 1, NoTestFiles: 1}, testreport.ErrNoTestFiles},
		{"generated", testreport.Summary{Events: 3, Packages: 1}, nil},
		{"filtered", testreport.Summary{Events: 6, Packages: 1, NoTestsRun: 1}, testreport.ErrNoTestsRun},
		{"exitearly", testreport.Summary{Events: 3, Packages: 1, NoTestsRun: 1}, testreport.ErrNoTestsRun},
		{"everyran", testreport.Summary{Events: 22, Packages: 3, Skipped: 1, NoTestFiles: 1}, testreport.ErrNoTestFiles},
		{"parallel", testreport.Summary{Events: 53, Packages: 1, Skipped: 1}, nil},
		{"exited", testreport.Summary{Events: 10, Packages: 1, Unfinished: 1}, testreport.ErrUnfinished},
		{"failing", testreport.Summary{Events: 30, Packages: 1, FailedPackages: 1, FailedTests: 3}, testreport.ErrFailed},
		{"panicking", testreport.Summary{Events: 27, Packages: 1, FailedPackages: 1, FailedTests: 1}, testreport.ErrFailed},
		{"broken", testreport.Summary{Events: 6, Packages: 1, FailedPackages: 1, BuildFailures: 1}, testreport.ErrFailed},
		{"all", testreport.Summary{
			Events: 116, Packages: 6, FailedPackages: 3, FailedTests: 4, BuildFailures: 1, Skipped: 3, NoTestFiles: 1,
		}, testreport.ErrFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			got, err := testreport.Summarize(bytes.NewReader(readFixture(t, tc.name+".jsonl")), &out, generated)
			if tc.wantErr == nil && err != nil {
				t.Fatalf("Summarize: %v", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("Summarize error = %v, want %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("Summary = %+v, want %+v", got, tc.want)
			}
			if want := string(readFixture(t, tc.name+".want")); out.String() != want {
				t.Errorf("transcript:\n%s\nwant:\n%s", out.String(), want)
			}
		})
	}
}

func TestSummarizeRefusesWhatDoesNotProveAPass(t *testing.T) {
	passing := string(readFixture(t, "passing.jsonl"))
	withoutResult := passing[:strings.LastIndex(strings.TrimSuffix(passing, "\n"), "\n")+1]
	cases := []struct {
		name  string
		input string
		want  error
	}{
		{"empty", "", testreport.ErrNoEvents},
		{"garbage", "ok  \texample.com/fixture/passing\t0.1s\n", testreport.ErrNotEvent},
		{"garbage without a newline", "PASS", testreport.ErrNotEvent},
		{"null", "null\n", testreport.ErrNotEvent},
		{"array", "[1]\n", testreport.ErrNotEvent},
		{"no action", `{"Package":"example.com/p"}` + "\n", testreport.ErrNotEvent},
		{"unknown action", `{"Action":"retry","Package":"example.com/p"}` + "\n", testreport.ErrNotEvent},
		{"no package", `{"Action":"pass"}` + "\n", testreport.ErrNotEvent},
		{"build output without an import path", `{"Action":"build-output","Output":"x\n"}` + "\n", testreport.ErrNotEvent},
		{"trailing data", `{"Action":"pass","Package":"example.com/p"} {}` + "\n", testreport.ErrNotEvent},
		{"a pass followed by garbage", passing + "panic: boom\n", testreport.ErrNotEvent},
		{"a pass with a blank line", passing + "\n", testreport.ErrNotEvent},
		{"a package without a result", withoutResult, testreport.ErrUnfinished},
		{"build output alone", `{"ImportPath":"example.com/p","Action":"build-output","Output":"x\n"}` + "\n", testreport.ErrNoPackages},
		{"a failed test in a passing package", `{"Action":"fail","Package":"example.com/p","Test":"TestX"}
{"Action":"pass","Package":"example.com/p"}
`, testreport.ErrFailed},
		{"a failed build beside a passing package", `{"ImportPath":"example.com/q","Action":"build-fail"}
{"Action":"pass","Package":"example.com/p"}
`, testreport.ErrFailed},
		{"a package that ran no test beside a passing one", `{"Action":"output","Package":"example.com/q","Output":"ok  \texample.com/q\t0.1s [no tests to run]\n"}
{"Action":"pass","Package":"example.com/q"}
{"Action":"pass","Package":"example.com/p"}
`, testreport.ErrNoTestsRun},
		{"a pass with no test run and no warning", `{"Action":"output","Package":"example.com/q","Output":"ok  \texample.com/q\t0.1s\n"}
{"Action":"pass","Package":"example.com/q"}
`, testreport.ErrNoTestsRun},
		{"a test that started and never ended in a passing package", `{"Action":"start","Package":"example.com/p"}
{"Action":"run","Package":"example.com/p","Test":"TestHangs"}
{"Action":"output","Package":"example.com/p","Output":"ok  \texample.com/p\t0.1s\n"}
{"Action":"pass","Package":"example.com/p"}
`, testreport.ErrUnfinished},
		{"a paused test that never continued", `{"Action":"run","Package":"example.com/p","Test":"TestX"}
{"Action":"pass","Package":"example.com/p","Test":"TestX"}
{"Action":"run","Package":"example.com/p","Test":"TestY"}
{"Action":"pause","Package":"example.com/p","Test":"TestY"}
{"Action":"pass","Package":"example.com/p"}
`, testreport.ErrUnfinished},
		{"a subtest that never ended under a parent that passed", `{"Action":"run","Package":"example.com/p","Test":"TestX"}
{"Action":"run","Package":"example.com/p","Test":"TestX/sub"}
{"Action":"pass","Package":"example.com/p","Test":"TestX"}
{"Action":"pass","Package":"example.com/p"}
`, testreport.ErrUnfinished},
		{"a benchmark with no result", `{"Action":"run","Package":"example.com/p","Test":"BenchmarkX"}
{"Action":"pass","Package":"example.com/p"}
`, testreport.ErrUnfinished},
		{"a result for a test that ended in another package", `{"Action":"run","Package":"example.com/p","Test":"TestX"}
{"Action":"run","Package":"example.com/q","Test":"TestX"}
{"Action":"pass","Package":"example.com/q","Test":"TestX"}
{"Action":"pass","Package":"example.com/q"}
{"Action":"pass","Package":"example.com/p"}
`, testreport.ErrUnfinished},
		{"a pass whose only test ran in another package", `{"Action":"run","Package":"example.com/p","Test":"TestX"}
{"Action":"pass","Package":"example.com/p","Test":"TestX"}
{"Action":"pass","Package":"example.com/q"}
{"Action":"pass","Package":"example.com/p"}
`, testreport.ErrNoTestsRun},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := testreport.Summarize(strings.NewReader(tc.input), &bytes.Buffer{}, generated)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Summarize error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestSummarizeShowsWhatItRefuses(t *testing.T) {
	var out bytes.Buffer
	if _, err := testreport.Summarize(strings.NewReader("panic: boom\n"), &out, generated); err == nil {
		t.Fatal("Summarize accepted a line that is not an event")
	}
	if out.String() != "panic: boom\n" {
		t.Errorf("transcript = %q, want the refused line itself", out.String())
	}

	passing := string(readFixture(t, "passing.jsonl"))
	unfinished := passing[:strings.LastIndex(strings.TrimSuffix(passing, "\n"), "\n")+1]
	out.Reset()
	if _, err := testreport.Summarize(strings.NewReader(unfinished), &out, generated); err == nil {
		t.Fatal("Summarize accepted a package without a result")
	}
	want := "-test.shuffle 1791112380631026000\nPASS\nok  \texample.com/fixture/passing\t0.289s\ntest: 0 skipped\n"
	if out.String() != want {
		t.Errorf("transcript = %q, want %q", out.String(), want)
	}
}

func TestSummarizeWritesNothingForAnEmptyStream(t *testing.T) {
	var out bytes.Buffer
	if _, err := testreport.Summarize(strings.NewReader(""), &out, generated); err == nil {
		t.Fatal("Summarize accepted an empty stream")
	}
	if out.Len() != 0 {
		t.Errorf("transcript = %q, want nothing that could read as a result", out.String())
	}
}

func TestSummarizeNamesAPassingPackageWithoutAResultLine(t *testing.T) {
	var out bytes.Buffer
	input := `{"Action":"run","Package":"example.com/p","Test":"TestX"}
{"Action":"pass","Package":"example.com/p","Test":"TestX"}
{"Action":"pass","Package":"example.com/p"}
`
	got, err := testreport.Summarize(strings.NewReader(input), &out, generated)
	if err != nil {
		t.Fatalf("Summarize: %v", err)
	}
	if got != (testreport.Summary{Events: 3, Packages: 1}) {
		t.Errorf("Summary = %+v", got)
	}
	if want := "ok  \texample.com/p\ntest: 0 skipped\n"; out.String() != want {
		t.Errorf("transcript = %q, want %q", out.String(), want)
	}
}

func TestSummarizeShowsATestThatNeverFinished(t *testing.T) {
	input := `{"Action":"run","Package":"example.com/p","Test":"TestHangs"}
{"Action":"output","Package":"example.com/p","Test":"TestHangs","Output":"=== RUN   TestHangs\n"}
{"Action":"output","Package":"example.com/p","Test":"TestHangs","Output":"panic: test timed out after 1s\n"}
{"Action":"output","Package":"example.com/p","Output":"FAIL\texample.com/p\t1.0s\n"}
{"Action":"fail","Package":"example.com/p"}
`
	var out bytes.Buffer
	if _, err := testreport.Summarize(strings.NewReader(input), &out, generated); !errors.Is(err, testreport.ErrFailed) {
		t.Fatalf("Summarize error = %v, want ErrFailed", err)
	}
	want := "panic: test timed out after 1s\nFAIL\texample.com/p\t1.0s\ntest: 0 skipped\n"
	if out.String() != want {
		t.Errorf("transcript = %q, want %q", out.String(), want)
	}
}

func TestSummarizeReadsALineLongerThanAScannerBuffer(t *testing.T) {
	long := strings.Repeat("x", 200_000)
	input := `{"Action":"output","Package":"example.com/p","Test":"TestX","Output":"` + long + `\n"}
{"Action":"fail","Package":"example.com/p","Test":"TestX"}
{"Action":"fail","Package":"example.com/p"}
`
	var out bytes.Buffer
	got, err := testreport.Summarize(strings.NewReader(input), &out, generated)
	if !errors.Is(err, testreport.ErrFailed) {
		t.Fatalf("Summarize error = %v, want ErrFailed", err)
	}
	if got.Events != 3 {
		t.Errorf("Events = %d, want 3", got.Events)
	}
	if want := long + "\ntest: 0 skipped\n"; out.String() != want {
		t.Errorf("transcript holds %d bytes, want %d", out.Len(), len(want))
	}
}

type failingWriter struct{}

var errWrite = errors.New("write refused")

func (failingWriter) Write([]byte) (int, error) { return 0, errWrite }

func TestSummarizeReportsAWriteFailure(t *testing.T) {
	_, err := testreport.Summarize(bytes.NewReader(readFixture(t, "passing.jsonl")), failingWriter{}, generated)
	if !errors.Is(err, errWrite) {
		t.Fatalf("Summarize error = %v, want the writer's", err)
	}
}

var errRead = errors.New("read refused")

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errRead }

func TestSummarizeReportsAReadFailureAfterAPass(t *testing.T) {
	r := io.MultiReader(bytes.NewReader(readFixture(t, "passing.jsonl")), failingReader{})
	got, err := testreport.Summarize(r, &bytes.Buffer{}, generated)
	if !errors.Is(err, errRead) {
		t.Fatalf("Summarize error = %v, want the reader's", err)
	}
	if got.Packages != 1 {
		t.Errorf("Packages = %d, want the passing package read before the failure", got.Packages)
	}
}

func FuzzSummarize(f *testing.F) {
	for _, name := range []string{"passing", "skipping", "notests", "generated", "filtered", "exitearly", "everyran", "parallel", "exited", "failing", "panicking", "broken", "all"} {
		b, err := fs.ReadFile(os.DirFS("testdata"), name+".jsonl")
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte(""))
	f.Add([]byte("null\n"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var out bytes.Buffer
		got, err := testreport.Summarize(bytes.NewReader(input), &out, generated)
		if err != nil {
			return
		}
		if got.Packages == 0 || got.FailedPackages != 0 || got.FailedTests != 0 || got.BuildFailures != 0 || got.NoTestsRun != 0 || got.NoTestFiles != 0 || got.Unfinished != 0 {
			t.Fatalf("Summarize passed %+v", got)
		}
		if !strings.HasSuffix(out.String(), " skipped\n") {
			t.Fatalf("a pass without the skip count: %q", out.String())
		}
	})
}

func TestSummarizeNamesEveryTestThatNeverEnded(t *testing.T) {
	input := `{"Action":"run","Package":"example.com/a","Test":"TestGone"}
{"Action":"pass","Package":"example.com/a"}
{"Action":"run","Package":"example.com/b","Test":"TestFine"}
{"Action":"pass","Package":"example.com/b","Test":"TestFine"}
{"Action":"pass","Package":"example.com/b"}
{"Action":"run","Package":"example.com/c","Test":"TestOne"}
{"Action":"run","Package":"example.com/c","Test":"TestTwo"}
{"Action":"pass","Package":"example.com/c"}
`
	var out bytes.Buffer
	got, err := testreport.Summarize(strings.NewReader(input), &out, generated)
	if !errors.Is(err, testreport.ErrUnfinished) {
		t.Fatalf("Summarize error = %v, want ErrUnfinished", err)
	}
	if want := "example.com/a TestGone, example.com/c TestOne, example.com/c TestTwo"; !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not name %q", err, want)
	}
	if got.Unfinished != 3 || got.Packages != 3 {
		t.Errorf("Summary = %+v, want 3 packages and 3 tests that never ended", got)
	}
	want := "ok  \texample.com/a\nok  \texample.com/b\nok  \texample.com/c\n" +
		"test: UNFINISHED example.com/a TestGone\ntest: UNFINISHED example.com/c TestOne\ntest: UNFINISHED example.com/c TestTwo\n" +
		"test: 0 skipped\n"
	if out.String() != want {
		t.Errorf("transcript = %q, want %q", out.String(), want)
	}
}

func TestSummarizeNamesEveryPackageThatRanNoTest(t *testing.T) {
	input := `{"Action":"output","Package":"example.com/a","Output":"ok  \texample.com/a\t0.1s [no tests to run]\n"}
{"Action":"pass","Package":"example.com/a"}
{"Action":"output","Package":"example.com/b","Output":"?   \texample.com/b\t[no test files]\n"}
{"Action":"skip","Package":"example.com/b"}
{"Action":"output","Package":"example.com/c","Output":"ok  \texample.com/c\t0.1s [no tests to run]\n"}
{"Action":"pass","Package":"example.com/c"}
`
	got, err := testreport.Summarize(strings.NewReader(input), &bytes.Buffer{}, generated)
	if !errors.Is(err, testreport.ErrNoTestsRun) {
		t.Fatalf("Summarize error = %v, want ErrNoTestsRun", err)
	}
	if !strings.Contains(err.Error(), "example.com/a, example.com/c") {
		t.Errorf("error %q does not name both packages that ran no test", err)
	}
	if got.NoTestsRun != 2 || got.Packages != 3 {
		t.Errorf("Summary = %+v, want 3 packages, 2 of them with no test run", got)
	}
}

func TestSummarizeCountsAnyRunEventAsATestRun(t *testing.T) {
	for _, name := range []string{"TestX", "TestX/sub", "ExampleX", "BenchmarkX", "FuzzX"} {
		t.Run(name, func(t *testing.T) {
			input := `{"Action":"run","Package":"example.com/p","Test":"` + name + `"}
{"Action":"pass","Package":"example.com/p","Test":"` + name + `"}
{"Action":"pass","Package":"example.com/p"}
`
			got, err := testreport.Summarize(strings.NewReader(input), &bytes.Buffer{}, generated)
			if err != nil {
				t.Fatalf("Summarize: %v", err)
			}
			if got.NoTestsRun != 0 {
				t.Errorf("NoTestsRun = %d, want 0", got.NoTestsRun)
			}
		})
	}
}
