package testreport_test

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/guardana/control/internal/testreport"
)

// bothRan is a stream in which TestA and TestB of example.com/p pass.
const bothRan = `{"Action":"start","Package":"example.com/p"}
{"Action":"run","Package":"example.com/p","Test":"TestA"}
{"Action":"pass","Package":"example.com/p","Test":"TestA"}
{"Action":"run","Package":"example.com/p","Test":"TestB"}
{"Action":"pass","Package":"example.com/p","Test":"TestB"}
{"Action":"output","Package":"example.com/p","Output":"ok  \texample.com/p\t0.1s\n"}
{"Action":"pass","Package":"example.com/p"}
`

var wantAB = testreport.ExpectedRuns{{Package: "example.com/p", Test: "TestA"}, {Package: "example.com/p", Test: "TestB"}}

func TestSummarizeRunsPassesWhenEveryListedTestPassed(t *testing.T) {
	var out bytes.Buffer
	got, err := testreport.SummarizeRuns(strings.NewReader(bothRan), &out, wantAB)
	if err != nil {
		t.Fatalf("SummarizeRuns: %v", err)
	}
	if got != (testreport.Summary{Events: 7, Packages: 1}) {
		t.Errorf("Summary = %+v", got)
	}
	want := "ok  \texample.com/p\t0.1s\n" +
		"test: 0 skipped\n" +
		"test: PASSED example.com/p TestA\n" +
		"test: PASSED example.com/p TestB\n"
	if out.String() != want {
		t.Errorf("transcript = %q, want %q", out.String(), want)
	}
}

// TestSummarizeRunsRefusesWhatDidNotPass is the checker's negative control:
// each planted stream lacks a pass of TestB in its own way, and each is
// refused naming it.
func TestSummarizeRunsRefusesWhatDidNotPass(t *testing.T) {
	cases := map[string]struct {
		stream string
		also   error
	}{
		"a skip": {strings.Replace(bothRan,
			`{"Action":"pass","Package":"example.com/p","Test":"TestB"}`,
			`{"Action":"output","Package":"example.com/p","Test":"TestB","Output":"    b_test.go:9: GUARDANA_TEST_OTHER_UID is not set\n"}`+"\n"+
				`{"Action":"skip","Package":"example.com/p","Test":"TestB"}`, 1), testreport.ErrUnexpectedSkip},
		"a missing test": {strings.Replace(bothRan,
			`{"Action":"run","Package":"example.com/p","Test":"TestB"}`+"\n"+`{"Action":"pass","Package":"example.com/p","Test":"TestB"}`+"\n",
			"", 1), nil},
		"no events":         {"", testreport.ErrNoEvents},
		"a stream of noise": {"PASS\nok  \texample.com/p\n", testreport.ErrNotEvent},
		"a failed test":     {strings.Replace(bothRan, `"pass","Package":"example.com/p","Test":"TestB"`, `"fail","Package":"example.com/p","Test":"TestB"`, 1), testreport.ErrFailed},
		"a pass without its package": {strings.Replace(bothRan,
			`{"Action":"pass","Package":"example.com/p","Test":"TestB"}`,
			`{"Action":"pass","Test":"TestB"}`, 1), testreport.ErrNotEvent},
		"the same name in another package": {strings.ReplaceAll(bothRan,
			`"Package":"example.com/p","Test":"TestB"`, `"Package":"example.com/q","Test":"TestB"`), nil},
		"a build failure": {`{"ImportPath":"example.com/p.test","Action":"build-output","Output":"p_test.go:1: syntax error\n"}
{"ImportPath":"example.com/p.test","Action":"build-fail"}
{"Action":"start","Package":"example.com/p"}
{"Action":"output","Package":"example.com/p","Output":"FAIL\texample.com/p [build failed]\n"}
{"Action":"fail","Package":"example.com/p"}
`, testreport.ErrFailed},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			_, err := testreport.SummarizeRuns(strings.NewReader(tc.stream), &out, wantAB)
			if !errors.Is(err, testreport.ErrNotRun) || !strings.Contains(err.Error(), "example.com/p TestB") {
				t.Fatalf("SummarizeRuns error = %v, want ErrNotRun naming example.com/p TestB", err)
			}
			if tc.also != nil && !errors.Is(err, tc.also) {
				t.Errorf("SummarizeRuns error = %v, want %v too", err, tc.also)
			}
			if !strings.Contains(out.String(), "test: NOT PASSED example.com/p TestB\n") {
				t.Errorf("transcript does not name the test:\n%s", out.String())
			}
		})
	}
}

// TestSummarizeRunsAdmitsNoSkip: a skip of a test the list does not name
// fails the run too, since the job's binaries run the listed tests alone.
func TestSummarizeRunsAdmitsNoSkip(t *testing.T) {
	stream := strings.Replace(bothRan, `{"Action":"pass","Package":"example.com/p"}`,
		`{"Action":"run","Package":"example.com/p","Test":"TestC"}
{"Action":"output","Package":"example.com/p","Test":"TestC","Output":"    c_test.go:3: needs root\n"}
{"Action":"skip","Package":"example.com/p","Test":"TestC"}
{"Action":"pass","Package":"example.com/p"}`, 1)
	_, err := testreport.SummarizeRuns(strings.NewReader(stream), &bytes.Buffer{}, wantAB)
	if !errors.Is(err, testreport.ErrUnexpectedSkip) || errors.Is(err, testreport.ErrNotRun) {
		t.Fatalf("SummarizeRuns error = %v, want ErrUnexpectedSkip alone", err)
	}
}

// TestSummarizeRunsTakesATestsLastResult: a test that failed after it
// passed, as a second run of the binary reports it, did not pass.
func TestSummarizeRunsTakesATestsLastResult(t *testing.T) {
	stream := bothRan + `{"Action":"start","Package":"example.com/p"}
{"Action":"run","Package":"example.com/p","Test":"TestA"}
{"Action":"fail","Package":"example.com/p","Test":"TestA"}
{"Action":"fail","Package":"example.com/p"}
`
	_, err := testreport.SummarizeRuns(strings.NewReader(stream), &bytes.Buffer{}, wantAB)
	if !errors.Is(err, testreport.ErrNotRun) || !strings.Contains(err.Error(), ": example.com/p TestA") ||
		strings.Contains(err.Error(), "TestB") {
		t.Fatalf("SummarizeRuns error = %v, want ErrNotRun naming TestA alone", err)
	}
}

func TestSummarizeRunsRefusesAnEmptyList(t *testing.T) {
	for _, list := range []testreport.ExpectedRuns{nil, {}} {
		if _, err := testreport.SummarizeRuns(strings.NewReader(bothRan), &bytes.Buffer{}, list); !errors.Is(err, testreport.ErrExpectedRuns) {
			t.Errorf("SummarizeRuns over %v = %v, want ErrExpectedRuns", list, err)
		}
	}
}

func TestParseExpectedRunsReadsOneEntryPerLine(t *testing.T) {
	text := "# the tests the job must pass\n" +
		"\n" +
		"example.com/p TestA\n" +
		"   \n" +
		"#example.com/q TestCommented\n" +
		"example.com/q TestA"
	got, err := testreport.ParseExpectedRuns([]byte(text))
	if err != nil {
		t.Fatalf("ParseExpectedRuns: %v", err)
	}
	want := testreport.ExpectedRuns{{Package: "example.com/p", Test: "TestA"}, {Package: "example.com/q", Test: "TestA"}}
	if !slices.Equal(got, want) {
		t.Errorf("ParseExpectedRuns = %q, want %q", got, want)
	}
}

func TestParseExpectedRunsRefusesAMalformedList(t *testing.T) {
	cases := map[string]string{
		"no test name":           "example.com/p\n",
		"a third field":          "example.com/p TestA needs root\n",
		"two spaces":             "example.com/p  TestA\n",
		"an indented entry":      " example.com/p TestA\n",
		"a tab in the test name": "example.com/p TestA\tx\n",
		"a subtest":              "example.com/p TestA/case\n",
		"a fuzz target":          "example.com/p FuzzA\n",
		"a lower-case test name": "example.com/p testA\n",
		"a test named twice":     "example.com/p TestA\nexample.com/q TestA\nexample.com/p TestA\n",
		"comments only":          "# nothing yet\n\n",
		"nothing":                "",
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := testreport.ParseExpectedRuns([]byte(text))
			if !errors.Is(err, testreport.ErrExpectedRuns) {
				t.Fatalf("ParseExpectedRuns = %q, %v; want ErrExpectedRuns", got, err)
			}
			if got != nil {
				t.Errorf("ParseExpectedRuns returned %q beside its error", got)
			}
		})
	}
}
