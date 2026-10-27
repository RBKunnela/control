package testreport_test

import (
	"bytes"
	"errors"
	"maps"
	"strings"
	"testing"

	"github.com/guardana/control/internal/testreport"
)

// twoSkips is a passing package in which TestX and TestY skip and TestZ runs.
const twoSkips = `{"Action":"run","Package":"example.com/p","Test":"TestX"}
{"Action":"output","Package":"example.com/p","Test":"TestX","Output":"    x_test.go:5: needs root\n"}
{"Action":"skip","Package":"example.com/p","Test":"TestX"}
{"Action":"run","Package":"example.com/p","Test":"TestY"}
{"Action":"output","Package":"example.com/p","Test":"TestY","Output":"    y_test.go:9: no read-only mount\n"}
{"Action":"skip","Package":"example.com/p","Test":"TestY"}
{"Action":"run","Package":"example.com/p","Test":"TestZ"}
{"Action":"pass","Package":"example.com/p","Test":"TestZ"}
{"Action":"pass","Package":"example.com/p"}
`

func TestSummarizeRefusesASkipTheListDoesNotName(t *testing.T) {
	cases := map[string]testreport.ExpectedSkips{
		"no list": nil,
		"the other test only": {
			{Package: "example.com/p", Test: "TestY"}: "no read-only mount",
		},
		"the same test in another package": {
			{Package: "example.com/q", Test: "TestX"}: "a reason",
			{Package: "example.com/p", Test: "TestY"}: "no read-only mount",
		},
		"listed, skipped for another reason": {
			{Package: "example.com/p", Test: "TestX"}: "a different reason",
			{Package: "example.com/p", Test: "TestY"}: "no read-only mount",
		},
		"its parent only": {
			{Package: "example.com/p", Test: "TestX/sub"}: "a reason",
			{Package: "example.com/p", Test: "TestY"}:     "no read-only mount",
		},
	}
	for name, expected := range cases {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			got, err := testreport.Summarize(strings.NewReader(twoSkips), &out, generated, expected)
			if !errors.Is(err, testreport.ErrUnexpectedSkip) {
				t.Fatalf("Summarize error = %v, want ErrUnexpectedSkip", err)
			}
			if !strings.Contains(err.Error(), ": example.com/p TestX") {
				t.Errorf("error %q does not name example.com/p TestX", err)
			}
			if got.Skipped != 2 || got.Unexpected < 1 {
				t.Errorf("Summary = %+v, want 2 skipped, TestX among the unexpected", got)
			}
			if !strings.Contains(out.String(), "test: SKIP example.com/p TestX: x_test.go:5: needs root\n") ||
				!strings.Contains(out.String(), "test: SKIP example.com/p TestY: y_test.go:9: no read-only mount\n") {
				t.Errorf("transcript does not list both skips:\n%s", out.String())
			}
		})
	}
}

// subtestSkip is a passing package in which TestX runs and its subtest skips.
const subtestSkip = `{"Action":"run","Package":"example.com/p","Test":"TestX"}
{"Action":"run","Package":"example.com/p","Test":"TestX/sub"}
{"Action":"output","Package":"example.com/p","Test":"TestX/sub","Output":"    x_test.go:7: needs root\n"}
{"Action":"skip","Package":"example.com/p","Test":"TestX/sub"}
{"Action":"pass","Package":"example.com/p","Test":"TestX"}
{"Action":"pass","Package":"example.com/p"}
`

func TestSummarizeRefusesASubtestOfAListedTest(t *testing.T) {
	expected := testreport.ExpectedSkips{{Package: "example.com/p", Test: "TestX"}: "needs root"}
	_, err := testreport.Summarize(strings.NewReader(subtestSkip), &bytes.Buffer{}, generated, expected)
	if !errors.Is(err, testreport.ErrUnexpectedSkip) || !strings.Contains(err.Error(), ": example.com/p TestX/sub") {
		t.Fatalf("Summarize error = %v, want ErrUnexpectedSkip naming example.com/p TestX/sub", err)
	}
}

// loggedThenSkipped is a package whose TestX logs the listed text and then
// skips for another reason.
const loggedThenSkipped = `{"Action":"run","Package":"example.com/p","Test":"TestX"}
{"Action":"output","Package":"example.com/p","Test":"TestX","Output":"    x_test.go:5: needs root, as the log says\n"}
{"Action":"output","Package":"example.com/p","Test":"TestX","Output":"    x_test.go:6: skipped while broken\n"}
{"Action":"skip","Package":"example.com/p","Test":"TestX"}
{"Action":"pass","Package":"example.com/p"}
`

func TestSummarizeJudgesTheLineASkipEndsWith(t *testing.T) {
	expected := testreport.ExpectedSkips{{Package: "example.com/p", Test: "TestX"}: "needs root"}
	_, err := testreport.Summarize(strings.NewReader(loggedThenSkipped), &bytes.Buffer{}, generated, expected)
	if !errors.Is(err, testreport.ErrUnexpectedSkip) {
		t.Fatalf("Summarize error = %v, want ErrUnexpectedSkip: the listed text is in a logged line, not the skip", err)
	}
	expected = testreport.ExpectedSkips{{Package: "example.com/p", Test: "TestX"}: "skipped while broken"}
	if _, err := testreport.Summarize(strings.NewReader(loggedThenSkipped), &bytes.Buffer{}, generated, expected); err != nil {
		t.Fatalf("Summarize refused a skip whose last line holds the listed text: %v", err)
	}
}

func TestSummarizeNamesASkipForAnotherReason(t *testing.T) {
	expected := testreport.ExpectedSkips{
		{Package: "example.com/p", Test: "TestX"}: "a different reason",
		{Package: "example.com/p", Test: "TestY"}: "no read-only mount",
	}
	_, err := testreport.Summarize(strings.NewReader(twoSkips), &bytes.Buffer{}, generated, expected)
	want := `: example.com/p TestX, whose message does not hold "a different reason"`
	if !errors.Is(err, testreport.ErrUnexpectedSkip) || !strings.Contains(err.Error(), want) {
		t.Fatalf("Summarize error = %v, want ErrUnexpectedSkip with %q", err, want)
	}
}

func TestSummarizeNamesEveryUnexpectedSkip(t *testing.T) {
	_, err := testreport.Summarize(strings.NewReader(twoSkips), &bytes.Buffer{}, generated, nil)
	if err == nil || !strings.Contains(err.Error(), ": example.com/p TestX, example.com/p TestY") {
		t.Fatalf("Summarize error = %v, want both skips named", err)
	}
}

func TestSummarizePassesAListedSkip(t *testing.T) {
	expected := testreport.ExpectedSkips{
		{Package: "example.com/p", Test: "TestX"}: "needs root",
		{Package: "example.com/p", Test: "TestY"}: "no read-only mount",
	}
	var out bytes.Buffer
	got, err := testreport.Summarize(strings.NewReader(twoSkips), &out, generated, expected)
	if err != nil {
		t.Fatalf("Summarize: %v", err)
	}
	if got != (testreport.Summary{Events: 9, Packages: 1, Skipped: 2}) {
		t.Errorf("Summary = %+v", got)
	}
	want := "ok  \texample.com/p\n" +
		"test: SKIP example.com/p TestX: x_test.go:5: needs root\n" +
		"test: SKIP example.com/p TestY: y_test.go:9: no read-only mount\n" +
		"test: 2 skipped\n"
	if out.String() != want {
		t.Errorf("transcript = %q, want %q", out.String(), want)
	}
}

func TestSummarizeReportsAListedSkipThatRan(t *testing.T) {
	expected := testreport.ExpectedSkips{
		{Package: "example.com/p", Test: "TestX"}:         "needs root",
		{Package: "example.com/p", Test: "TestY"}:         "no read-only mount",
		{Package: "example.com/p", Test: "TestZ"}:         "needs root",
		{Package: "example.com/p", Test: "TestGone"}:      "renamed since",
		{Package: "example.com/elsewhere", Test: "TestW"}: "a package this stream never reached",
	}
	var out bytes.Buffer
	got, err := testreport.Summarize(strings.NewReader(twoSkips), &out, generated, expected)
	if err != nil {
		t.Fatalf("Summarize refused an expected skip that ran: %v", err)
	}
	if got.Unexpected != 0 || got.Skipped != 2 {
		t.Errorf("Summary = %+v", got)
	}
	want := "ok  \texample.com/p\n" +
		"test: SKIP example.com/p TestX: x_test.go:5: needs root\n" +
		"test: SKIP example.com/p TestY: y_test.go:9: no read-only mount\n" +
		"test: EXPECTED SKIP ABSENT example.com/p TestGone\n" +
		"test: EXPECTED SKIP RAN example.com/p TestZ\n" +
		"test: 2 skipped\n"
	if out.String() != want {
		t.Errorf("transcript = %q, want %q", out.String(), want)
	}
}

func TestParseExpectedSkipsReadsOneEntryPerLine(t *testing.T) {
	text := "# the tests a run may skip\n" +
		"\n" +
		"example.com/p TestX needs root\n" +
		"   \n" +
		"example.com/p TestX/a_case FuzzSeed run only as   its own child\n" +
		"example.com/q FuzzF/seed#0 a seed the fuzz target skips\n" +
		"#example.com/q TestCommented a reason\n" +
		"example.com/q ExampleE no output on this platform"
	got, err := testreport.ParseExpectedSkips([]byte(text))
	if err != nil {
		t.Fatalf("ParseExpectedSkips: %v", err)
	}
	want := testreport.ExpectedSkips{
		{Package: "example.com/p", Test: "TestX"}:        "needs root",
		{Package: "example.com/p", Test: "TestX/a_case"}: "FuzzSeed run only as   its own child",
		{Package: "example.com/q", Test: "FuzzF/seed#0"}: "a seed the fuzz target skips",
		{Package: "example.com/q", Test: "ExampleE"}:     "no output on this platform",
	}
	if !maps.Equal(got, want) {
		t.Errorf("ParseExpectedSkips = %q, want %q", got, want)
	}
}

func TestParseExpectedSkipsRefusesAMalformedList(t *testing.T) {
	cases := map[string]string{
		"no reason":                 "example.com/p TestX\n",
		"a reason of white space":   "example.com/p TestX   \n",
		"an empty test name":        "example.com/p  TestX needs root\n",
		"an empty import path":      " TestX needs root\n",
		"an indented entry":         " example.com/p TestX needs root\n",
		"a tab in the import path":  "example.com/p\tq TestX needs root\n",
		"a tab in the test name":    "example.com/p TestX\tsub needs root\n",
		"a reason in the test name": "example.com/p needs root\n",
		"a lower-case test name":    "example.com/p testX needs root\n",
		"a test named twice":        "example.com/p TestX needs root\nexample.com/q TestX needs root\nexample.com/p TestX another reason\n",
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := testreport.ParseExpectedSkips([]byte(text))
			if !errors.Is(err, testreport.ErrExpectedSkips) {
				t.Fatalf("ParseExpectedSkips = %q, %v; want ErrExpectedSkips", got, err)
			}
			if got != nil {
				t.Errorf("ParseExpectedSkips returned %q beside its error", got)
			}
		})
	}
}

func TestParseExpectedSkipsNamesTheLine(t *testing.T) {
	_, err := testreport.ParseExpectedSkips([]byte("# a comment\nexample.com/p TestX needs root\nexample.com/p TestX again\n"))
	if err == nil || !strings.Contains(err.Error(), "line 3 names example.com/p TestX a second time") {
		t.Fatalf("ParseExpectedSkips error = %v, want the duplicate's line named", err)
	}
}
