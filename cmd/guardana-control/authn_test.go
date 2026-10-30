package main

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"strings"
	"testing"
	"time"
)

// reservedApprovers spell the reserved prefix as it is, in capitals, and with
// a Cyrillic a. Each is an identifier the store would otherwise take.
var reservedApprovers = []string{"authn:x:y", "AUTHN:x:y", "\u0430uthn:x:y"}

// TestAnswerUnderTheReservedPrefixIsRefusedAndWritesNothing: a person who
// types the prefix into --approver-id is refused as every other approver id
// the store refuses is, and the directory is byte for byte what it was.
func TestAnswerUnderTheReservedPrefixIsRefusedAndWritesNothing(t *testing.T) {
	for _, command := range []string{"approve", "reject"} {
		for _, id := range reservedApprovers {
			t.Run(command+" "+id, func(t *testing.T) {
				dir, plane := newStore(t)
				hold(t, plane, waitingID, clockNow().Add(15*time.Minute))
				before := files(t, dir)

				code, stdout, stderr := invoke(t, "approvals", command, "--approver-id", id, dir, waitingID)
				if code != exitFail || stdout != "" {
					t.Errorf("exit %d, stdout %q; want %d and nothing", code, stdout, exitFail)
				}
				if line := oneStderrLine(t, stderr); !strings.Contains(line, "approver id") || !strings.Contains(line, "reserved authn: prefix") {
					t.Errorf("stderr = %q, want a line naming the approver id and the reserved prefix", line)
				}
				if after := files(t, dir); !maps.Equal(before, after) {
					t.Error("the directory changed under a call that was refused")
				}
			})
		}
	}
}

// TestConsoleUnderTheReservedPrefixDoesNotStart: the page refuses the prefix
// as its approver id and binds nothing, so no answer is ever filed under it.
func TestConsoleUnderTheReservedPrefixDoesNotStart(t *testing.T) {
	dir, plane := newStore(t)
	hold(t, plane, waitingID, clockNow().Add(15*time.Minute))
	before := files(t, dir)
	for _, id := range reservedApprovers {
		// A page that wrongly started serves until its context ends; the
		// deadline turns that into a failure rather than a hang.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		var stdout, stderr bytes.Buffer
		code := serveConsole(ctx, []string{"--approvals", dir, "--approver-id", id}, strings.NewReader(""), &stdout, &stderr)
		cancel()
		if code != exitUsage || stdout.Len() != 0 || !strings.Contains(stderr.String(), "authn:") {
			t.Errorf("%+q: exit %d, stdout %q, stderr %q; want %d naming the prefix", id, code, stdout.String(), stderr.String(), exitUsage)
		}
	}
	if after := files(t, dir); !maps.Equal(before, after) {
		t.Error("the directory changed under a page that did not start")
	}
}

// TestConsoleTakesNoApproverFromTheRequest: the approver is the starter's,
// so an answer whose body names one is refused and writes nothing. The same
// body without the member is filed, so the member is what is refused.
func TestConsoleTakesNoApproverFromTheRequest(t *testing.T) {
	dir, plane := newStore(t)
	hold(t, plane, waitingID, clockNow().Add(15*time.Minute))
	p := startPage(context.Background(), t, "--approvals", dir, "--approver-id", "duty-officer")
	before := files(t, dir)

	body := map[string]string{}
	if err := json.Unmarshal([]byte(answerBody(t, waitingID, "")), &body); err != nil {
		t.Fatal(err)
	}
	body["approver_id"] = "authn:x:y"
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	if code, out := p.post(t, "/api/approve", string(raw)); code != http.StatusBadRequest {
		t.Errorf("an answer naming its approver answered %d %q, want %d", code, out, http.StatusBadRequest)
	}
	if after := files(t, dir); !maps.Equal(before, after) {
		t.Fatal("the directory changed under an answer that was refused")
	}
	p.mustPost(t, "/api/approve", answerBody(t, waitingID, ""))
	code, listing, stderr := invoke(t, "approvals", "list", dir)
	if code != exitOK {
		t.Fatalf("approvals list answered %d: %s", code, stderr)
	}
	if got := fieldOf(t, blockOf(t, listing, waitingID), "answered by"); got != "duty-officer" {
		t.Errorf("the control answer is filed under %q, want the starter's", got)
	}
}
