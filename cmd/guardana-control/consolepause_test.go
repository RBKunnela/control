package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/pause"
)

// shellWords splits line as a POSIX shell splits words made of plain
// characters, single quotes and backslash escapes, which is all the page
// prints.
func shellWords(t *testing.T, line string) []string {
	t.Helper()
	var words []string
	var word strings.Builder
	inWord, quoted := false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quoted && c == '\'':
			quoted = false
		case quoted:
			word.WriteByte(c)
		case c == '\'':
			quoted, inWord = true, true
		case c == '\\' && i+1 < len(line):
			i++
			word.WriteByte(line[i])
			inWord = true
		case c == ' ':
			if inWord {
				words, inWord = append(words, word.String()), false
				word.Reset()
			}
		default:
			word.WriteByte(c)
			inWord = true
		}
	}
	if quoted {
		t.Fatalf("%q ends inside a quote", line)
	}
	if inWord {
		words = append(words, word.String())
	}
	return words
}

// printedCommand posts body to path on a page that writes no pause, and
// returns the command its refusal names, as words after the binary's name,
// with the placeholders filled from fill.
func printedCommand(t *testing.T, p *runningPage, path, body string, fill *strings.Replacer) []string {
	t.Helper()
	code, out := p.post(t, path, body)
	var refused struct{ Error string }
	if err := json.Unmarshal([]byte(out), &refused); err != nil || code != http.StatusConflict {
		t.Fatalf("%s answered %d %q, want 409", path, code, out)
	}
	_, command, ok := strings.Cut(refused.Error, "sign it with: ")
	if !ok {
		t.Fatalf("%s names no command: %q", path, refused.Error)
	}
	words := shellWords(t, fill.Replace(command))
	if len(words) == 0 || words[0] != brand.CLI {
		t.Fatalf("%s names %q, not a command of %s", path, command, brand.CLI)
	}
	return words[1:]
}

// holdsSignedEntry fails unless the file at path is signed and holds one
// entry, with want's id, scope and reason.
func holdsSignedEntry(t *testing.T, path string, want pause.Entry) {
	t.Helper()
	l, err := pause.List(path)
	if err != nil || l.Signed == nil || len(l.Entries) != 1 {
		t.Fatalf("the file holds %+v, %v; want one signed entry", l, err)
	}
	if e := l.Entries[0]; e.ID != want.ID || e.Scope != want.Scope || e.Reason != want.Reason {
		t.Errorf("the file holds %+v, want %+v", e, want)
	}
}

// TestThePageNamesPauseCommandsTheCLIRuns: the pause and the lift a page
// refuses on a signed pause file are each named as a command that, with its
// placeholders filled in, the pause command runs: the add leaves the scope
// and reason asked for, signed, and the remove leaves no entry.
func TestThePageNamesPauseCommandsTheCLIRuns(t *testing.T) {
	keyFile, pub, _ := operatorKey(t)
	judge := rosterOf(t, pub)
	file := signedInitialized(t, keyFile)
	dir, _ := newStore(t)
	p := startPage(context.Background(), t, "--approvals", dir, "--pause", file, "--approver-id", "duty-officer")
	fill := strings.NewReplacer("<operator key file>", keyFile, "<the plane's trust.roster>", judge[1],
		"<the plane's trust.root_public_key>", judge[3])

	const run = "run-0123456789abcdef0123456789abcdef"
	add := printedCommand(t, p, "/api/pause", `{"scope":{"kind":"run","id":"`+run+`"},"reason":"the card's fraud"}`, fill)
	code, id, stderr := invoke(t, add...)
	id = strings.TrimSpace(id)
	if code != exitOK || !drawnID.MatchString(id) {
		t.Fatalf("the printed add %q answered %d: %q %q", add, code, id, stderr)
	}
	holdsSignedEntry(t, file, pause.Entry{ID: id, Scope: pause.Scope{Kind: pause.ScopeRun, ID: run}, Reason: "the card's fraud"})

	remove := printedCommand(t, p, "/api/unpause", `{"id":"`+id+`"}`, fill)
	if code, _, stderr := invoke(t, remove...); code != exitOK {
		t.Fatalf("the printed remove %q answered %d: %q", remove, code, stderr)
	}
	if l, err := pause.List(file); err != nil || l.Signed == nil || len(l.Entries) != 0 {
		t.Errorf("after the printed remove the file holds %+v, %v", l, err)
	}
}
