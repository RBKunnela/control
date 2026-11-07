package console

import (
	"strings"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/keytext"
	"github.com/guardana/control/internal/pause"
)

// writesNoPause reports whether this page may not write the pause file: a
// page of an operator under the signed authority, or a file that is signed.
// Either takes a pause only from an operator key, which this page never
// holds.
func (p *page) writesNoPause() bool {
	if p.o.Reader != nil {
		return true
	}
	l, err := pause.List(p.o.PauseFile)
	return err == nil && l.Signed != nil
}

// noPause is the refusal of a pause this page may not write, naming the
// command that signs it.
func noPause(command string) string {
	return "this pause file is written only signed by an operator key, which this page never holds, so nothing was written; " +
		"sign it with: " + command
}

// signFlags are the pause flags of a signed write: the operator's key and
// the plane's roster and trust root, which pause add and remove need beside
// it and this page does not know.
const signFlags = "--key <operator key file> --roster <the plane's trust.roster> --root-key <the plane's trust.root_public_key>"

// pauseCommand is the pause add command that signs the pause b asks for.
func (p *page) pauseCommand(b *pauseBody) string {
	words := []string{brand.CLI, "pause", "add", signFlags}
	s := b.Scope
	switch pause.ScopeKind(s.Kind) {
	case pause.ScopeGlobal:
		words = append(words, "--global")
	case pause.ScopeRun, pause.ScopeAgent, pause.ScopePrincipal:
		words = append(words, "--"+s.Kind, shellWord(s.ID))
	default:
		words = append(words, "--provider", shellWord(s.Provider))
		if s.Action != "" {
			words = append(words, "--action", shellWord(s.Action))
		}
		if s.Name != "" {
			words = append(words, "--name", shellWord(s.Name))
		}
	}
	if b.Reason != "" {
		words = append(words, "--reason", shellWord(b.Reason))
	}
	return keytext.Printable(strings.Join(append(words, "--", shellWord(p.o.PauseFile)), " "))
}

// unpauseCommand is the pause remove command that signs the lift of id.
func (p *page) unpauseCommand(id string) string {
	return keytext.Printable(brand.CLI + " pause remove " + signFlags + " -- " + shellWord(p.o.PauseFile) + " " + shellWord(id))
}
