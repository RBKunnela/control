package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/scenario"
)

func (p *play) pause(ctx context.Context, i int, ps *scenario.Pause) error {
	if p.r.plane.pauseFile == "" {
		return errors.New("the plane reads no pause file")
	}
	args := []string{"pause", "add"}
	switch sc := ps.Scope; sc.Kind {
	case pause.ScopeGlobal:
		args = append(args, "--global")
	case pause.ScopeProvider:
		args = append(args, "--provider", sc.Provider)
	default:
		args = append(args, "--provider", sc.Provider, "--action", sc.Action)
		if sc.Name != "" {
			args = append(args, "--name", sc.Name)
		}
	}
	reason := ps.Reason + " [scenario " + rand.Text() + "]"
	if ps.Reason == "" {
		reason = reason[1:]
	}
	if len(reason) > pause.MaxReasonBytes {
		return fmt.Errorf("the reason leaves no room under the pause file's bound of %d bytes for the marker the runner adds to it", pause.MaxReasonBytes)
	}
	args = append(args, "--reason", reason)
	before, err := p.entryLines(ctx)
	if err != nil {
		return err
	}
	out, err := p.r.control.run(ctx, append(args, "--", p.r.plane.pauseFile)...)
	id := strings.TrimSuffix(out, "\n")
	if err == nil && (id == "" || strings.ContainsAny(id, "\r\n")) {
		err = fmt.Errorf("%s pause add printed %q, not one entry id", brand.CLI, out)
	}
	if err != nil {
		// An add can write its entry and still fail, and finish knows only the
		// ids an add printed.
		return errors.Join(err, p.removeOwn(context.WithoutCancel(ctx), before, ps.Scope, reason))
	}
	p.added[i] = id
	p.entries++
	return p.r.pauseRead(ctx, p.entries)
}

// entryLines is every entry the pause file holds, by id, as the line pause
// list prints for it.
func (p *play) entryLines(ctx context.Context) (map[string]string, error) {
	out, err := p.r.control.run(ctx, "pause", "list", p.r.plane.pauseFile)
	if err != nil {
		return nil, fmt.Errorf("listing the pause file's entries: %w", err)
	}
	lines := map[string]string{}
	if out == "no entries\n" {
		return lines, nil
	}
	for line := range strings.Lines(out) {
		line = strings.TrimSuffix(line, "\n")
		id, _, _ := strings.Cut(line, " ")
		if id == "" {
			return nil, fmt.Errorf("%s pause list printed a line that names no entry: %q", brand.CLI, line)
		}
		lines[id] = line
	}
	return lines, nil
}

// removeOwn removes the one entry new since before whose line carries scope
// and reason, which holds a marker no one else was given. Anything else new
// may be an operator's, an emergency stop among them, so when no new entry or
// more than one is the add's, none is removed.
func (p *play) removeOwn(ctx context.Context, before map[string]string, scope pause.Scope, reason string) error {
	now, err := p.entryLines(ctx)
	if err != nil {
		return fmt.Errorf("the add may have left an entry: %w", err)
	}
	var fresh, own []string
	for _, id := range slices.Sorted(maps.Keys(now)) {
		if _, ok := before[id]; ok {
			continue
		}
		fresh = append(fresh, id)
		if listsAs(now[id], id, scope, reason) {
			own = append(own, id)
		}
	}
	switch {
	case len(fresh) == 0:
		return nil
	case len(own) != 1:
		return fmt.Errorf("removed no entry: %d of the %d entries new since the add carry its scope and marker, and any of %s may be its",
			len(own), len(fresh), strings.Join(fresh, ", "))
	}
	if _, err := p.r.control.run(ctx, "pause", "remove", "--", p.r.plane.pauseFile, own[0]); err != nil {
		return fmt.Errorf("removing the entry %s the add left: %w", own[0], err)
	}
	return nil
}

// listsAs reports whether line is how pause list prints the entry id with
// scope and reason, at whatever creation time.
func listsAs(line, id string, scope pause.Scope, reason string) bool {
	rest, ok := strings.CutPrefix(line, id+" "+oneLine(listedScope(scope))+" created ")
	if !ok {
		return false
	}
	created, quoted, ok := strings.Cut(rest, " reason ")
	return ok && !strings.Contains(created, " ") && quoted == oneLine(strconv.Quote(reason))
}

// listedScope is a scope as pause list prints it.
func listedScope(s pause.Scope) string {
	switch s.Kind {
	case pause.ScopeGlobal:
		return "global"
	case pause.ScopeProvider:
		return "provider " + s.Provider
	}
	if s.Name == "" {
		return s.Action + " " + s.Provider
	}
	return s.Action + " " + s.Provider + "/" + s.Name
}

func (p *play) unpause(ctx context.Context, u *scenario.Unpause) error {
	id, ok := p.added[u.Step]
	if !ok {
		return fmt.Errorf("step[%d] added no pause entry", u.Step)
	}
	if _, err := p.r.control.run(ctx, "pause", "remove", "--", p.r.plane.pauseFile, id); err != nil {
		return err
	}
	delete(p.added, u.Step)
	p.entries--
	return p.r.pauseRead(ctx, p.entries)
}
