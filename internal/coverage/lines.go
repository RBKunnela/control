package coverage

import (
	"fmt"
	"strings"
)

// Lines prints the map: per path its line, then its plane, source and join
// lines indented beside it, then a row per undeclared egress host and a line
// counting those cut, then a row per egress source whose import refused a
// line, then a row per egress source that is not live, and last the standing
// row for undeclared paths.
func (r *Report) Lines() []string {
	var out []string
	for _, p := range r.Paths {
		out = append(out, fmt.Sprintf("%s %s: %s", p.Path.ID, stateWithTrust(p), p.Basis))
		for _, l := range p.Planes {
			out = append(out, fmt.Sprintf("  plane %s: %s: %s", printable(l.Plane), l.State, l.Basis))
		}
		for _, l := range p.Sources {
			state := l.State.String()
			if l.State == Observed {
				state += ", " + trustName(l.Trust) + sampledWord(l.Sampled)
			}
			out = append(out, fmt.Sprintf("  source %s: %s: %s", printable(l.SourceID), state, l.Basis))
		}
		if p.State >= Decided && len(p.Path.Sources) == 0 {
			out = append(out, "  join: none checked: no source is named for it")
		}
		out = append(out, joinLines(p.Joins)...)
	}
	out = append(out, undeclaredLines(r.Undeclared, r.UndeclaredCut)...)
	out = append(out, refusedLines(r.Refused)...)
	out = append(out, unseenLines(r.Unseen)...)
	return append(out, UndeclaredRow)
}

func stateWithTrust(p PathCoverage) string {
	if p.State == Observed {
		return p.State.String() + ", " + trustName(p.Trust) + sampledWord(p.Sampled)
	}
	return p.State.String()
}

func sampledWord(sampled bool) string {
	if sampled {
		return ", sampled"
	}
	return ""
}

// joinLines counts the joins, names every call around the plane, and counts
// the joins not checked by why.
func joinLines(joins []JoinCheck) []string {
	if len(joins) == 0 {
		return nil
	}
	counts := map[Join]int{}
	var around, whys []string
	why := map[string]int{}
	for _, j := range joins {
		counts[j.Join]++
		switch j.Join {
		case JoinAround:
			around = append(around, fmt.Sprintf("  join %s: %s", printable(j.ObservationID), JoinAround))
		case JoinNotChecked:
			if why[j.Why] == 0 {
				whys = append(whys, j.Why)
			}
			why[j.Why]++
		}
	}
	var parts []string
	for _, k := range []Join{Joined, JoinAround, JoinNotChecked} {
		if counts[k] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[k], map[Join]string{Joined: "joined",
				JoinAround: "around the plane", JoinNotChecked: "not checked"}[k]))
		}
	}
	out := append([]string{"  join: " + strings.Join(parts, ", ")}, around...)
	for _, w := range whys {
		out = append(out, fmt.Sprintf("  join not checked: %d (%s)", why[w], w))
	}
	return out
}
