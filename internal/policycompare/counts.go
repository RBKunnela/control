package policycompare

// unlabelled is the label tally of the cases no label names.
const unlabelled = "unlabelled"

// count tallies the rows, each count over its own denominator: every case
// read; the cases evaluated on both sides and the unknown ones out of those
// read; the changes out of the cases compared, which are those not unknown;
// and each label's changes out of the cases it labels.
func count(rows []CaseRow) Counts {
	c := Counts{
		Read:     len(rows),
		BySource: map[Source]int{SourceCase: 0, SourceEvidence: 0},
		Unknown:  UnknownCount{Of: len(rows), ByReason: map[Reason]int{}},
		ByLabel:  map[string]Tally{string(Attack): {}, string(Legitimate): {}, unlabelled: {}},
	}
	for _, r := range Reasons() {
		c.Unknown.ByReason[r] = 0
	}
	c.EvaluatedBothSides.Of, c.Compared.Of = len(rows), len(rows)
	for _, row := range rows {
		c.BySource[row.Source]++
		if row.Before.Evaluated && row.After.Evaluated {
			c.EvaluatedBothSides.Count++
		}
		key := unlabelled
		if row.Label != nil {
			key = string(*row.Label)
		}
		t := c.ByLabel[key]
		t.Of++
		switch row.Change {
		case Unchanged:
			c.Change.Unchanged++
			t.Unchanged++
		case Stricter:
			c.Change.Stricter++
			t.Stricter++
		case Looser:
			c.Change.Looser++
			t.Looser++
		case Other:
			c.Change.Other++
			t.Other++
		default:
			c.Unknown.Count++
			if row.UnknownReason != nil {
				c.Unknown.ByReason[*row.UnknownReason]++
			}
			t.Unknown++
		}
		c.ByLabel[key] = t
	}
	c.Compared.Count = c.Read - c.Unknown.Count
	c.Change.Of = c.Compared.Count
	return c
}
