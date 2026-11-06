package console

import (
	"cmp"
	"net/http"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/keytext"
)

// stateReply is what the page shows: what `approvals list` prints and what
// `pause list` prints, as data, with every sentence the page says about them
// already made. The script adds no words of its own to a record, a listing or
// a pause. Every value from a record, its projection or the pause file passes
// through keytext.Printable, as the commands print it, but for the handles an
// answer or a lift sends back. Pause is null for a page started without a
// pause file.
type stateReply struct {
	ApproverID string         `json:"approver_id"`
	Who        string         `json:"who"`
	Approvals  approvalsReply `json:"approvals"`
	Pause      *pauseReply    `json:"pause"`
}

// approvalsReply is one listing. Error is set when no listing could be made
// at all; Complete is then false and PlaneRunning null, because nothing
// measured either. Records are in the order their requests were held.
type approvalsReply struct {
	Directory    string         `json:"directory"`
	Error        string         `json:"error,omitempty"`
	Complete     bool           `json:"complete"`
	PlaneRunning *bool          `json:"plane_running"`
	Plane        string         `json:"plane"`
	Banner       []string       `json:"banner"`
	Empty        string         `json:"empty"`
	Gone         string         `json:"gone"`
	Problems     []problemReply `json:"problems"`
	Records      []recordReply  `json:"records"`
}

type problemReply struct {
	Name  string `json:"name"`
	Error string `json:"error"`
}

// recordReply is one record as the listing prints it. Expired is the page's
// clock against the expiry, the comparison an answer is refused on. The
// approver's reason is left out, as the listing leaves it out. Status and
// Fields are what the card shows, Answerable whether it offers an answer, and
// Confirm names the call an answer is asked to confirm.
type recordReply struct {
	ApprovalID   string         `json:"approval_id"`
	State        string         `json:"state"`
	Request      string         `json:"request"`
	ActionDigest string         `json:"action_digest"`
	BundleDigest string         `json:"bundle_digest"`
	Expires      string         `json:"expires"`
	Expired      bool           `json:"expired"`
	AnsweredBy   string         `json:"answered_by"`
	AnsweredAt   string         `json:"answered_at"`
	Readable     *readableReply `json:"readable"`
	ReadableNote string         `json:"readable_note,omitempty"`
	Title        string         `json:"title"`
	Status       string         `json:"status"`
	Fields       []fieldReply   `json:"fields"`
	Answerable   bool           `json:"answerable"`
	Confirm      string         `json:"confirm"`
	// Signed is a record held under the signed authority, which the page
	// never answers; SignWith is the commands that do, and Tenant and
	// Project what they sign beside the digest.
	Signed   bool     `json:"signed"`
	Tenant   string   `json:"tenant"`
	Project  string   `json:"project"`
	SignWith []string `json:"sign_with"`
	// requested is when the plane held the request, which orders the cards.
	requested time.Time
}

// fieldReply is one label and its value, as a card shows them.
type fieldReply struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// readableReply is the projection's named fields and nothing else. None of
// them is bound to the digest beside them.
type readableReply struct {
	Principal   string `json:"principal"`
	Agent       string `json:"agent"`
	Action      string `json:"action"`
	Upstream    string `json:"upstream"`
	Resource    string `json:"resource"`
	EffectClass string `json:"effect_class"`
	RuleIDs     string `json:"rule_ids"`
	Requested   string `json:"requested"`
}

// The sentences of a listing.
const (
	planeHolds      = "A plane holds this directory."
	planeAbsent     = "No plane holds this directory, so nothing will consume an answer."
	planeUnknown    = "Cannot say whether a plane holds this directory: no listing could be made."
	notAnEmptyList  = "This is not an empty directory; nothing below is known."
	incompleteList  = "This listing is incomplete: it is not every record in the directory."
	noRecords       = "No records."
	goneFromListing = "This record is no longer in the directory. What is shown is how it last stood; this page cannot say what became of it after that."
)

func (p *page) state(w http.ResponseWriter, r *http.Request, _ any) {
	out := stateReply{ApproverID: keytext.Printable(p.o.ApproverID), Who: p.who(), Approvals: p.listing(r)}
	if p.o.PauseFile != "" {
		out.Pause = pauseState(p.o.PauseFile)
	}
	reply(w, http.StatusOK, out)
}

func (p *page) listing(r *http.Request) approvalsReply {
	out := approvalsReply{Directory: keytext.Printable(p.o.Directory), Gone: goneFromListing, Banner: []string{}, Problems: []problemReply{}, Records: []recordReply{}}
	l, err := p.list(r.Context())
	if err != nil {
		out.Error = keytext.Printable(err.Error())
		out.Plane = planeUnknown
		out.Banner = []string{"No listing could be made: " + out.Error + ".", notAnEmptyList}
		return out
	}
	running := l.PlaneRunning
	out.Complete, out.PlaneRunning = l.Complete, &running
	out.Plane = planeAbsent
	if running {
		out.Plane = planeHolds
	}
	for _, pr := range l.Problems {
		out.Problems = append(out.Problems, problemReply{Name: keytext.Printable(pr.Name), Error: keytext.Printable(pr.Err.Error())})
	}
	if !l.Complete {
		out.Banner = append(out.Banner, incompleteList)
		for _, pr := range out.Problems {
			out.Banner = append(out.Banner, pr.Name+": "+pr.Error)
		}
	}
	now := p.now()
	for _, e := range l.Entries {
		out.Records = append(out.Records, p.recordOf(e, now, running))
	}
	// A card keeps its place on the page while it is open, and a new hold
	// goes after every card already shown: approval ids are random, and an
	// order by them would move a button under the approver's pointer.
	slices.SortStableFunc(out.Records, func(a, b recordReply) int {
		return cmp.Or(a.requested.Compare(b.requested), strings.Compare(a.ApprovalID, b.ApprovalID))
	})
	if l.Complete && len(out.Records) == 0 {
		out.Empty = noRecords
	}
	return out
}

// recordOf renders one entry as renderEntry in the approvals command does,
// and says what became of it with a plane running or not. ApprovalID and
// ActionDigest are the handles an answer carries back, and are kept as the
// record holds them; every value the card shows is printable.
func (p *page) recordOf(e approvals.Entry, now time.Time, planeRunning bool) recordReply {
	a := e.Record.Approval
	rec := recordReply{
		ApprovalID:   e.Record.ApprovalID,
		State:        a.GetState().String(),
		Request:      keytext.Printable(e.Record.RequestID),
		ActionDigest: a.GetActionDigest(),
		BundleDigest: keytext.Printable(a.GetPolicyBundleDigest()),
		Expires:      stamp(a.GetExpiresAt()),
		Expired:      a.GetExpiresAt() == nil || !now.Before(a.GetExpiresAt().AsTime()),
		Title:        "Approval " + keytext.Printable(e.Record.ApprovalID),
		requested:    a.GetRequestedAt().AsTime(),
	}
	if id := a.GetApproverId(); id != "" {
		rec.AnsweredBy, rec.AnsweredAt = keytext.Printable(id), stamp(a.GetDecidedAt())
	}
	switch v := e.View; {
	case v == nil:
		rec.ReadableNote = "none: the projection is missing or would not decode"
	case v.ApprovalID != e.Record.ApprovalID || v.ActionDigest != a.GetActionDigest():
		rec.ReadableNote = "none: the projection beside this record describes another approval"
	default:
		rec.Readable = &readableReply{
			Principal:   keytext.Printable(v.Principal),
			Agent:       keytext.Printable(v.Agent),
			Action:      keytext.Printable(v.Action),
			Upstream:    keytext.Printable(v.Provider),
			Resource:    keytext.Printable(strings.TrimSpace(v.ResourceType + " " + v.ResourceID)),
			EffectClass: keytext.Printable(v.EffectClass),
			RuleIDs:     keytext.Printable(strings.Join(v.RuleIDs, ", ")),
			Requested:   v.RequestedAt.UTC().Format(time.RFC3339),
		}
	}
	if e.Record.HeldUnder() == approvals.HeldUnderSigned {
		rec.Signed = true
		rec.Tenant, rec.Project = keytext.Printable(e.Record.Tenant), keytext.Printable(e.Record.Project)
		rec.SignWith = p.signCommands(e.Record.ApprovalID)
	}
	rec.Status = statusOf(rec, planeRunning)
	rec.Fields = fieldsOf(rec)
	rec.Answerable = a.GetState() == controlv1.ApprovalState_APPROVAL_STATE_PENDING && !rec.Expired && p.mayClaim(e.Record)
	rec.Confirm = confirmOf(rec)
	return rec
}

// statusOf is the one sentence a card says of its record. It claims no more
// than the record: an approval can resume a retry and is never said to have
// run, and whether a retry spent it is the plane's own record, which this page
// does not read.
func statusOf(r recordReply, planeRunning bool) string {
	by := ""
	if r.AnsweredBy != "" {
		by = " by " + r.AnsweredBy
	}
	switch r.State {
	case controlv1.ApprovalState_APPROVAL_STATE_PENDING.String():
		switch {
		case r.Expired:
			return "Past its expiry. No answer is accepted."
		case r.Signed:
			return "Held under the signed authority until " + r.Expires +
				". This page answers nothing: an operator signs the answer with the command below."
		}
		return "Waiting for an answer until " + r.Expires + "."
	case controlv1.ApprovalState_APPROVAL_STATE_APPROVED.String():
		switch {
		case r.Expired:
			return "Approved" + by + ". It expired before a retry used it."
		case !planeRunning:
			return "Approved" + by + ". No plane holds this directory, so the call it was held for will not run."
		}
		return "Approved" + by + ". The call can resume on the agent's retry before " + r.Expires +
			", once; this page cannot see whether a retry spent it."
	case controlv1.ApprovalState_APPROVAL_STATE_REJECTED.String():
		return "Rejected" + by + "."
	}
	return "State " + r.State + "."
}

// fieldsOf is a card's labels and values, in the order the listing prints
// them.
func fieldsOf(r recordReply) []fieldReply {
	out := []fieldReply{
		{"state", strings.ToLower(strings.TrimPrefix(r.State, "APPROVAL_STATE_"))},
		{"request", r.Request},
		{"action digest", keytext.Printable(r.ActionDigest)},
		{"bundle digest", r.BundleDigest},
		{"expires", r.Expires},
	}
	if r.AnsweredBy != "" {
		out = append(out, fieldReply{"answered by", r.AnsweredBy}, fieldReply{"answered at", r.AnsweredAt})
	}
	if r.Signed {
		out = append(out, fieldReply{"tenant", r.Tenant}, fieldReply{"project", r.Project})
		for _, c := range r.SignWith {
			out = append(out, fieldReply{"sign with", c})
		}
	}
	if v := r.Readable; v != nil {
		return append(out,
			fieldReply{"principal", v.Principal},
			fieldReply{"agent", v.Agent},
			fieldReply{"action", v.Action},
			fieldReply{"upstream", v.Upstream},
			fieldReply{"resource", v.Resource},
			fieldReply{"effect class", v.EffectClass},
			fieldReply{"rule ids", v.RuleIDs},
			fieldReply{"requested", v.Requested},
		)
	}
	return append(out, fieldReply{"readable", r.ReadableNote})
}

// confirmHexDigits is how much of the action digest a confirmation shows.
const confirmHexDigits = 12

// confirmOf names the call an answer is about: its tool and its upstream as
// the projection has them, and the head of the digest the answer is bound to.
func confirmOf(r recordReply) string {
	tool, upstream := "a tool this page cannot read", "an upstream this page cannot read"
	if v := r.Readable; v != nil {
		if v.Action != "" {
			tool = "tool " + v.Action
		}
		if v.Upstream != "" {
			upstream = "upstream " + v.Upstream
		}
	}
	head := strings.TrimPrefix(r.ActionDigest, "sha256:")
	if len(head) > confirmHexDigits {
		head = head[:confirmHexDigits]
	}
	return tool + " on " + upstream + ", action digest " + keytext.Printable(head)
}

// stamp renders a time in UTC, or says there is none.
func stamp(ts *timestamppb.Timestamp) string {
	if ts == nil {
		return "none"
	}
	return ts.AsTime().UTC().Format(time.RFC3339)
}

// signCommands are the approvals commands that sign an answer to approvalID,
// approve and then reject, with the inbox this page was told of, each path
// one shell word and the directory after "--", so a name starting with a dash
// is not read as a flag.
func (p *page) signCommands(approvalID string) []string {
	inbox := "<the plane's approvals.inbox_dir>"
	if p.o.Inbox != "" {
		inbox = shellWord(p.o.Inbox)
	}
	var out []string
	for _, verb := range []string{"approve", "reject"} {
		out = append(out, keytext.Printable(brand.CLI+" approvals "+verb+" --key <operator key file> --inbox "+inbox+" -- "+
			shellWord(p.o.Directory)+" "+shellWord(approvalID)))
	}
	return out
}

// shellWord is s as one word of a POSIX shell: as it stands when it holds
// only characters no shell treats specially, single-quoted otherwise.
func shellWord(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./:=+@%,") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// mayClaim reports whether this page may file a claim for rec: a page over
// the approver's handle, for a record held under the directory.
func (p *page) mayClaim(rec approvals.Record) bool {
	return p.o.Approvals != nil && rec.HeldUnder() != approvals.HeldUnderSigned
}

// who is the sentence the page says of whoever answers through it.
func (p *page) who() string {
	if p.o.Approvals == nil {
		return "This page holds no operator key and answers nothing; each hold shows the command that signs its answer."
	}
	return "Answering as " + keytext.Printable(p.o.ApproverID) +
		". This name is recorded on each answer as given; nothing checks it. A hold under the signed authority shows the command that signs it."
}
