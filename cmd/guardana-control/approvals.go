package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/brand"
)

// The names these commands report themselves under, which are the words that
// reach them.
const (
	listName    = "approvals list"
	approveName = "approvals approve"
	rejectName  = "approvals reject"
)

// approvalAuthority is what the help and docs/reference/cli.md both say about
// who may answer an approval. Whoever can write the directory can approve; the
// approver id is recorded beside the answer and nothing authenticates it.
const approvalAuthority = "Write access to the approvals directory is the approval authority:\n" +
	"--approver-id is a claim recorded as given, never an identity.\n" +
	"An id that could read as authn:, mixes scripts or holds a hidden or restyled character is refused."

// answerForm is how the two answering commands spell what follows their two
// words. The flags come first because the flag package stops reading them at
// the first argument that is not one.
const answerForm = "--approver-id <id> [--reason <text>] <dir> <approval-id>"

// unbound is what a listing says, once and before the records, about the
// readable fields beside each digest: the binding is over the authorized
// argument bytes, which no record holds, so nothing printed here can be
// checked against the digest it sits beside.
const unbound = "the readable fields below come from a projection and are not bound to the\n" +
	"action digest beside them: the binding is over the authorized argument\n" +
	"bytes, which no record holds"

// errIncomplete is a listing that is neither the whole directory nor an empty
// one. Printing it without saying so would read as "these are all the
// approvals there are".
var errIncomplete = errors.New("the listing is incomplete: what it shows is not every record under the directory")

// answer is what an approver names beside the approval they are answering.
type answer struct{ approverID, reason string }

// answerFlags declares the flags the two answering commands share, writing the
// flag package's own diagnostics to out. The help's form and the parser both
// come from here, and a test holds the one to the other.
func answerFlags(command string, out io.Writer) (*flag.FlagSet, *answer) {
	flags := commandFlags(command, out)
	var a answer
	flags.StringVar(&a.approverID, "approver-id", "", "who is answering, recorded as claimed and never authenticated")
	flags.StringVar(&a.reason, "reason", "", "why, recorded on the approval")
	return flags, &a
}

// answerFlagSet is the command listing's view of those flags.
func answerFlagSet(command string, out io.Writer) *flag.FlagSet {
	flags, _ := answerFlags(command, out)
	return flags
}

func approveCommand(args []string, stdout, stderr io.Writer) int {
	return answerApproval(approveName, controlv1.ApprovalState_APPROVAL_STATE_APPROVED, args, stdout, stderr)
}

func rejectCommand(args []string, stdout, stderr io.Writer) int {
	return answerApproval(rejectName, controlv1.ApprovalState_APPROVAL_STATE_REJECTED, args, stdout, stderr)
}

// answerApproval parses one command's own arguments and files one answer. Both
// commands require an approver id, including the one that refuses: an answer
// nobody claims tells whoever reads the evidence later nothing at all.
func answerApproval(command string, state controlv1.ApprovalState, args []string, stdout, stderr io.Writer) int {
	flags, ans := answerFlags(command, stderr)
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if flags.NArg() != 2 {
		return usageError(stderr, command, "takes a directory and an approval id, with every flag before them")
	}
	if ans.approverID == "" {
		return usageError(stderr, command, "--approver-id names who is answering; an approval nobody claims is not an answer")
	}
	store, err := approvals.OpenApprover(flags.Arg(0))
	if err != nil {
		return fail(stderr, command, err)
	}
	status := fileAnswer(store, command, flags.Arg(1), state, *ans, stdout, stderr)
	if err := store.Close(); err != nil && status == exitOK {
		return fail(stderr, command, err)
	}
	return status
}

// fileAnswer writes the answer and reports what the store made of it. The
// clock is this process's: the store compares an answer against the approval's
// expiry, and an approver's machine is where that comparison is made.
//
// An answer written while no plane holds the directory is a success and exits
// zero: the record is on disk and a plane that journals its holds reads it.
// The operator is told what that means on stderr, because the call it was held
// for will not run whatever they do next.
func fileAnswer(store *approvals.Approver, command, id string, state controlv1.ApprovalState, ans answer, stdout, stderr io.Writer) int {
	done, err := store.Answer(context.Background(), id, state, ans.approverID, ans.reason, time.Now())
	if err != nil {
		if hint := answerHint(err); hint != "" {
			return fail(stderr, command, fmt.Errorf("%w; %s", err, hint))
		}
		return fail(stderr, command, err)
	}
	line := fmt.Sprintf("approval %s: %s by %s\n", oneLine(id), verb(state), oneLine(ans.approverID))
	if _, err := io.WriteString(stdout, line); err != nil {
		return fail(stderr, command, fmt.Errorf("writing to standard output: %w", err))
	}
	if !done.PlaneRunning {
		for _, fact := range noPlaneNotice {
			writeLine(stderr, brand.CLI+": "+command+": "+fact)
		}
	}
	return exitOK
}

// noPlaneNotice is what an approver is told when the answer was written and no
// plane was there to wait for it. It is four facts rather than a warning,
// because each of them changes what the operator does next: what is true of
// the directory, what becomes of the call, that the answer was written all the
// same, and what the next plane makes of it.
var noPlaneNotice = [...]string{
	"no plane holds this directory, so nothing is waiting for this answer",
	"the call this approval was held for will not run: a hold does not survive the plane stopping",
	"the answer is written to the directory all the same",
	"a plane that keeps a hold journal records it on that call's trail, as a decision that came too late to resume it",
}

// verb names what was filed, in the word the record now carries.
func verb(state controlv1.ApprovalState) string {
	if state == controlv1.ApprovalState_APPROVAL_STATE_APPROVED {
		return "approved"
	}
	return "rejected"
}

// answerHint says what an operator can do about a refusal, which the store's
// sentinel alone does not: which of the states an answer can meet this record
// is in, and that the directory was left as it was.
func answerHint(err error) string {
	switch {
	case errors.Is(err, approvals.ErrOutcomeUnknown):
		return "the plane may have read this answer before the failed write was taken back; run approvals list before answering again"
	case errors.Is(err, approvals.ErrApprovalConsumed):
		return "the plane consumed this approval already; nothing was written"
	case errors.Is(err, approvals.ErrResolved):
		return "the plane closed this request without resuming it; nothing was written"
	case errors.Is(err, approvals.ErrApprovalAnswered):
		return "an approver answered this approval already; nothing was written"
	case errors.Is(err, approvals.ErrApprovalExpired):
		return "the approval is past its expiry; nothing was written"
	case errors.Is(err, approvals.ErrNoApproval):
		return "this directory holds no record under that approval id; nothing was written"
	}
	return ""
}

// approvalsList prints what is waiting under dir and what became of what is
// not. A directory that is not an approvals store is refused rather than
// printed as an empty one.
func approvalsList(dir string, stdout, stderr io.Writer) int {
	store, err := approvals.OpenApprover(dir)
	if err != nil {
		return fail(stderr, listName, err)
	}
	status := printListing(store, dir, stdout, stderr)
	if err := store.Close(); err != nil && status == exitOK {
		return fail(stderr, listName, err)
	}
	return status
}

// printListing writes the listing to stdout and every record it could not read
// to stderr. A listing the store reports incomplete fails: it is not every
// record under the directory, and nothing here can say which are missing.
func printListing(store *approvals.Approver, dir string, stdout, stderr io.Writer) int {
	l, err := store.List(context.Background())
	if err != nil {
		return fail(stderr, listName, err)
	}
	var b strings.Builder
	renderListing(&b, dir, l)
	if _, err := io.WriteString(stdout, b.String()); err != nil {
		return fail(stderr, listName, fmt.Errorf("writing to standard output: %w", err))
	}
	for _, p := range l.Problems {
		writeLine(stderr, brand.CLI+": "+listName+": "+oneLine(p.Name)+": "+oneLine(p.Err.Error()))
	}
	if !l.Complete {
		return fail(stderr, listName, errIncomplete)
	}
	return exitOK
}

func renderListing(b *strings.Builder, dir string, l approvals.Listing) {
	plane := "no plane holds this directory, so nothing will consume an answer"
	if l.PlaneRunning {
		plane = "a plane holds this directory"
	}
	fmt.Fprintf(b, "%s in %s\n%s\n%s\n", plural(len(l.Entries), "record", "records"), oneLine(dir), plane, unbound)
	for _, e := range l.Entries {
		b.WriteString("\n")
		renderEntry(b, e)
	}
}

// renderEntry writes one record: what the plane wrote and can read back, then
// the readable fields, and where they are not there it says so rather than
// leaving a reader to read absence as emptiness.
func renderEntry(b *strings.Builder, e approvals.Entry) {
	a := e.Record.Approval
	fmt.Fprintf(b, "approval %s\n", oneLine(e.Record.ApprovalID))
	field(b, "state", a.GetState().String())
	field(b, "resolution", e.Record.Resolution.String())
	field(b, "request", e.Record.RequestID)
	field(b, "action digest", a.GetActionDigest())
	field(b, "bundle digest", a.GetPolicyBundleDigest())
	field(b, "expires", stamp(a.GetExpiresAt()))
	if id := a.GetApproverId(); id != "" {
		field(b, "answered by", id)
		field(b, "answered at", stamp(a.GetDecidedAt()))
	}
	switch {
	case e.View == nil:
		field(b, "readable", "none: the projection is missing or would not decode")
	case e.View.ApprovalID != e.Record.ApprovalID || e.View.ActionDigest != a.GetActionDigest():
		field(b, "readable", "none: the projection beside this record describes another approval")
	default:
		renderView(b, *e.View)
	}
}

// renderView writes the projection's fields. It prints the named fields and
// nothing else, so free text the envelope carried cannot reach a listing.
func renderView(b *strings.Builder, v approvals.View) {
	field(b, "principal", v.Principal)
	field(b, "agent", v.Agent)
	field(b, "action", v.Action)
	field(b, "upstream", v.Provider)
	field(b, "resource", strings.TrimSpace(v.ResourceType+" "+v.ResourceID))
	field(b, "effect class", v.EffectClass)
	field(b, "rule ids", strings.Join(v.RuleIDs, ", "))
	field(b, "requested", v.RequestedAt.UTC().Format(time.RFC3339))
}

// field writes one label and one value, every value through oneLine: a record
// and its projection are files an approver's directory holds, and a value with
// a line break in it could otherwise forge the next line of a listing.
func field(b *strings.Builder, label, value string) {
	fmt.Fprintf(b, "  %-14s %s\n", label, oneLine(value))
}

// stamp renders a time in UTC, or says there is none: an empty column would
// read as a zero time rather than as a field the record does not carry.
func stamp(ts *timestamppb.Timestamp) string {
	if ts == nil {
		return "none"
	}
	return ts.AsTime().UTC().Format(time.RFC3339)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}
