package inbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policykey"
)

// The inbox's bounds, which a writer of the directory cannot raise.
const (
	// MaxInboxEntries bounds the names one listing of the inbox reads. A
	// directory holding more is read as truncated.
	MaxInboxEntries = 4096
	// MaxAnswersPerApproval bounds the answers one approval takes. More is
	// read as truncated.
	MaxAnswersPerApproval = 16
	// MaxAnswerFileBytes bounds one answer file: a DSSE envelope of a body at
	// approvals.MaxAnswerBodyBytes with its signature.
	MaxAnswerFileBytes = 32768
	// MaxAnswerLabelBytes bounds the label an answer file carries after its
	// approval id.
	MaxAnswerLabelBytes = 64
)

// answerSuffix ends the name of every answer file.
const answerSuffix = ".answer"

// The causes an inbox counts, one per file it left out of a batch.
const (
	InboxForeignName   = "foreign_name"
	InboxNotRegular    = "not_regular"
	InboxTooLarge      = "too_large"
	InboxMalformed     = "malformed"
	InboxOtherApproval = "other_approval"
	InboxUnreadable    = "unreadable"
	InboxTruncated     = "truncated"
	InboxUnremoved     = "unremoved"
)

// ErrInboxPermissions is an inbox a group or the world may write that is not
// sticky, so any writer could remove or replace another's answer.
const ErrInboxPermissions Error = "inbox: the inbox may be written by others and is not sticky"

// Inbox is the directory operators file signed answers in, as the plane
// reads it. Every file in it is untrusted: the plane authenticates each
// answer itself. A name this package does not write, and a file whose body
// names another approval, are left out alone and counted. A file named for
// the approval that cannot be read as an answer, because it is not a regular
// file, cannot be read, is too large or is no envelope, makes the batch
// unjudged: it may be the rejection that wins. A directory past a bound is
// read as truncated.
//
// The documented shape is a directory of the operators' group, writable by
// that group and sticky, so an operator removes only their own answers.
type Inbox struct {
	root *os.Root
	dir  string

	mu     sync.Mutex
	counts map[string]uint64
}

// OpenInbox opens dir and refuses one a group or the world may write that is
// not sticky.
func OpenInbox(dir string) (*Inbox, error) {
	root, err := os.OpenRoot(dir + string(os.PathSeparator) + ".")
	if err != nil {
		return nil, fmt.Errorf("the inbox: %w", err)
	}
	in := &Inbox{root: root, dir: dir, counts: map[string]uint64{}}
	if err := in.judge(); err != nil {
		return nil, errors.Join(err, root.Close())
	}
	return in, nil
}

// Close releases the directory.
func (in *Inbox) Close() error {
	if in == nil || in.root == nil {
		return nil
	}
	return in.root.Close()
}

// judge refuses the directory when others may write it and it is not sticky.
func (in *Inbox) judge() error {
	info, err := in.root.Stat(".")
	if err != nil {
		return fmt.Errorf("the inbox: %w", err)
	}
	if info.Mode().Perm()&writableByOthers != 0 && info.Mode()&fs.ModeSticky == 0 {
		return fmt.Errorf("%w: mode %04o", ErrInboxPermissions, info.Mode().Perm())
	}
	return nil
}

// Batch is what one read of the inbox found for an approval: the
// envelopes, whether a bound stopped the read, and whether a file named for
// the approval could not be read as an answer.
type Batch struct {
	Envelopes []policy.StatementEnvelope
	Truncated bool
	Unjudged  bool
}

// AnswerFileName is the name an answer to approvalID takes under label, which
// tells two operators' answers apart. It refuses an approval id no record can
// be filed under and a label of anything but ASCII letters, digits, "_" and
// "-" within MaxAnswerLabelBytes.
func AnswerFileName(approvalID, label string) (string, error) {
	if err := approvals.CheckApprovalID(approvalID); err != nil {
		return "", err
	}
	if !answerLabel(label) {
		return "", fmt.Errorf("%w: the label is not 1 to %d letters, digits, _ or -", approvals.ErrRecordName, MaxAnswerLabelBytes)
	}
	return approvalID + "." + label + answerSuffix, nil
}

func answerLabel(label string) bool {
	return label != "" && len(label) <= MaxAnswerLabelBytes && approvals.CheckApprovalID(label) == nil
}

// Read returns the answers filed for approvalID, sorted by name. An error is
// a directory that could not be listed or judged, which the caller reads as
// unavailable.
func (in *Inbox) Read(ctx context.Context, approvalID string) (Batch, error) {
	if in == nil || in.root == nil {
		return Batch{}, approvals.ErrClosed
	}
	if err := approvals.CheckApprovalID(approvalID); err != nil {
		return Batch{}, err
	}
	if err := ctx.Err(); err != nil {
		return Batch{}, err
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	if err := in.judge(); err != nil {
		return Batch{}, err
	}
	names, truncated, err := in.list(approvalID)
	if err != nil {
		return Batch{}, err
	}
	out := Batch{Truncated: truncated}
	for _, name := range names {
		env, ok, unjudged := in.readAnswer(name, approvalID)
		if ok {
			out.Envelopes = append(out.Envelopes, env)
		}
		out.Unjudged = out.Unjudged || unjudged
	}
	if out.Truncated {
		in.counts[InboxTruncated]++
	}
	return out, nil
}

// list names the files of approvalID, sorted. A name this package does not
// write is counted and left out; more than MaxInboxEntries names, or more
// than MaxAnswersPerApproval of approvalID, is truncated.
func (in *Inbox) list(approvalID string) ([]string, bool, error) {
	d, err := in.root.Open(".")
	if err != nil {
		return nil, false, err
	}
	entries, readErr := d.ReadDir(MaxInboxEntries + 1)
	if err := errors.Join(ignoreEOF(readErr), d.Close()); err != nil {
		return nil, false, err
	}
	truncated := len(entries) > MaxInboxEntries
	var names []string
	for _, e := range entries[:min(len(entries), MaxInboxEntries)] {
		id, label, ok := strings.Cut(strings.TrimSuffix(e.Name(), answerSuffix), ".")
		if !strings.HasSuffix(e.Name(), answerSuffix) || !ok || approvals.CheckApprovalID(id) != nil || !answerLabel(label) {
			in.counts[InboxForeignName]++
			continue
		}
		if id == approvalID {
			names = append(names, e.Name())
		}
	}
	slices.Sort(names)
	if len(names) > MaxAnswersPerApproval {
		names, truncated = names[:MaxAnswersPerApproval], true
	}
	return names, truncated, nil
}

func ignoreEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

// readAnswer reads one answer file. It counts one that is not a regular
// file, cannot be read, is too large or is no envelope, and reports it
// unjudged; it counts and leaves out alone one whose body names another
// approval. The body is read only for its approvalId here; it is judged after
// its signature verifies, by the plane.
func (in *Inbox) readAnswer(name, approvalID string) (_ policy.StatementEnvelope, ok, unjudged bool) {
	refuse := func(cause string) (policy.StatementEnvelope, bool, bool) {
		in.counts[cause]++
		return policy.StatementEnvelope{}, false, cause != InboxOtherApproval
	}
	info, err := in.root.Lstat(name)
	switch {
	case err != nil:
		return refuse(InboxUnreadable)
	case !info.Mode().IsRegular():
		return refuse(InboxNotRegular)
	}
	f, err := in.root.OpenFile(name, os.O_RDONLY|nonBlocking, 0)
	if err != nil {
		return refuse(InboxUnreadable)
	}
	defer func() { _ = f.Close() }()
	if opened, err := f.Stat(); err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return refuse(InboxNotRegular)
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxAnswerFileBytes+1))
	switch {
	case err != nil:
		return refuse(InboxUnreadable)
	case len(raw) > MaxAnswerFileBytes:
		return refuse(InboxTooLarge)
	}
	env, err := policykey.ParseEnvelope(raw, MaxAnswerFileBytes)
	if err != nil {
		return refuse(InboxMalformed)
	}
	if named, err := approvals.ReadAnswer(env.Payload); err == nil && named.ApprovalID != approvalID {
		return refuse(InboxOtherApproval)
	}
	return env, true, false
}

// Counts is how often each cause left a file out, or truncated a read.
func (in *Inbox) Counts() map[string]uint64 {
	if in == nil {
		return nil
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	return maps.Clone(in.counts)
}

// Usable reports whether the directory can be judged now.
func (in *Inbox) Usable() bool {
	if in == nil || in.root == nil {
		return false
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.judge() == nil
}

// MarshalAnswerFile is the file an operator files env in, refused where the
// inbox would not read it.
func MarshalAnswerFile(env policy.StatementEnvelope) ([]byte, error) {
	return policykey.MarshalEnvelope(env, MaxAnswerFileBytes)
}

// Pruned is what one prune of the inbox did: the answer files it
// removed, and those it may not remove, which are counted and left.
type Pruned struct {
	Removed, Refused int
}

// Prune removes every answer file whose approval live reports no longer held
// and whose modification time is ttl or more before now: nothing reads such
// a file again, and left in place it would fill the inbox's bound. A name
// this package does not write is left alone. An unlink the directory does not
// allow, such as another account's file under the sticky bit when the plane
// does not own the directory, is counted in Refused and never stops the
// prune. An error is a directory that could not be listed or judged.
func (in *Inbox) Prune(ctx context.Context, now time.Time, ttl time.Duration, live func(approvalID string) bool) (Pruned, error) {
	var out Pruned
	if in == nil || in.root == nil {
		return out, approvals.ErrClosed
	}
	if now.IsZero() {
		return out, approvals.ErrZeroTime
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	if err := in.judge(); err != nil {
		return out, err
	}
	d, err := in.root.Open(".")
	if err != nil {
		return out, err
	}
	err = in.pruneEach(ctx, d, now.Add(-ttl), live, &out)
	return out, errors.Join(err, d.Close())
}

// pruneEach reads d a bound's worth of names at a time and prunes each.
func (in *Inbox) pruneEach(ctx context.Context, d *os.File, cutoff time.Time, live func(string) bool, out *Pruned) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, err := d.ReadDir(MaxInboxEntries)
		for _, e := range entries {
			in.pruneOne(e.Name(), cutoff, live, out)
		}
		if errors.Is(err, io.EOF) || (err == nil && len(entries) == 0) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// pruneOne removes name when it is an answer file of an approval no longer
// held, last modified at or before cutoff.
func (in *Inbox) pruneOne(name string, cutoff time.Time, live func(string) bool, out *Pruned) {
	id, label, ok := strings.Cut(strings.TrimSuffix(name, answerSuffix), ".")
	if !strings.HasSuffix(name, answerSuffix) || !ok || approvals.CheckApprovalID(id) != nil || !answerLabel(label) || live(id) {
		return
	}
	info, err := in.root.Lstat(name)
	if err != nil || info.ModTime().After(cutoff) {
		return
	}
	if err := in.root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		out.Refused++
		in.counts[InboxUnremoved]++
		return
	}
	out.Removed++
}

// Entries is how many names the inbox holds, at most MaxInboxEntries, and
// whether it holds more.
func (in *Inbox) Entries() (int, bool, error) {
	if in == nil || in.root == nil {
		return 0, false, approvals.ErrClosed
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	d, err := in.root.Open(".")
	if err != nil {
		return 0, false, err
	}
	entries, readErr := d.ReadDir(MaxInboxEntries + 1)
	if err := errors.Join(ignoreEOF(readErr), d.Close()); err != nil {
		return 0, false, err
	}
	return min(len(entries), MaxInboxEntries), len(entries) > MaxInboxEntries, nil
}
