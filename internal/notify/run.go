package notify

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
	"github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/findinglog"
)

// Options name one run.
type Options struct {
	// FindingsDir holds the findings log, findinglog.FileName.
	FindingsDir string
	// StateDir is the state, a directory only this account may enter.
	StateDir string
	// Init starts a state in a directory without a marker, with an empty
	// delivered list, so every alert is delivered again. Over a started state
	// it is ErrInitialised.
	Init bool
	// Program and Args are run without a shell, once per delivery, in this
	// process's working directory, with only PATH, HOME, LANG, LC_ALL, TMPDIR,
	// USER and the variables Env names of its environment, each where set.
	Program string
	Args    []string
	// Env names the variables of this process's environment the program
	// also receives; each must be set here.
	Env []string
	// Timeout bounds one delivery; at it the program's group is killed.
	Timeout time.Duration
	// Stdout and Stderr take the program's output; a nil one discards it.
	Stdout, Stderr io.Writer
}

// Summary counts what one run did with each finding record it read. A
// caller exits 1 when Failed or Unclosed is not zero.
type Summary struct {
	Delivered, AlreadyDelivered, Failed, Inform int
	// Unclosed counts the bytes past the log's last write a report closed
	// when no writer held the log: a write that will never be closed.
	Unclosed int64
	// Failures name each failed delivery by its key, in log order.
	Failures []Failure
}

// Failure is one delivery not marked: its key and why.
type Failure struct {
	Key string
	Err error
}

// fileOps are the calls a mark makes on the delivered list, so a test can
// make either fail between a program's exit and the mark, and the open of
// the log for its lines, so a test can change the log after it was judged.
type fileOps struct {
	write   func(*os.File, []byte) (int, error)
	sync    func(*os.File) error
	openLog func(path string) (*os.File, error)
}

var osOps = fileOps{write: (*os.File).Write, sync: (*os.File).Sync, openLog: openLog}

func openLog(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|openFlags, 0) //nolint:gosec // G304: the operator's findings directory, which ReadFile has just judged
}

// Run hands each alert of the findings log that the state has not marked, in
// log order, to the program: the record on its standard input as the one
// line the log carries, which the program must exit 0 on within the timeout
// for the key, the finding id and verdict, to be marked and synced. A program
// that exits otherwise, cannot start or times out is a Failure, and the run
// moves on to the next alert; the next run retries it. An inform finding is
// counted and left alone.
//
// An error stops the run where it stands: a state or a log refused, a log
// whose first line is not the one the state recorded (ErrOtherLog), a log
// line that is not the record read for it (ErrChanged), a state another run
// holds (ErrLocked), ctx done, or a mark that did not reach the disk
// (ErrMark), whose record the next run delivers again.
func Run(ctx context.Context, o Options) (Summary, error) { return run(ctx, o, osOps) }

func run(ctx context.Context, o Options, ops fileOps) (Summary, error) {
	if err := o.check(); err != nil {
		return Summary{}, err
	}
	if !supported || !files.PermissionBits {
		return Summary{}, ErrUnsupported
	}
	s, err := openState(o.StateDir, o.Init, ops)
	if err != nil {
		return Summary{}, err
	}
	d := &deliveries{o: o, s: s}
	err = d.all(ctx)
	return d.sum, errors.Join(err, s.close())
}

func (o Options) check() error {
	switch {
	case o.FindingsDir == "":
		return fmt.Errorf("%w: no findings directory", ErrOptions)
	case o.StateDir == "":
		return fmt.Errorf("%w: no state directory", ErrOptions)
	case o.Program == "":
		return fmt.Errorf("%w: no program", ErrOptions)
	case o.Timeout <= 0:
		return fmt.Errorf("%w: a timeout of %s", ErrOptions, o.Timeout)
	}
	for _, name := range o.Env {
		if err := envName(name); err != nil {
			return err
		}
	}
	return nil
}

// envName refuses a name no variable can have, or one this process does not
// set. A name holding '=' may hold a value, so that refusal does not quote it.
func envName(name string) error {
	if name == "" || strings.ContainsAny(name, "=\x00") {
		return fmt.Errorf("%w: a variable to pass is named with no name, an '=' or a NUL", ErrOptions)
	}
	if _, ok := os.LookupEnv(name); !ok {
		return fmt.Errorf("%w: the variable %q to pass is not set", ErrOptions, name)
	}
	return nil
}

// deliveries is one run over one log.
type deliveries struct {
	o   Options
	s   *state
	sum Summary
}

// all reads the log once through findinglog, which judges it and returns the
// records its reports close, and once raw, for the bytes of each record's
// line: the n records are the file's first n lines. Bytes past the last
// committed write that no writer holds are counted as Unclosed.
func (d *deliveries) all(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path := filepath.Join(d.o.FindingsDir, findinglog.FileName)
	records, tail, err := findinglog.ReadFileTail(path)
	if err != nil {
		return err
	}
	if !tail.Held {
		d.sum.Unclosed = tail.Bytes
	}
	if len(records) == 0 {
		return nil
	}
	f, err := d.s.ops.openLog(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return d.each(ctx, records, bufio.NewReaderSize(f, findinglog.MaxLineBytes+1))
}

// each handles records, each with its line from lines. Every line must be
// its record, delivered or not, report or finding, before anything is
// decided on it: a line that is not is a log changed since it was judged.
func (d *deliveries) each(ctx context.Context, records []*findingv1alpha1.Record, lines *bufio.Reader) error {
	for i, rec := range records {
		if err := ctx.Err(); err != nil {
			return err
		}
		line, err := lines.ReadSlice('\n')
		if err != nil {
			return fmt.Errorf("%w: line %d of %d: %w", ErrChanged, i+1, len(records), err)
		}
		if err := sameRecord(line, rec); err != nil {
			return err
		}
		if i == 0 {
			if err := d.s.checkLog(line); err != nil {
				return err
			}
		}
		if err := d.one(ctx, rec, line); err != nil {
			return err
		}
	}
	return nil
}

// one handles one record whose log line, line, sameRecord has held to it.
func (d *deliveries) one(ctx context.Context, rec *findingv1alpha1.Record, line []byte) error {
	f := rec.GetFindingRecord()
	switch {
	case f == nil:
		return nil
	case f.GetEscalation() == findingv1alpha1.Escalation_ESCALATION_INFORM:
		d.sum.Inform++
		return nil
	case f.GetEscalation() != findingv1alpha1.Escalation_ESCALATION_ALERT:
		return fmt.Errorf("%w: a finding with escalation %s", ErrChanged, f.GetEscalation())
	}
	k := key(f.GetFinding().GetFindingId(), f.GetFinding().GetVerdict())
	if d.s.keys[k] {
		d.sum.AlreadyDelivered++
		return nil
	}
	if err := errors.Join(d.s.room(k), ctx.Err()); err != nil {
		return err
	}
	if err := deliver(ctx, d.o, line); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		d.sum.Failed++
		d.sum.Failures = append(d.sum.Failures, Failure{Key: k, Err: err})
		return nil
	}
	if err := d.s.mark(k); err != nil {
		return err
	}
	d.sum.Delivered++
	return nil
}

// sameRecord refuses a line that is not, byte for byte, the line the writer
// writes for the record findinglog read for it, so the program is never
// handed bytes the run did not judge: a line re-spelled to the same record
// is a log changed as much as one carrying another.
func sameRecord(line []byte, rec *findingv1alpha1.Record) error {
	want, err := findinglog.Line(rec)
	if err != nil {
		return fmt.Errorf("%w: the record read for a line has no line of its own: %w", ErrChanged, err)
	}
	if !bytes.Equal(line, append(want, '\n')) {
		return fmt.Errorf("%w: a line is not the record read for it", ErrChanged)
	}
	return nil
}
