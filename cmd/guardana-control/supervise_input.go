package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/coverage"
	"github.com/guardana/control/internal/observe"
	"github.com/guardana/control/internal/runs"
	"github.com/guardana/control/internal/supervise"
	"google.golang.org/protobuf/encoding/protojson"
)

// readRun reads the opened run's record and the runs its procedure's
// children mode reads beside it. Under inherit the run is a root and the tree
// all of it; under separate any opened run is read with its children. A 0.1
// procedure reads a root run alone, and refuses a child: a child's events
// carry its own id, so supervising one alone would judge part of a task as
// the whole. Only the records of the run's own tree bound the read, never
// how many other runs the directory holds.
func readRun(dir, id string, mode supervise.Children) (supervise.Run, []supervise.Run, error) {
	if !observe.ValidRunID(id) {
		return supervise.Run{}, nil, refusedInput("run", id, supervise.ErrRunID)
	}
	admin, err := openRuns(runs.OpenAdmin, dir)
	if err != nil {
		return supervise.Run{}, nil, refusedInput("runs", dir, err)
	}
	recs, err := readFamily(admin, id, mode)
	err = errors.Join(err, admin.Close())
	switch {
	case errors.Is(err, runs.ErrNoRun):
		return supervise.Run{}, nil, refusedInput("run", id, errors.New("no record of it in the runs directory"))
	case errors.Is(err, runs.ErrNotRoot) && mode == supervise.ChildrenInherit:
		return supervise.Run{}, nil, refusedInput("run", id,
			errors.New("a child run is not supervised on its own: children inherit judges a root and its whole tree"))
	case errors.Is(err, runs.ErrNotRoot):
		return supervise.Run{}, nil, refusedInput("run", id, errors.New("a child run is not supervised on its own"))
	case err != nil:
		return supervise.Run{}, nil, refusedInput("runs", dir, err)
	}
	tree := make([]supervise.Run, 0, len(recs))
	for _, r := range recs {
		tree = append(tree, supervise.Run{ID: r.ID, Tenant: r.Who.TenantID, Project: r.Who.ProjectID,
			Closed: r.Closed(), Parent: r.Parent})
	}
	if mode == supervise.ChildrenUnstated {
		return tree[0], nil, nil
	}
	return tree[0], tree, nil
}

// readFamily is the records mode reads of run id, id's first.
func readFamily(admin *runs.Admin, id string, mode supervise.Children) ([]runs.Record, error) {
	ctx, cancel := context.WithTimeout(context.Background(), runsLockWait)
	defer cancel()
	switch mode {
	case supervise.ChildrenInherit:
		return admin.Tree(ctx, id, supervise.MaxTreeRuns)
	case supervise.ChildrenSeparate:
		return admin.Children(ctx, id, supervise.MaxTreeRuns)
	case supervise.ChildrenUnstated:
		rec, err := admin.Lookup(ctx, id)
		if err == nil && rec.Parent != "" {
			err = fmt.Errorf("%w: %s", runs.ErrNotRoot, id)
		}
		return []runs.Record{rec}, err
	}
	return nil, fmt.Errorf("children mode %d is not one this build reads", mode)
}

// readSupervisedExport reads an export as coverage does, then takes its
// events from the same bytes: coverage.ReadExport judges the export and keeps
// no event.
func readSupervisedExport(path string) (supervise.Export, error) {
	raw, err := readExportFile(path)
	if err != nil {
		return supervise.Export{}, err
	}
	x, err := coverage.ReadExport(bytes.NewReader(raw))
	if err != nil {
		return supervise.Export{}, refusedInput("evidence", path, err)
	}
	events, err := exportEvents(raw)
	if err != nil {
		return supervise.Export{}, refusedInput("evidence", path, err)
	}
	return supervise.Export{Events: events, Whole: x.Whole, NotWhole: x.NotWhole}, nil
}

// exportEvents decodes the event records of an export coverage.ReadExport
// accepted. Bytes after the last newline are a line cut short, which that
// reader does not read either.
func exportEvents(raw []byte) ([]*controlv1.Event, error) {
	lines := bytes.Split(raw, []byte("\n"))
	var out []*controlv1.Event
	for _, line := range lines[:len(lines)-1] {
		var rec struct {
			Type  string          `json:"type"`
			Event json.RawMessage `json:"event"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, err
		}
		if rec.Type != "event" {
			continue
		}
		ev := &controlv1.Event{}
		if err := protojson.Unmarshal(rec.Event, ev); err != nil {
			return nil, errors.New("an event does not decode")
		}
		out = append(out, ev)
	}
	return out, nil
}

// readSupervisedSource reads a source as coverage does: a descriptor that
// does not exist is reported absent, and a log directory with no log yet
// gives a source never heard.
func readSupervisedSource(descriptor, logDir string) (supervise.Source, bool, error) {
	src, present, err := readSource(descriptor, logDir)
	if err != nil || !present {
		return supervise.Source{}, present, err
	}
	out := supervise.Source{
		SourceID:         src.Descriptor.GetSourceId(),
		Tenant:           src.Descriptor.GetTenantId(),
		Project:          src.Descriptor.GetProjectId(),
		HeartbeatSeconds: src.Descriptor.GetHeartbeatSeconds(),
	}
	out.LastHeard, out.Heard = observe.LastHeard(src.Descriptor, src.Records)
	out.EveryRunDoubted, out.DoubtedRuns = observe.DoubtedRuns(src.Descriptor, src.Records)
	for _, r := range src.Records {
		if o := r.GetObservation(); o != nil {
			out.Observations = append(out.Observations, o)
		}
	}
	return out, true, nil
}

// unreadSources names each --source the run could not be judged against: a
// descriptor that does not exist, by its path, and each source
// supervise.Evaluate judged never heard or silent, by its id.
func unreadSources(in supervise.Input, res *supervise.Result) []string {
	var out []string
	for _, path := range in.SourcesNotRead {
		out = append(out, "source "+oneLine(path)+" absent")
	}
	for _, id := range res.NeverHeard {
		out = append(out, "source "+oneLine(id)+" never heard")
	}
	for _, id := range res.Silent {
		out = append(out, "source "+oneLine(id)+" silent")
	}
	return out
}
