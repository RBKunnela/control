package approvals_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
)

// TestAnApprovalFromAnotherMajorIsNotHeld: the approval's own schema version
// is a contract version like the record's, and a major this build does not
// read is refused rather than held as if it were understood.
func TestAnApprovalFromAnotherMajorIsNotHeld(t *testing.T) {
	for _, v := range []string{"9.0", "2.0", "", "1.", "1.x", "1.0.0", "1.-3", "1.+3", "01.0"} {
		p, dir := openPlane(t)
		h := held(t, firstApproval, "req-1")
		h.Approval.SchemaVersion = v
		if err := p.Hold(t.Context(), h, minted); !errors.Is(err, approvals.ErrSchemaVersion) {
			t.Errorf("holding an approval of version %q = %v, want ErrSchemaVersion", v, err)
		}
		if names := recordNames(t, dir); len(names) != 0 {
			t.Errorf("a refused hold of version %q wrote %v", v, names)
		}
	}
	p, _ := openPlane(t)
	h := held(t, firstApproval, "req-1")
	h.Approval.SchemaVersion = "1.7"
	if err := p.Hold(t.Context(), h, minted); err != nil {
		t.Errorf("holding an approval of a later minor = %v, want it held", err)
	}
}

// TestAnApprovalFromAnotherMajorOnDiskIsNotAnswered: a record whose approval
// is of a major this build does not read is refused by the approver too, and
// nothing is filed.
func TestAnApprovalFromAnotherMajorOnDiskIsNotAnswered(t *testing.T) {
	_, dir, _ := heldOne(t)
	writeFile(t, dir, heldName, withApprovalField(t, readFile(t, dir, heldName), "schemaVersion", `"9.0"`))
	_, err := openApprover(t, dir).Answer(t.Context(), firstApproval, controlv1.ApprovalState_APPROVAL_STATE_APPROVED,
		"approver-1", "", minted.Add(time.Minute))
	if !errors.Is(err, approvals.ErrSchemaVersion) {
		t.Fatalf("answering an approval of major 9 = %v, want ErrSchemaVersion", err)
	}
	assertNames(t, dir, heldName)
}

// TestAMarkerIsReadStrictly: the marker decides whether a directory is a
// store, so it is held to the members it names exactly. encoding/json would
// fold a member's case, skip an unknown one and keep the last of two.
func TestAMarkerIsReadStrictly(t *testing.T) {
	cases := map[string]string{
		"an unknown member":         `{"schema_version":"2.0","kind":"approvals","writable_by":"anyone"}`,
		"members in capitals":       `{"SCHEMA_VERSION":"2.0","KIND":"approvals"}`,
		"the kind given twice":      `{"schema_version":"2.0","kind":"hold_journal","kind":"approvals"}`,
		"the version given twice":   `{"schema_version":"9.0","schema_version":"2.0","kind":"approvals"}`,
		"a marker that is an array": `["approvals"]`,
	}
	for name, marker := range cases {
		t.Run(name, func(t *testing.T) {
			dir := markedStore(t, marker)
			if _, err := approvals.OpenPlane(dir); !errors.Is(err, approvals.ErrNotAStore) {
				t.Errorf("a plane over %s = %v, want ErrNotAStore", name, err)
			}
			if _, err := approvals.OpenApprover(dir); !errors.Is(err, approvals.ErrNotAStore) {
				t.Errorf("an approver over %s = %v, want ErrNotAStore", name, err)
			}
		})
	}
	dir := markedStore(t, `{"schema_version":"2.0","kind":"approvals"}`+"\n")
	p, err := approvals.OpenPlane(dir)
	if err != nil {
		t.Fatalf("a plane over the marker as the format spells it = %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
}

// markedStore is a store a plane made, closed, with marker written over the
// marker it left.
func markedStore(t *testing.T, marker string) string {
	t.Helper()
	p, dir := openPlane(t)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "store.meta", []byte(marker))
	return dir
}

// TestA10DirectoryIsRefusedByName: a directory or a record of the format that
// kept the spent mark beside the answers is refused, by both handles, with a
// message naming both versions and what to do; a record of the current major
// beside it is read.
func TestA10DirectoryIsRefusedByName(t *testing.T) {
	dir := markedStore(t, `{"schema_version":"1.0","kind":"approvals"}`+"\n")
	for name, open := range map[string]func() error{
		"a plane":     func() error { _, err := approvals.OpenPlane(dir); return err },
		"an approver": func() error { _, err := approvals.OpenApprover(dir); return err },
	} {
		err := open()
		if !errors.Is(err, approvals.ErrNotAStore) || !errors.Is(err, approvals.ErrSchemaVersion) ||
			!strings.Contains(err.Error(), "1.0") || !strings.Contains(err.Error(), "2.0") || !strings.Contains(err.Error(), "empty the directory") {
			t.Errorf("%s over a 1.0 directory: %v; want it refused, naming 1.0 and 2.0 and saying to empty it", name, err)
		}
	}

	p, dir, h := heldOne(t)
	writeFile(t, dir, heldName, withField(t, readFile(t, dir, heldName), "schema_version", `"1.0"`))
	_, err := p.Find(t.Context(), h.Binding, minted)
	if !errors.Is(err, approvals.ErrSchemaVersion) || !strings.Contains(err.Error(), "2.0") {
		t.Errorf("Find over a 1.0 record: %v; want ErrSchemaVersion naming 2.0", err)
	}
	writeFile(t, dir, heldName, withField(t, readFile(t, dir, heldName), "schema_version", `"2.3"`))
	if found, err := p.Find(t.Context(), h.Binding, minted); err != nil || len(found) != 1 {
		t.Errorf("Find over a record of a later minor = %d, %v; want it read", len(found), err)
	}
}
