package pause

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/guardana/control/internal/files"
)

// ErrMergeConflict is one entry id two pause files hold for two pauses.
const ErrMergeConflict Error = "pause: one entry id names two pauses"

// Merge writes into the unsigned pause file at path every entry of backup,
// the bytes of an unsigned pause file, that it does not hold already, so no
// pause either holds is lifted; a missing file is written with backup's
// entries alone. It refuses a signed file on either side with ErrSigned, an
// id the two hold for two entries with ErrMergeConflict, and a union Check
// refuses, past MaxEntries among them, each leaving the file as it was. It
// returns how many entries it added, and writes nothing when that is none
// and the file stands.
func Merge(ctx context.Context, path string, backup []byte) (int, error) {
	return merge(ctx, path, backup, true)
}

// CheckMerge refuses what Merge would refuse of the file at path and
// backup, and writes nothing.
func CheckMerge(ctx context.Context, path string, backup []byte) error {
	_, err := merge(ctx, path, backup, false)
	return err
}

func merge(ctx context.Context, path string, backup []byte, write bool) (int, error) {
	from, err := decodeFile(backup)
	switch {
	case err != nil:
		return 0, fmt.Errorf("the backup's pause file: %w", err)
	case from.signed != nil:
		return 0, fmt.Errorf("%w: the backup's pause file", ErrSigned)
	}
	added := 0
	err = locked(ctx, path, func(root *os.Root) error {
		cur, _, err := loadIn(root, path, ownedByThisUser)
		missing := errors.Is(err, ErrMissing)
		switch {
		case missing:
		case err != nil:
			return err
		case cur.signed != nil:
			return fmt.Errorf("%w: %s", ErrSigned, path)
		}
		next, n, err := union(cur.doc, from.doc)
		if err != nil {
			return err
		}
		added = n
		if !write || (added == 0 && !missing) {
			return nil
		}
		return writeUnion(root, path, next, missing)
	})
	if err != nil {
		return 0, err
	}
	return added, nil
}

// writeUnion writes next as the file at path, which root holds, making it
// where it is missing.
func writeUnion(root *os.Root, path string, next Document, missing bool) error {
	body, err := Marshal(next)
	if err != nil {
		return err
	}
	if missing {
		return files.CreateNoReplaceIn(root, filepath.Base(path), body, fileMode)
	}
	return files.ReplaceIn(root, filepath.Base(path), body, fileMode)
}

// union is have with every entry of add it does not hold appended, and how
// many those are, refusing one id held for two entries.
func union(have, add Document) (Document, int, error) {
	next := Document{Entries: slices.Clone(have.Entries)}
	added := 0
	for _, e := range add.Entries {
		i := slices.IndexFunc(next.Entries, func(h Entry) bool { return h.ID == e.ID })
		switch {
		case i < 0:
			next.Entries = append(next.Entries, e)
			added++
		case !sameEntry(next.Entries[i], e):
			return Document{}, 0, fmt.Errorf("%w: %q", ErrMergeConflict, e.ID)
		}
	}
	return next, added, nil
}
