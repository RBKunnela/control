package recovery_test

import (
	"slices"
	"testing"

	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/recovery"
)

// TestEveryFileKeyIsBackedUpOrNamedNever: a key naming a file or a
// directory added to the configuration fails here until it is classified,
// and a classified key the configuration no longer has fails too.
func TestEveryFileKeyIsBackedUpOrNamedNever(t *testing.T) {
	copied, never := recovery.Classified()
	var files []string
	for _, f := range gatewayconfig.Fields() {
		if !f.File {
			continue
		}
		files = append(files, f.Path)
		_, isNever := never[f.Path]
		switch {
		case slices.Contains(copied, f.Path) && isNever:
			t.Errorf("%s is both backed up and never", f.Path)
		case !slices.Contains(copied, f.Path) && !isNever:
			t.Errorf("%s names a file or a directory, and recovery neither backs it up nor says why not", f.Path)
		}
	}
	if len(files) < 20 {
		t.Fatalf("only %d keys name a file: %q; the field table lost its file flag", len(files), files)
	}
	for _, k := range copied {
		if !slices.Contains(files, k) {
			t.Errorf("backed up %s is no key naming a file", k)
		}
	}
	for k := range never {
		if !slices.Contains(files, k) {
			t.Errorf("never %s is no key naming a file", k)
		}
	}
}
