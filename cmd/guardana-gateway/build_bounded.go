package main

import (
	"fmt"
	"path/filepath"

	ondisk "github.com/guardana/control/internal/files"
)

// shortID bounds a key id read from a bundle file, which nothing has verified
// yet, before it reaches a log line.
func shortID(id string) string {
	const limit = 64
	if len(id) > limit {
		return id[:limit] + "..."
	}
	return id
}

// readBounded reads a regular file of at most limit bytes. The open does not
// block, so a named pipe configured as the bundle is refused rather than
// waited on for good.
func readBounded(path string, limit int64) ([]byte, error) {
	raw, err := ondisk.ReadRegular(filepath.Clean(path), limit, 0)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return raw, nil
}
