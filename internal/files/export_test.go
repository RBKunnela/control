package files

import (
	"errors"
	"io/fs"
	"os"
)

// CreateNoReplace is CreateNoReplaceIn through a handle to dir, which the
// tests take a directory's name for.
func CreateNoReplace(dir, name string, body []byte, perm fs.FileMode) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	return errors.Join(CreateNoReplaceIn(root, name, body, perm), root.Close())
}
