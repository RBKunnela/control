package gatewayconfig

import (
	"fmt"
	"path/filepath"
)

// checkSignedPause requires pause.floor_dir under the signed authority where
// a pause file is set, and refuses it anywhere else. The floor is the
// plane's to write and the pause file's directory the operators', so neither
// may be, hold or sit inside the other.
func (c *Config) checkSignedPause() error {
	signed := c.Approvals.Authority == AuthoritySigned && c.Pause.File != ""
	switch {
	case !signed && c.Pause.FloorDir != "":
		return fmt.Errorf("pause.floor_dir: only a pause file under the %s authority is read above a floor, and here the authority is %s or pause.file is not set",
			AuthoritySigned, c.Approvals.Authority)
	case !signed:
		return nil
	case c.Pause.FloorDir == "":
		return fmt.Errorf("pause.floor_dir: the %s authority takes a signed pause only at a serial its floor takes, and it has no default", AuthoritySigned)
	}
	shared, err := sharesDir(c.Resolve(c.Pause.FloorDir), filepath.Dir(c.Resolve(c.Pause.File)))
	if err != nil {
		return fmt.Errorf("pause.floor_dir: %w", err)
	}
	if shared {
		return fmt.Errorf("pause.floor_dir: %q shares a path with the pause file's directory; operators write the pause file, and the plane alone writes its floor",
			c.Pause.FloorDir)
	}
	return nil
}
