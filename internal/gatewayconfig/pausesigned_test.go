package gatewayconfig

import (
	"os"
	"strings"
	"testing"
)

// TestASignedPauseFileNeedsItsOwnFloor: under the signed authority a pause
// file is read only above a floor, which no other authority reads and which
// never shares a path with the operators' pause directory.
func TestASignedPauseFileNeedsItsOwnFloor(t *testing.T) {
	const file = "\npause:\n  file: pause/pause.json\n"
	cfg, err := Load(write(t, signedBlock+file+"  floor_dir: pausefloor\n"), os.Environ())
	if err != nil {
		t.Fatalf("a signed pause file over its own floor was refused: %v", err)
	}
	if cfg.Pause.FloorDir != "pausefloor" {
		t.Errorf("pause.floor_dir = %q", cfg.Pause.FloorDir)
	}
	if _, err := Load(write(t, signedBlock), os.Environ()); err != nil {
		t.Errorf("a signed plane with no pause file needs no floor: %v", err)
	}

	for _, c := range []struct{ name, text, says string }{
		{"a signed pause file with no floor", signedBlock + file, "pause.floor_dir: the signed authority takes a signed pause only"},
		{"the floor as the pause directory", signedBlock + file + "  floor_dir: pause\n", "shares a path with the pause file's directory"},
		{"the floor holding the pause directory", signedBlock + file + "  floor_dir: .\n", "shares a path with the pause file's directory"},
		{"the floor inside the pause directory", signedBlock + file + "  floor_dir: pause/floor\n", "shares a path with the pause file's directory"},
		{"a floor under the directory authority", fileProvider + file + "  floor_dir: pausefloor\n", "pause.floor_dir: only a pause file under the signed authority"},
		{"a floor with no pause file", signedBlock + "\npause:\n  floor_dir: pausefloor\n", "pause.floor_dir: only a pause file under the signed authority"},
	} {
		if _, err := Load(write(t, c.text), os.Environ()); err == nil || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: %v, want a refusal saying %q", c.name, err, c.says)
		}
	}
}
