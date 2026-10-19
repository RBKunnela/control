package hookbridge

import (
	"errors"
	"os"
	"testing"
	"testing/fstest"
)

func TestABuiltInProfileIsFoundByItsDirectory(t *testing.T) {
	raw, err := os.ReadFile("testdata/neutral/profile.json")
	if err != nil {
		t.Fatal(err)
	}
	fsys := fstest.MapFS{
		"profiles/neutral/profile.json": {Data: raw},
		"profiles/renamed/profile.json": {Data: raw},
		"neutral/profile.json":          {Data: raw},
	}
	p, err := loadFrom(fsys, "neutral")
	if err != nil || p.ID != "neutral" {
		t.Fatalf("loadFrom(neutral) = %+v, %v", p, err)
	}
	if _, err := loadFrom(fsys, "renamed"); !errors.Is(err, ErrProfile) {
		t.Fatalf("a profile whose id is not its directory's: %v", err)
	}
	for _, id := range []string{"absent", "../neutral", "-neutral", "neutral/"} {
		if _, err := loadFrom(fsys, id); !errors.Is(err, ErrUnknownProfile) {
			t.Errorf("loadFrom(%q) = %v, want ErrUnknownProfile", id, err)
		}
	}
}
