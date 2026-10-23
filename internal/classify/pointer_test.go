package classify_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/guardana/control/internal/classify"
)

func TestAPointerIsCheckedAgainstRFC6901AndTheBound(t *testing.T) {
	eight := strings.Repeat("/a", 8)
	token64 := "/" + strings.Repeat("t", 64)
	for _, p := range []string{"", "/", "/a", "/a~0b~1c", eight, token64, "/0/x"} {
		if err := classify.CheckPointer(p); err != nil {
			t.Errorf("CheckPointer(%q) = %v, want accepted", p, err)
		}
	}
	for _, p := range []string{"a", "a/b", eight + "/a", token64 + "t", "/a~", "/a~2", "/~"} {
		if err := classify.CheckPointer(p); !errors.Is(err, classify.ErrPointer) {
			t.Errorf("CheckPointer(%q) = %v, want ErrPointer", p, err)
		}
	}
	// The bound is on a token as written: an escape counts its two bytes, so
	// 63 bytes and ~0 are past it though the member they name is 64.
	for p, ok := range map[string]bool{
		"//":                                 true,
		"/~01":                               true,
		"/a b":                               true,
		"/\u00e9":                            true,
		"/" + strings.Repeat("a", 62) + "~0": true,
		"/" + strings.Repeat("a", 63) + "~0": false,
	} {
		if err := classify.CheckPointer(p); (err == nil) != ok {
			t.Errorf("CheckPointer(%q) = %v, want accepted %v", p, err, ok)
		}
	}
	if classify.MaxPointerTokens != 8 || classify.MaxPointerTokenSize != 64 {
		t.Errorf("the bounds are %d tokens of %d bytes; the cases above are written for 8 of 64",
			classify.MaxPointerTokens, classify.MaxPointerTokenSize)
	}
}
