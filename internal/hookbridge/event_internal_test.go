package hookbridge

import "testing"

// ReadEvent hands repeatsAName only input it has already read as valid, so
// no event reaches the decoder's errors; this holds the scan to failing closed
// on its own.
func TestInputTheScanCannotReadToItsEndIsRepeated(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want bool
	}{
		{`{"a":1,"b":{"a":2}}`, false},
		{`{"a":1,"b":{"c":2,"c":3}}`, true},
		{`{"a":1}}`, true},
		{`{"a":[1,}`, true},
		{`{"a":1`, true},
		{`{"a":{"b":[1]`, true},
		{`{"a":1,`, true},
	} {
		if got := repeatsAName([]byte(tc.raw)); got != tc.want {
			t.Errorf("repeatsAName(%s) = %t, want %t", tc.raw, got, tc.want)
		}
	}
}
