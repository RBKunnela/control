// The row check beyond the C0 controls. A summary travels into evidence as
// well as onto the page, so a rune that changes what a row says without
// changing its shape is refused like one that breaks the shape. Every rune is
// built from its number, so this file holds none raw.
package reasondoc

import (
	"fmt"
	"strings"
	"testing"

	"github.com/guardana/control/internal/policy/reasons"
)

// A C1 control is a line break or a terminal command to some readers, a format
// character is invisible or reorders the text around it, and U+2028 and U+2029
// end a line for JavaScript and Python. Each is tried in both cells, and the
// refusal has to name the rune, since the rune is what nobody can see.
func TestRenderRefusesARuneThatChangesWhatARowSays(t *testing.T) {
	for _, r := range []rune{
		0x85,    // NEL: a C1 control, and a line break
		0x9b,    // CSI: a C1 control, and a terminal command
		0x2028,  // line separator
		0x2029,  // paragraph separator
		0x202e,  // right-to-left override, a format character
		0x200b,  // zero width space, a format character
		0xfeff,  // byte order mark, a format character
		0xad,    // soft hyphen, a format character
		0x061c,  // Arabic letter mark, a format character
		0xe0001, // language tag, a format character four bytes long
	} {
		t.Run(fmt.Sprintf("%U", r), func(t *testing.T) {
			summary := good()
			summary.Summary = "A sentence" + string(r) + " that hides something."
			id := good()
			id.ID = "A_" + string(r) + "CODE"

			for cell, code := range map[string]reasons.Code{"summary": summary, "identifier": id} {
				page, err := render([]reasons.Code{code})
				if err == nil {
					t.Fatalf("%s: render returned a page, want an error:\n%s", cell, page)
				}
				if want := fmt.Sprintf("%U", r); !strings.Contains(err.Error(), want) {
					t.Errorf("%s: error %q does not name %s", cell, err, want)
				}
			}
		})
	}
}

// The control for the test above: letters, marks and punctuation beyond ASCII
// render, and so does a no-break space, which is a space and not a format
// character. Without it, a check that refused everything beyond ASCII would
// pass the test above.
func TestRenderAcceptsTextBeyondASCII(t *testing.T) {
	code := good()
	code.Summary = "A sentence about a caf" + string(rune(0xe9)) + ", a dash " + string(rune(0x2014)) +
		" and a no-break" + string(rune(0xa0)) + "space."
	if _, err := render([]reasons.Code{code}); err != nil {
		t.Errorf("render refused ordinary text: %v", err)
	}
}
