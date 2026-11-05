package gateway

import (
	"errors"
	"slices"
	"strings"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// TestApplyRefusesACheckingTypeWithNoCheck: a type in the checking set that
// holds has no case for is refused, never passed to the adapter unchecked.
func TestApplyRefusesACheckingTypeWithNoCheck(t *testing.T) {
	saved := checking
	checking = append(slices.Clone(checking), "emit_alert")
	t.Cleanup(func() { checking = saved })

	out, left, err := apply(&controlv1.ActionEnvelope{}, []byte(`{"a":1}`), []*controlv1.Obligation{obligation("emit_alert", false)})
	if !errors.Is(err, errRewrite) || out != nil || left != nil {
		t.Fatalf("apply = %q, %v, %v; want nil, nil, errRewrite", out, left, err)
	}
	if !strings.Contains(err.Error(), "emit_alert") {
		t.Errorf("the refusal %q does not name the type", err)
	}
}

// TestApplyRefusesAFailingCheckBesideARewrite: a failing check refuses the
// call even when the rewrite would apply, and a holding one leaves the
// rewrite's bytes.
func TestApplyRefusesAFailingCheckBesideARewrite(t *testing.T) {
	env := &controlv1.ActionEnvelope{Resource: &controlv1.Resource{Id: "ord-1"}}
	capped := obligation("cap_amount", false, "max", "1")
	if out, _, err := apply(env, []byte(`{"amount":5}`), []*controlv1.Obligation{capped, obligation("restrict_resources", false, "ids", "ord-1")}); err != nil || string(out) != `{"amount":1}` {
		t.Errorf("a holding check and a cap = %s, %v; want the capped bytes", out, err)
	}
	if out, left, err := apply(env, []byte(`{"amount":5}`), []*controlv1.Obligation{capped, obligation("restrict_resources", false, "ids", "ord-2")}); !errors.Is(err, errRewrite) || out != nil || left != nil {
		t.Errorf("a failing check and a cap = %s, %v, %v; want errRewrite", out, left, err)
	}
}
