package gatewayconfig

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/guardana/control/pkg/contract"
)

// TestThePlaneIDIsAnIdentifier: plane_id is held to the contract's
// identifier rule, naming the key and not repeating the value; an inner
// space and an id at the bound load as written.
func TestThePlaneIDIsAnIdentifier(t *testing.T) {
	const marker = "plane-HUNTER2"
	for _, c := range []struct {
		name, value string
		want        error
	}{
		{"a leading space", " " + marker, contract.ErrInvalidValue},
		{"a NUL", marker + "\x00", contract.ErrInvalidValue},
		{"a trailing ideographic space", marker + "　", contract.ErrInvalidValue},
		{"past the bound", strings.Repeat("p", contract.MaxStringBytes+1), contract.ErrTooLarge},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := loadWith(t, compose(signedBlock), map[string]string{"plane_id": c.value})
			switch {
			case err == nil:
				t.Fatal("accepted")
			case !strings.HasPrefix(err.Error(), "plane_id: ") || !errors.Is(err, c.want):
				t.Errorf("the refusal %q does not name plane_id with %v", err, c.want)
			case strings.Contains(err.Error(), marker):
				t.Errorf("the refusal repeats the value: %v", err)
			}
		})
	}
	for _, value := range []string{"plane a", strings.Repeat("p", contract.MaxStringBytes)} {
		cfg, err := loadWith(t, compose(signedBlock), map[string]string{"plane_id": value})
		if err != nil {
			t.Fatalf("plane_id of %d bytes was refused: %v", len(value), err)
		}
		if cfg.PlaneID != value {
			t.Errorf("plane_id loaded as %q", cfg.PlaneID)
		}
	}
	if cfg := load(t, write(t, signedBlock)); cfg.PlaneID != "plane-a" {
		t.Errorf("plane_id from the file = %q, want plane-a", cfg.PlaneID)
	}
}

// TestASignedPlaneServesOneTenant: under signed, a listener principal's
// tenant that differs from tenant_id is refused, naming both keys; the same
// tenant, or none, loads, and so does a differing one under directory.
func TestASignedPlaneServesOneTenant(t *testing.T) {
	principal := func(tenant string) string {
		return strings.Replace(document, "  principal:\n    id: agent-runner\n",
			"  principal:\n    id: agent-runner\n    tenant_id: "+tenant+"\n", 1)
	}
	if principal("x") == document {
		t.Fatal("the document names no listener principal to extend")
	}
	signed := func(doc string) string {
		return strings.Replace(doc, memoryAuthority, "", 1) + signedBlock
	}
	directory := func(doc string) string {
		return strings.Replace(doc, memoryAuthority, "", 1) + fileProvider
	}

	_, err := Load(writeDocument(t, signed(principal("globex"))), os.Environ())
	if err == nil {
		t.Fatal("a signed plane with a listener tenant apart from tenant_id was accepted")
	}
	for _, want := range []string{"listener.principal.tenant_id", `"globex"`, `tenant_id "acme"`, "one tenant"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal %q does not say %q", err, want)
		}
	}

	for _, near := range []string{"acmf", "Acme", "ACME"} {
		if _, err := Load(writeDocument(t, signed(principal(near))), os.Environ()); err == nil {
			t.Errorf("a signed plane with the listener tenant %q beside tenant_id acme was accepted", near)
		}
	}

	for name, c := range map[string]struct{ doc, tenant string }{
		"signed, the listener's tenant the plane's": {signed(principal("acme")), "acme"},
		"signed, no listener tenant":                {signed(document), "acme"},
		"directory, another listener tenant":        {directory(principal("globex")), "globex"},
	} {
		cfg, err := Load(writeDocument(t, c.doc), os.Environ())
		if err != nil {
			t.Errorf("%s: refused: %v", name, err)
			continue
		}
		if got := cfg.ListenerTenant(); got != c.tenant {
			t.Errorf("%s: the listener's tenant is %q, want %q", name, got, c.tenant)
		}
	}
}
