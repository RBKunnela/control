package enforce_test

import (
	"strings"
	"testing"

	"github.com/guardana/control/adapters/enforce"
	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	"github.com/guardana/control/internal/enforceclient"
)

// TestTheAPIVersionIsThePackages: the version both sides build their paths
// from is the one the messages' package carries.
func TestTheAPIVersionIsThePackages(t *testing.T) {
	pkg := string((&enforcev1alpha1.AdmitRequest{}).ProtoReflect().Descriptor().ParentFile().Package())
	want := pkg[strings.LastIndex(pkg, ".")+1:]
	for side, version := range map[string]string{"receiver": enforce.APIVersion, "client": enforceclient.APIVersion} {
		if version != want {
			t.Errorf("the %s says %s; the package is %s", side, version, pkg)
		}
	}
	if enforce.PathAdmit != "/enforce/"+want+"/admit" || enforceclient.PathAdmit != enforce.PathAdmit {
		t.Fatalf("admit is %s and %s", enforce.PathAdmit, enforceclient.PathAdmit)
	}
}
