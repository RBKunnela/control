package supervise

import (
	"strings"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/policy/strictjson"
)

// payloadReadable reports whether ev's payload, when it is one that carries a
// version of its own (an ActionEnvelope, a Decision, an Approval or an
// ActionResult), names MAJOR.MINOR on the major this build reads: the event's
// version does not vouch for a payload that names its own. No payload, or one
// that carries no version, is readable.
func payloadReadable(ev *controlv1.Event) bool {
	var version string
	switch p := ev.GetPayload().(type) {
	case *controlv1.Event_Proposed:
		version = p.Proposed.GetSchemaVersion()
	case *controlv1.Event_Decision:
		version = p.Decision.GetSchemaVersion()
	case *controlv1.Event_Approval:
		version = p.Approval.GetSchemaVersion()
	case *controlv1.Event_Result:
		version = p.Result.GetSchemaVersion()
	default:
		return true
	}
	return strictjson.IsVersion(version, contractMajor())
}

// contractMajor is the major of the Protobuf package the generated types
// carry, so a build generated from a v2 contract reads no 1.x payload.
func contractMajor() string {
	pkg := string((&controlv1.ActionEnvelope{}).ProtoReflect().Descriptor().ParentFile().Package())
	return strings.TrimPrefix(pkg[strings.LastIndex(pkg, ".")+1:], "v")
}
