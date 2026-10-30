package observe_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/observe"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// The expected ids were computed outside Go: SHA-256 over the domain
// "observation-id:1" and the five fields, each preceded by its length as eight
// big-endian bytes, cut to 16 bytes.
func TestObservationIDIsPinned(t *testing.T) {
	cases := []struct {
		fields [5]string
		want   string
	}{
		{[5]string{"tenant-a", "project-a", "agent-runtime", fixtureTraceID, fixtureSpanID}, fixtureObservationID},
		{[5]string{"t", "p", "s", "0af7651916cd43dd8448eb211c80319c", "b7ad6b7169203331"}, "obs-7878707f4fd09993f61cb2223c0ea91f"},
		{[5]string{"", "", "", "", ""}, "obs-4921e12cd31a28cfc3d81dd7ff510919"},
		{[5]string{"ab", "c", "s", "0af7651916cd43dd8448eb211c80319c", "b7ad6b7169203331"}, "obs-574fba6134032a5d23de3af53cc11a9a"},
		{[5]string{"a", "bc", "s", "0af7651916cd43dd8448eb211c80319c", "b7ad6b7169203331"}, "obs-13fc8f16940d2df696a3f28b2293b204"},
	}
	for _, c := range cases {
		f := c.fields
		if got := observe.ObservationID(f[0], f[1], f[2], f[3], f[4]); got != c.want {
			t.Errorf("ObservationID%q = %s, want %s", f, got, c.want)
		}
	}
}

// Moving one byte across any boundary between adjacent fields keeps the
// concatenation and must change the id.
func TestObservationIDSeparatesItsFields(t *testing.T) {
	base := [5]string{"tenant", "project", "source", fixtureTraceID, fixtureSpanID}
	seen := map[string][5]string{}
	record := func(f [5]string) {
		id := observe.ObservationID(f[0], f[1], f[2], f[3], f[4])
		if prev, dup := seen[id]; dup && prev != f {
			t.Fatalf("%q and %q share the id %s", prev, f, id)
		}
		seen[id] = f
	}
	record(base)
	for i := range 4 {
		left := base
		left[i], left[i+1] = base[i]+base[i+1][:1], base[i+1][1:]
		record(left)
		right := base
		right[i], right[i+1] = base[i][:len(base[i])-1], base[i][len(base[i])-1:]+base[i+1]
		record(right)
	}
	if len(seen) != 9 {
		t.Fatalf("%d distinct ids, want 9", len(seen))
	}
}

func TestIDForms(t *testing.T) {
	hex32 := "0af7651916cd43dd8448eb211c80319c"
	trace := map[string]bool{
		hex32: true, strings.Repeat("0", 31) + "1": true,
		strings.Repeat("0", 32): false, strings.ToUpper(hex32): false,
		hex32[:31]: false, hex32 + "0": false, hex32[:31] + "g": false, "": false,
	}
	for s, want := range trace {
		if got := observe.ValidTraceID(s); got != want {
			t.Errorf("ValidTraceID(%q) = %v, want %v", s, got, want)
		}
	}
	span := map[string]bool{
		"b7ad6b7169203331": true, "0000000000000001": true,
		"0000000000000000": false, "B7AD6B7169203331": false,
		"b7ad6b716920333": false, "b7ad6b71692033310": false, "b7ad6b716920333z": false, hex32: false,
	}
	for s, want := range span {
		if got := observe.ValidSpanID(s); got != want {
			t.Errorf("ValidSpanID(%q) = %v, want %v", s, got, want)
		}
	}
	run := map[string]bool{
		"run-" + hex32: true, fixtureRunID: true,
		hex32: false, "RUN-" + hex32: false, "run-" + strings.ToUpper(hex32): false,
		"run-" + hex32[:31]: false, "run-" + hex32 + "0": false, "run_" + hex32: false, "run-": false,
	}
	for s, want := range run {
		if got := observe.ValidRunID(s); got != want {
			t.Errorf("ValidRunID(%q) = %v, want %v", s, got, want)
		}
	}
}

// The expected digest is computed from an observation written without the two
// cleared fields, not from one this package cleared.
func TestContentDigestIgnoresOnlyReceiptAndDescriptor(t *testing.T) {
	without := fixtureObservation()
	without.ReceivedTime = nil
	without.Source.DescriptorSha256 = ""
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(without)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	want := hex.EncodeToString(sum[:])

	a := fixtureObservation()
	other := fixtureObservation()
	other.ReceivedTime = ts("2027-01-01T00:00:00Z")
	other.Source.DescriptorSha256 = strings.Repeat("f", 64)
	for name, o := range map[string]*observev1.Observation{"fixture": a, "re-read": other} {
		if got := observe.ContentDigest(o); got != want {
			t.Errorf("ContentDigest(%s) = %s, want %s", name, got, want)
		}
	}
	if a.ReceivedTime == nil || a.Source.DescriptorSha256 != fixtureDescriptorSHA256 {
		t.Error("ContentDigest changed the observation it was given")
	}
}

// mutations changes one field of every message in an observation, each to a
// value the fixture does not hold.
var mutations = map[string]func(o *observev1.Observation){
	"schema_version":             func(o *observev1.Observation) { o.SchemaVersion = "0.2" },
	"observation_id":             func(o *observev1.Observation) { o.ObservationId = "obs-" + strings.Repeat("0", 32) },
	"tenant_id":                  func(o *observev1.Observation) { o.TenantId = "tenant-b" },
	"project_id":                 func(o *observev1.Observation) { o.ProjectId = "project-b" },
	"source.source_id":           func(o *observev1.Observation) { o.Source.SourceId = "other" },
	"source.trust":               func(o *observev1.Observation) { o.Source.Trust = observev1.Trust_TRUST_PLATFORM },
	"source.kind":                func(o *observev1.Observation) { o.Source.Kind = observe.KindEgressAccessLog },
	"source.convention.name":     func(o *observev1.Observation) { o.Source.Convention.Name = "x" },
	"source.convention.version":  func(o *observev1.Observation) { o.Source.Convention.Version = "1.40.0" },
	"event_time":                 func(o *observev1.Observation) { o.EventTime.Nanos++ },
	"stage":                      func(o *observev1.Observation) { o.Stage = observev1.Stage_STAGE_FAILED },
	"subject.kind":               func(o *observev1.Observation) { o.Subject.Kind = observev1.SubjectKind_SUBJECT_KIND_MODEL },
	"subject.name":               func(o *observev1.Observation) { o.Subject.Name = "write_file" },
	"subject.operation":          func(o *observev1.Observation) { o.Subject.Operation = "chat" },
	"subject.provider":           func(o *observev1.Observation) { o.Subject.Provider = "remote" },
	"subject.server_address":     func(o *observev1.Observation) { o.Subject.ServerAddress = "x.example" },
	"outcome.status":             func(o *observev1.Observation) { o.Outcome.Status = observev1.Status_STATUS_ERROR },
	"outcome.error_type":         func(o *observev1.Observation) { o.Outcome.ErrorType = "timeout" },
	"correlation.basis":          func(o *observev1.Observation) { o.Correlation.Basis = observev1.Basis_BASIS_NONE },
	"correlation.run_id":         func(o *observev1.Observation) { o.Correlation.RunId = "" },
	"correlation.trace_id":       func(o *observev1.Observation) { o.Correlation.TraceId = strings.Repeat("1", 32) },
	"correlation.span_id":        func(o *observev1.Observation) { o.Correlation.SpanId = strings.Repeat("1", 16) },
	"correlation.parent_span_id": func(o *observev1.Observation) { o.Correlation.ParentSpanId = "" },
	"content_attributes_dropped": func(o *observev1.Observation) { o.ContentAttributesDropped = 3 },
	"connection.port":            func(o *observev1.Observation) { o.Connection = &observev1.Connection{Port: 443} },
	"connection.method":          func(o *observev1.Observation) { o.Connection = &observev1.Connection{Method: "GET"} },
	"connection.http_status":     func(o *observev1.Observation) { o.Connection = &observev1.Connection{HttpStatus: 200} },
	"connection.bytes_sent":      func(o *observev1.Observation) { o.Connection = &observev1.Connection{BytesSent: 1} },
	"connection.bytes_received":  func(o *observev1.Observation) { o.Connection = &observev1.Connection{BytesReceived: 1} },
	"connection.caller":          func(o *observev1.Observation) { o.Connection = &observev1.Connection{Caller: "c"} },
	"connection.caller_basis": func(o *observev1.Observation) {
		o.Connection = &observev1.Connection{CallerBasis: observev1.CallerBasis_CALLER_BASIS_NONE}
	},
}

func TestContentDigestSeesEveryOtherField(t *testing.T) {
	base := observe.ContentDigest(fixtureObservation())
	for name, mutate := range mutations {
		o := fixtureObservation()
		mutate(o)
		if observe.ContentDigest(o) == base {
			t.Errorf("changing %s leaves the digest unchanged", name)
		}
	}
	// A field added to the contract without a mutation here would go unexamined.
	cleared := map[string]bool{"received_time": true, "source.descriptor_sha256": true}
	walkLeaves("", fixtureObservation().ProtoReflect().Descriptor(), func(path string) {
		if _, ok := mutations[path]; !ok && !cleared[path] {
			t.Errorf("field %s has no mutation", path)
		}
	})
}

func walkLeaves(prefix string, md protoreflect.MessageDescriptor, leaf func(string)) {
	for i := range md.Fields().Len() {
		fd := md.Fields().Get(i)
		path := prefix + string(fd.Name())
		if m := fd.Message(); m != nil && m.FullName().Parent() == md.FullName().Parent() {
			walkLeaves(path+".", m, leaf)
			continue
		}
		leaf(path)
	}
}

func TestContentDigestOfNothingIsEmpty(t *testing.T) {
	if got := observe.ContentDigest(nil); got != "" {
		t.Errorf("ContentDigest(nil) = %q, want empty", got)
	}
	bad := fixtureObservation()
	bad.Subject.Name = "\xff"
	if got := observe.ContentDigest(bad); got != "" {
		t.Errorf("ContentDigest(invalid UTF-8) = %q, want empty", got)
	}
}
