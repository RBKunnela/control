// Package brand holds the product name for Go code.
//
// A rename needs two mechanisms, because Go code and everything else are
// handled differently. Go code reads every name from here and spells none out.
// Outside Go code the name is a literal in go.mod, the proto files, the image
// reference and the documentation; scripts/rename-product.sh rewrites those in
// the same pass, and scripts/check-brand.sh fails the gate when a literal
// appears in a file that is not on the allowlist.
//
// See docs/adr/0006-product-name-switch.md.
package brand

const (
	// Name is the product name shown to a person: CLI help, log banners,
	// documentation titles.
	Name = "Guardana Control"

	// Slug is the single-token form of Name. It does not reach the action
	// digest: that domain tag is fixed and carries no product name, so a
	// rename invalidates no stored approval and no fixture (ADR-0010).
	Slug = "guardana-control"

	// CLI is the command-line binary name. It equals Slug today and stays a
	// separate constant because a rename may move one without the other.
	CLI = "guardana-control"

	// Gateway is the binary name of the inline proxy, which ships and is
	// deployed separately from the CLI.
	Gateway = "guardana-gateway"

	// EnvPrefix namespaces every environment variable the product reads, so a
	// host running several agent tools has no collisions. Build names with Env
	// rather than concatenating this by hand.
	EnvPrefix = "GUARDANA_CONTROL_"

	// OTelNamespace prefixes emitted span, metric and attribute names. Dotted,
	// not hyphenated, because that is the OpenTelemetry convention.
	OTelNamespace = "guardana.control"

	// ProtoPackage is the Protobuf package of the wire contract and appears in
	// every fully qualified message name. It is a public contract after the
	// first tagged release (ADR-0002).
	ProtoPackage = "guardana.control.v1"

	// ModulePath mirrors the module directive in go.mod. Nothing makes the
	// compiler keep the two in step; brand_test.go does, and
	// scripts/rename-product.sh refuses to start while they differ.
	ModulePath = "github.com/guardana/control"

	// Image is the container image reference without a tag. Release tooling
	// appends the version.
	Image = "ghcr.io/guardana/control"

	// PythonPackage is the import name of the Python client under clients/:
	// the slug spelled as a Python identifier. scripts/rename-product.sh
	// refuses to start while the two differ.
	PythonPackage = "guardana_control"
)

// Env returns the environment variable name for key under the product prefix.
func Env(key string) string { return EnvPrefix + key }
