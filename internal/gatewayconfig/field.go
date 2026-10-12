package gatewayconfig

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/guardana/control/internal/policykey"
)

// field is one configuration key of the struct T: where it sits, what it
// takes, what it defaults to, whether a value is required, and how a string
// becomes the value and the value a string.
type field[T any] struct {
	path     string
	kind     string
	def      string
	required bool
	// values is the closed set of spellings an enum key takes; nil for every
	// other kind.
	values []string
	// credential says the value is never printed.
	credential bool
	// address says the value is a URL, printed through ShowAddress.
	address bool
	set     func(*T, string) error
	show    func(*T) string
}

// enumKind is the kind of a key that takes one of a closed set of spellings;
// the set itself is on the field.
const enumKind = "one of"

// EnvName is the environment variable that sets the key at path, without the
// product's prefix, which brand.Env adds. The path's dots and the prefix are
// the only transformation, so a key and its variable are one spelling apart.
func EnvName(path string) string {
	return strings.ToUpper(strings.ReplaceAll(path, ".", "_"))
}

func stringField[T any](path, def string, required bool, get func(*T) *string) field[T] {
	return field[T]{
		path: path, kind: "string", def: def, required: required,
		set:  func(t *T, v string) error { *get(t) = v; return nil },
		show: func(t *T) string { return *get(t) },
	}
}

// credential marks a key whose value is never printed.
func credential[T any](f field[T]) field[T] {
	f.credential = true
	return f
}

// address marks a key whose value is a URL, printed only while it carries
// nothing that could hold a credential.
func address[T any](f field[T]) field[T] {
	f.address = true
	return f
}

// errKeyTextInPath refuses a path that holds key text, without repeating it.
var errKeyTextInPath = errors.New("holds a PEM marker or the start of a key file's body line, " +
	"which is key text where a path belongs; the value is not repeated here")

// filePath marks a key whose value names a file or a directory: one that
// holds key text is a key pasted where its path belongs, and is refused.
func filePath[T any](f field[T]) field[T] {
	set := f.set
	f.set = func(t *T, v string) error {
		if policykey.HoldsKeyText(v) {
			return errKeyTextInPath
		}
		return set(t, v)
	}
	return f
}

// quoteValue is a value as a refusal quotes it: in Go quotes, with any key text
// in it withheld.
func quoteValue(v string) string {
	return policykey.Printable(strconv.Quote(v))
}

func intField[T any](path, def string, get func(*T) *int) field[T] {
	return field[T]{
		path: path, kind: "integer", def: def,
		set: func(t *T, v string) error {
			n, err := strconv.Atoi(v)
			if err != nil {
				return fmt.Errorf("not an integer: %s", quoteValue(v))
			}
			*get(t) = n
			return nil
		},
		show: func(t *T) string { return strconv.Itoa(*get(t)) },
	}
}

func boolField[T any](path, def string, get func(*T) *bool) field[T] {
	return field[T]{
		path: path, kind: "true or false", def: def,
		set: func(t *T, v string) error {
			switch v {
			case "true":
				*get(t) = true
			case "false":
				*get(t) = false
			default:
				return fmt.Errorf("not true or false: %s", quoteValue(v))
			}
			return nil
		},
		show: func(t *T) string { return strconv.FormatBool(*get(t)) },
	}
}

func durationField[T any](path, def string, get func(*T) *time.Duration) field[T] {
	return field[T]{
		path: path, kind: "duration", def: def,
		set: func(t *T, v string) error {
			d, err := time.ParseDuration(v)
			if err != nil {
				return fmt.Errorf("not a duration such as 30s or 10m: %s", quoteValue(v))
			}
			if d < 0 {
				return fmt.Errorf("a duration cannot be negative: %s", quoteValue(v))
			}
			*get(t) = d
			return nil
		},
		show: func(t *T) string { return get(t).String() },
	}
}

// requiredDuration is a duration with no default, which a configuration has
// to set to a positive value. It shows as empty while unset, which is how
// checkRequired tells a key nobody set.
func requiredDuration[T any](path string, get func(*T) *time.Duration) field[T] {
	f := noDefaultDuration(path, get)
	f.required = true
	return f
}

// noDefaultDuration is a positive duration with no default, which another
// key decides whether a configuration has to set.
func noDefaultDuration[T any](path string, get func(*T) *time.Duration) field[T] {
	f := durationField(path, "", get)
	parse := f.set
	f.set = func(t *T, v string) error {
		if err := parse(t, v); err != nil {
			return err
		}
		if *get(t) == 0 {
			return fmt.Errorf("not a positive duration: %s", quoteValue(v))
		}
		return nil
	}
	f.show = func(t *T) string {
		if *get(t) == 0 {
			return ""
		}
		return get(t).String()
	}
	return f
}

func bytesField[T any](path, def string, get func(*T) *int64) field[T] {
	return field[T]{
		path: path, kind: "bytes, plain or with KiB, MiB, GiB", def: def,
		set: func(t *T, v string) error {
			n, err := parseBytes(v)
			if err != nil {
				return err
			}
			*get(t) = n
			return nil
		},
		show: func(t *T) string { return strconv.FormatInt(*get(t), 10) },
	}
}

// enumField takes one of the spellings values names and nothing else. The
// field carries them in order, so a refusal and the reference page name the
// same set.
func enumField[T any](path, def string, values []string, required bool, get func(*T) *string) field[T] {
	return field[T]{
		path: path, kind: enumKind, def: def, required: required, values: values,
		set: func(t *T, v string) error {
			if !slices.Contains(values, v) {
				return fmt.Errorf("not one of %s: %s", strings.Join(values, ", "), quoteValue(v))
			}
			*get(t) = v
			return nil
		},
		show: func(t *T) string { return *get(t) },
	}
}

// parseBytes reads a byte count, plain or with a binary suffix. A negative or
// unreadable count is refused here rather than at the spool, which would name
// its own option instead of the key the operator wrote.
func parseBytes(v string) (int64, error) {
	multiplier := int64(1)
	digits := v
	for _, suffix := range []struct {
		name string
		mul  int64
	}{{"KiB", 1 << 10}, {"MiB", 1 << 20}, {"GiB", 1 << 30}} {
		if rest, ok := strings.CutSuffix(v, suffix.name); ok {
			digits, multiplier = rest, suffix.mul
			break
		}
	}
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("not a byte count such as 512, 64MiB or 1GiB: %s", quoteValue(v))
	}
	if n > (1<<62)/multiplier {
		return 0, fmt.Errorf("byte count out of range: %s", quoteValue(v))
	}
	return n * multiplier, nil
}

// applyDefaults sets every field of t that has one to its default, so that the
// defaults live in the tables and nowhere else.
func applyDefaults[T any](t *T, fields []field[T]) error {
	for _, f := range fields {
		if f.def == "" {
			continue
		}
		if err := f.set(t, f.def); err != nil {
			return fmt.Errorf("the default of %s is not a value it takes: %w", f.path, err)
		}
	}
	return nil
}

// checkRequired names the first key that has to carry a value and does not.
func checkRequired[T any](t *T, fields []field[T], prefix string) error {
	for _, f := range fields {
		if f.required && f.show(t) == "" {
			return fmt.Errorf("%s: no value, and it has no default", prefix+f.path)
		}
	}
	return nil
}
