package gatewayconfig

import (
	"fmt"
	"slices"
	"strings"

	"github.com/guardana/control/internal/brand"
)

// baseEnv is what every command upstream receives of the plane's environment
// without listing it.
var baseEnv = []string{"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "USER"}

// BaseEnv returns the variables every command upstream receives without
// listing them, each only when the plane has it. The list is a copy.
func BaseEnv() []string { return slices.Clone(baseEnv) }

// checkEnvNames refuses a name an upstream's command may not receive: one
// under the plane's own prefix, whose value is the plane's configuration or
// one of its credentials, and one no environment can hold. The prefix is
// matched in any case, since a platform may compare names without it. An
// item that is not a name is never repeated: a pasted NAME=value carries the
// value, and a value pasted alone is one.
func checkEnvNames(at string, names []string) error {
	for i, name := range names {
		if before, _, pasted := strings.Cut(name, "="); pasted {
			after := ""
			if envName(before) {
				after = " after " + before
			}
			return fmt.Errorf("%s%d: the item holds \"=\"%s; list the name only, and its value stays in the plane's environment",
				at, i, after)
		}
		if !envName(name) {
			return fmt.Errorf("%s%d: not a variable name, which is a letter or _ first, then letters, digits and _, "+
				"in ASCII; the item is not repeated here", at, i)
		}
		if strings.HasPrefix(strings.ToUpper(name), brand.EnvPrefix) {
			return fmt.Errorf("%s%d: %s is under %s, which holds the plane's own configuration and credentials; "+
				"no upstream receives it", at, i, name, brand.EnvPrefix)
		}
	}
	return nil
}

// envName reports whether name is a portable environment variable name.
func envName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		letter := c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
		if !letter && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// EnvironmentOverrides returns, sorted, every key the environment set, a
// header named as its key reads, such as pdp.headers.<name>, and never a
// value. No key is exempt: the plane's account sets its own environment when
// it restarts, so any key set there is one no placement of the configuration
// protects. A Config that Load did not make holds nothing the environment
// set.
func EnvironmentOverrides(c *Config) []string {
	var keys []string
	for key, source := range c.source {
		if strings.HasPrefix(source, brand.EnvPrefix) && envName(source) {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	return keys
}
