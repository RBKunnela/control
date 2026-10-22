package testreport

import (
	"fmt"
	"strconv"
	"strings"
)

// GeneratedDir is the directory of the root module that holds the generated
// packages, the only packages that may have no test files.
const GeneratedDir = "api/gen/"

// GeneratedPrefix returns the import path prefix of the generated packages of
// the module whose go.mod is given: its module path, then GeneratedDir. A
// go.mod with no module directive, more than one, or one whose path it cannot
// read is refused with ErrModulePath.
func GeneratedPrefix(gomod []byte) (string, error) {
	var paths []string
	for line := range strings.Lines(string(gomod)) {
		code, _, _ := strings.Cut(line, "//")
		fields := strings.Fields(code)
		if len(fields) == 0 || fields[0] != "module" {
			continue
		}
		if len(fields) != 2 {
			return "", fmt.Errorf("%w: %q", ErrModulePath, strings.TrimSpace(code))
		}
		path := fields[1]
		if strings.HasPrefix(path, `"`) {
			unquoted, err := strconv.Unquote(path)
			if err != nil {
				return "", fmt.Errorf("%w: %s", ErrModulePath, path)
			}
			path = unquoted
		}
		if path == "" || strings.ContainsAny(path, "\"() \t") {
			return "", fmt.Errorf("%w: %q", ErrModulePath, path)
		}
		paths = append(paths, path)
	}
	if len(paths) != 1 {
		return "", fmt.Errorf("%w: %d module directive(s)", ErrModulePath, len(paths))
	}
	return paths[0] + "/" + GeneratedDir, nil
}
