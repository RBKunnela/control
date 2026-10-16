package docsconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/guardana/control/internal/docscheck/frontmatter"
)

// Config is the parsed file. Every field is required unless its comment says
// it may be empty.
type Config struct {
	// Budgets is the most words a page of each type may hold. Every type in
	// frontmatter.Types has a budget here or is named in ExemptTypes, never
	// both and never neither.
	Budgets     map[string]int `json:"budgets"`
	ExemptTypes []string       `json:"exempt_types"`
	// Readme bounds README.md files, which carry no frontmatter: the root
	// one and those of folders.
	Readme Readme `json:"readme"`
	// Ceilings pins a page over its budget to its exact word count, so the
	// count may only fall, and a rise is a visible edit here. May be empty.
	Ceilings map[string]int `json:"ceilings"`
	// Directories maps a directory to the type its pages declare; a page in
	// none of them is refused.
	Directories map[string]Directory `json:"directories"`
	// PageTypes overrides the directory's type for one page, such as a
	// frozen page that cannot move. May be empty.
	PageTypes map[string]string `json:"page_types"`
	// Frozen names paths whose change is a contract change. May be empty.
	Frozen []string `json:"frozen"`
	// Excluded names paths and directories outside the documentation system.
	// May be empty.
	Excluded []string `json:"excluded"`
	// Surfaces are the code globs a page must cover; the impact tool reports
	// a change under one that no page covers.
	Surfaces []string `json:"surfaces"`
	// Released is the version the site names as published. A maintainer sets
	// it once the release is out, since its changelog section is dated before
	// the tag exists and the site deploys from main.
	Released string `json:"released"`
}

// Excludes reports whether rel, a repository path, is one Excluded names: the
// path itself, or a path under a directory it names with a trailing slash.
func (c Config) Excludes(rel string) bool {
	for _, prefix := range c.Excluded {
		if rel == prefix || strings.HasSuffix(prefix, "/") && strings.HasPrefix(rel, prefix) {
			return true
		}
	}
	return false
}

// Readme is the word budget of README.md files.
type Readme struct {
	Root   int `json:"root"`
	Folder int `json:"folder"`
}

// Directory is what a directory under docs/ holds. The zero value of
// MayBeEmpty means the directory must hold at least one page.
type Directory struct {
	Type       string `json:"type"`
	MayBeEmpty bool   `json:"may_be_empty"`
}

// VersionPattern is a semantic version 2.0.0 without a leading v, unanchored:
// what CHANGELOG.md writes between the brackets of a release's heading.
const VersionPattern = `(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?`

var version = regexp.MustCompile(`^` + VersionPattern + `$`)

// ErrInvalid is wrapped by every refusal.
var ErrInvalid = errors.New("docs.json")

// Parse reads the file. It refuses an unknown or repeated key anywhere in
// the document, a member not spelled exactly as the schema names it, a
// missing required section and every value the checks could not act on.
func Parse(data []byte) (Config, error) {
	var c Config
	if err := checkKeysOnce(data, reflect.TypeFor[Config]()); err != nil {
		return Config{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("%w: text after the document", ErrInvalid)
	}
	if err := validate(c); err != nil {
		return Config{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return c, nil
}

// frame is one open object or array while the token stream is walked.
type frame struct {
	object bool
	seen   map[string]bool
	key    bool // an object frame awaits a key
	// typ is the type the collection decodes into, nil when the schema does
	// not reach it, and value the type of the value after the last key read.
	typ, value reflect.Type
}

// checkKeysOnce walks the token stream from root, the document's type, and
// refuses a key given twice in one object, which encoding/json would read as
// the last, and a struct member spelled other than its json name, which it
// reads case-insensitively. A map's keys are paths, read as written.
func checkKeysOnce(data []byte, root reflect.Type) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	var stack []*frame
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if top := last(stack); top != nil && top.object && top.key && tok != json.Delim('}') {
			if err := top.readKey(tok); err != nil {
				return err
			}
			continue
		}
		stack, err = step(stack, tok, root)
		if err != nil {
			return err
		}
	}
}

func (f *frame) readKey(tok json.Token) error {
	key, ok := tok.(string)
	if !ok {
		return fmt.Errorf("an object key is not a string: %v", tok)
	}
	if f.seen[key] {
		return fmt.Errorf("key %q is given twice in one object", key)
	}
	f.seen[key] = true
	f.key = false
	f.value = nil
	switch {
	case f.typ == nil:
	case f.typ.Kind() == reflect.Map:
		f.value = f.typ.Elem()
	case f.typ.Kind() == reflect.Struct:
		for i := range f.typ.NumField() {
			name, _, _ := strings.Cut(f.typ.Field(i).Tag.Get("json"), ",")
			if name == key {
				f.value = f.typ.Field(i).Type
				return nil
			}
			if strings.EqualFold(name, key) {
				return fmt.Errorf("key %q is not spelled as member %q", key, name)
			}
		}
	}
	return nil
}

// valueType is the type the next value decodes into, nil past the schema.
func valueType(stack []*frame, root reflect.Type) reflect.Type {
	top := last(stack)
	switch {
	case top == nil:
		return root
	case top.object:
		return top.value
	case top.typ != nil && top.typ.Kind() == reflect.Slice:
		return top.typ.Elem()
	}
	return nil
}

// step consumes one value token: it opens a frame for a delimiter that
// starts a collection, closes one for a delimiter that ends it, and after
// any value tells an enclosing object that a key comes next.
func step(stack []*frame, tok json.Token, root reflect.Type) ([]*frame, error) {
	if d, ok := tok.(json.Delim); ok {
		switch d {
		case '{':
			return append(stack, &frame{object: true, seen: map[string]bool{}, key: true, typ: valueType(stack, root)}), nil
		case '[':
			return append(stack, &frame{typ: valueType(stack, root)}), nil
		default:
			if len(stack) == 0 {
				return nil, fmt.Errorf("unexpected %v", d)
			}
			stack = stack[:len(stack)-1]
		}
	}
	if top := last(stack); top != nil && top.object {
		top.key = true
	}
	return stack, nil
}

func last(stack []*frame) *frame {
	if len(stack) == 0 {
		return nil
	}
	return stack[len(stack)-1]
}

func validate(c Config) error {
	for _, check := range []func(Config) error{validateBudgets, validateExemptions, validateCeilings, validateDirectories, validatePageTypes, validateLists, validateReleased} {
		if err := check(c); err != nil {
			return err
		}
	}
	return nil
}

func validateBudgets(c Config) error {
	if len(c.Budgets) == 0 {
		return errors.New("budgets is empty")
	}
	for typ, n := range c.Budgets {
		if !slices.Contains(frontmatter.Types, typ) {
			return fmt.Errorf("budgets: %q is not a page type", typ)
		}
		if n <= 0 {
			return fmt.Errorf("budgets: %s has no positive budget", typ)
		}
	}
	if c.Readme.Root <= 0 || c.Readme.Folder <= 0 {
		return errors.New("readme.root and readme.folder must be positive")
	}
	return nil
}

func validateExemptions(c Config) error {
	for i, typ := range c.ExemptTypes {
		if !slices.Contains(frontmatter.Types, typ) {
			return fmt.Errorf("exempt_types: %q is not a page type", typ)
		}
		if slices.Contains(c.ExemptTypes[:i], typ) {
			return fmt.Errorf("exempt_types: %s is listed twice", typ)
		}
	}
	for _, typ := range frontmatter.Types {
		_, budgeted := c.Budgets[typ]
		exempt := slices.Contains(c.ExemptTypes, typ)
		switch {
		case budgeted && exempt:
			return fmt.Errorf("%s has a budget and is exempt", typ)
		case !budgeted && !exempt:
			return fmt.Errorf("%s has no budget and is not exempt", typ)
		}
	}
	return nil
}

func validateCeilings(c Config) error {
	for p, n := range c.Ceilings {
		if err := checkPath(p); err != nil {
			return fmt.Errorf("ceilings: %w", err)
		}
		if n <= 0 {
			return fmt.Errorf("ceilings: %s has no positive count", p)
		}
	}
	return nil
}

func validateDirectories(c Config) error {
	if len(c.Directories) == 0 {
		return errors.New("directories is empty")
	}
	for dir, d := range c.Directories {
		if err := checkPath(dir); err != nil {
			return fmt.Errorf("directories: %w", err)
		}
		if !slices.Contains(frontmatter.Types, d.Type) {
			return fmt.Errorf("directories: %s holds type %q, which is not one of %s", dir, d.Type, strings.Join(frontmatter.Types, ", "))
		}
	}
	return nil
}

func validatePageTypes(c Config) error {
	for page, typ := range c.PageTypes {
		if err := checkPath(page); err != nil {
			return fmt.Errorf("page_types: %w", err)
		}
		if !strings.HasSuffix(page, ".md") {
			return fmt.Errorf("page_types: %s is not a page", page)
		}
		if !slices.Contains(frontmatter.Types, typ) {
			return fmt.Errorf("page_types: %s has type %q, which is not one of %s", page, typ, strings.Join(frontmatter.Types, ", "))
		}
	}
	return nil
}

func validateLists(c Config) error {
	for name, list := range map[string][]string{"frozen": c.Frozen, "excluded": c.Excluded, "surfaces": c.Surfaces} {
		for i, p := range list {
			if err := checkPath(strings.TrimSuffix(p, "/")); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			if slices.Contains(list[:i], p) {
				return fmt.Errorf("%s: %s is listed twice", name, p)
			}
		}
	}
	if len(c.Surfaces) == 0 {
		return errors.New("surfaces is empty, so no change would ever need a page")
	}
	return nil
}

func validateReleased(c Config) error {
	switch {
	case c.Released == "":
		return errors.New("released is empty; it names the version the site shows as published")
	case !version.MatchString(c.Released):
		return fmt.Errorf("released: %q is not a version as a CHANGELOG.md heading writes it, such as 1.2.3 or 1.2.3-alpha", c.Released)
	}
	return nil
}

// checkPath admits a clean, relative, slash path with no parent reference:
// what a walk of the repository produces.
func checkPath(p string) error {
	switch {
	case p == "":
		return errors.New("a path is empty")
	case strings.HasPrefix(p, "/"), strings.Contains(p, "\\"):
		return fmt.Errorf("%q is not a relative slash path", p)
	case path.Clean(p) != p, p == "." || p == "..", strings.HasPrefix(p, "../"):
		return fmt.Errorf("%q is not a clean path", p)
	}
	return nil
}
