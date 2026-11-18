package docsconfig

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// ReadingPath is one reader's way through the pages, rendered above the
// catalogue of docs/index.md. It lives here, beside the rest of what the index
// generator reads, because the index is rendered and never edited by hand.
type ReadingPath struct {
	// Reader names who the path is for; it is the path's heading.
	Reader string `json:"reader"`
	// Lead is one sentence saying what the path gets that reader.
	Lead string `json:"lead"`
	// Pages are repository paths of pages under docs/, in reading order.
	Pages []string `json:"pages"`
}

func validateReadingPaths(c Config) error {
	for i, p := range c.ReadingPaths {
		if err := validateReadingPath(p); err != nil {
			return fmt.Errorf("reading_paths[%d]: %w", i, err)
		}
		for _, q := range c.ReadingPaths[:i] {
			if q.Reader == p.Reader {
				return fmt.Errorf("reading_paths: reader %q is listed twice", p.Reader)
			}
		}
	}
	return nil
}

func validateReadingPath(p ReadingPath) error {
	for name, text := range map[string]string{"reader": p.Reader, "lead": p.Lead} {
		if strings.TrimSpace(text) != text || text == "" || strings.ContainsAny(text, "\r\n") {
			return fmt.Errorf("%s is empty, padded or more than one line", name)
		}
	}
	if len(p.Pages) == 0 {
		return errors.New("pages is empty")
	}
	for i, page := range p.Pages {
		if err := checkPath(page); err != nil {
			return fmt.Errorf("pages: %w", err)
		}
		if !strings.HasPrefix(page, "docs/") || !strings.HasSuffix(page, ".md") {
			return fmt.Errorf("pages: %s is not a page under docs/", page)
		}
		if slices.Contains(p.Pages[:i], page) {
			return fmt.Errorf("pages: %s is listed twice", page)
		}
	}
	return nil
}
