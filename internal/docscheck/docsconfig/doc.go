// Package docsconfig reads docs/docs.json, the one file that says what the
// documentation checks and the impact tool judge by: budgets per page type,
// the exact ceilings of pages over budget, which directory holds which type,
// what is frozen, what is excluded, which code surfaces need a page and
// which release the site names as published, and the reading paths the
// index renders above its catalogue.
//
// The reader is strict: an unknown key, a repeated key, a missing section or
// a value the checks could not act on is refused, because a setting the
// reader skipped is a check that examined nothing.
package docsconfig
