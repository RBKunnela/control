// Package hookbridge admits a tool call that an agent runtime announces
// through command hooks, and reports its completion, over the enforcement
// API. A profile says, as data, where a runtime's events keep each value;
// the package holds no runtime's name and no policy meaning.
//
// The admit and the completion arrive in separate processes, so the handle
// between them lives in an owner-only directory, under a name derived from
// the run token, the session and the call id, and is taken by exactly one
// completion.
package hookbridge
