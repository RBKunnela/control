// Package egresslog imports an egress proxy's access log, written as JSON
// lines, as connection observations.
//
// The descriptor names which top-level member of a line holds each value,
// and the importer reads those members and no other: a path, a query, a
// header or a body the proxy also logged is skipped unread, never copied. A
// line that is not one JSON object, that repeats a member, that has no time
// it can read, whose destination is not a host alone or an authority, as the
// mapping declares, or whose port its authority contradicts is refused and
// counted by reason; a malformed optional value is dropped and counted, and
// its line kept. A destination holding a URL is refused, never parsed down
// to its host. Hosts and caller addresses are written in internal/netname's
// one spelling, which the coverage inventory declares hosts in.
//
// It is pure: it reads only the reader it is given and takes the receive time
// as an argument. See ADR-0040.
package egresslog
