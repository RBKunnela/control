// Package netname holds the one spelling of a host a connection is made to
// and of the address a caller connects from. The egress importer writes
// hosts and addresses in it and the coverage inventory declares hosts in it,
// so the two compare one form instead of two copies of a rule.
//
// It is pure and outside the guarded trees, which may not reach net/netip.
package netname
