// Package observe holds the rules of the observation contract: its version
// tables, the table of source kinds, the checks every source descriptor
// shares whatever its kind, the derivation of an observation's id and content
// digest, the restrictive reading of its enums, and the codec of one log line.
// The checks of a kind's own members are its importer's, behind
// ingest.ReadDescriptor.
//
// It is pure: no file, clock, network or randomness, so a later supervisor can
// import it beside the core. See ADR-0040.
package observe
