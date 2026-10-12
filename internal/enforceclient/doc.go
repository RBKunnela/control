// Package enforceclient is the reference client of the enforcement API
// (ADR-0051): it asks a receiver on a Unix socket before a tool acts, runs the
// tool only with the exact bytes an EXECUTE answer authorized, and reports
// how the call ended with one complete or one abort.
//
// Call holds every client rule of the contract, and the files under
// testdata/enforce/client are the cases a client in any language is held to.
package enforceclient
