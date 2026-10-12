// Package enforce is the enforcement API adapter (ADR-0051): it serves admit,
// complete and abort on a Unix socket to a tool outside MCP, builds each
// envelope from the run token and the operator's tool table, and hands the
// plane's decision to a client that enforces it.
//
// It translates; the meaning of a call lives in the envelope it builds and in
// the policy, never here. A client can ignore any answer, so the adapter
// declares that it cooperates and never that it enforces.
package enforce
