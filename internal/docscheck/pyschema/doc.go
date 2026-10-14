// Package pyschema builds the table a client of the enforcement API reads its
// answers by: every message a body reaches, each member with its JSON name,
// kind and shape, and every enum with its names and numbers. The model is
// built from the compiled descriptors and names no language; Python renders
// it for the client under clients/python, and a field the table has no kind
// for is refused instead of guessed.
package pyschema
