//go:build !unix

package inbox

// nonBlocking has no counterpart here; the listing refuses what is not a
// regular file.
const nonBlocking = 0
