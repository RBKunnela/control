// Package runs is the runs directory of ADR-0034: the runs an operator opened,
// each with a token, and the flow state of each root run, kept on disk so
// that it outlives the process that served it.
//
// Two handles open one directory and the compiler keeps them apart. OpenAdmin
// is the operator's: it opens, closes and lists runs and reads a run's tree,
// each under the directory's exclusive lock, and it is the only code that
// encodes a record;
// InitAdmin opens it the same way after making an empty directory a runs
// directory.
// OpenPlane is the plane's: it resolves a token, reads a root's state and
// raises it under the root's own lock file; it takes no directory lock, so
// planes side by side share one directory, and it never creates, rewrites or
// deletes a record. The zero value of either handle fails closed.
//
// A handle opens its directory once, as an os.Root, and reaches every file
// through it. It judges the directory again at every call: the same
// directory, the same owner, no write bit for the group or the world, and
// still at the name it was opened under.
//
// # The names under the directory
//
//	runs.meta          the marker; a directory without it is refused
//	<id>.run.json      a run's record
//	<id>.run.tmp       a record being replaced, by the operator only
//	<root>.state.json  a root run's flow state
//	<root>.state.tmp   a state being replaced, only under the root's lock
//	<root>.lock        the root's lock file, created at opening
//	.tmp-<26 base32>   what a crash while the marker was created leaves; never read
//
// An id is "run-" and 32 lower-case hex digits. Any other name, and any entry
// that is not a regular file whatever its name, is foreign and refuses the
// directory. A record or a state is only ever replaced whole: written to its
// temporary name, forced to disk, renamed, and the directory forced to disk
// after. Nothing removes a state or a lock file, and closing a run replaces
// its record.
//
// # The token
//
// A token is "<id>.<secret>", the secret 32 random bytes in base64url without
// padding. A record keeps the hex SHA-256 of the secret's bytes and never the
// secret, so the token printed at opening is its only copy.
//
// # The formats
//
// Both files are one JSON object whose keys are all required and matched
// exactly: an absent, unknown or repeated key is refused, never defaulted. A
// record's schema_version is read at major 2 and a state's at major 1, any
// other refused; a record of major 1 names no project, so it is refused, never
// read as any project's. A record holds schema_version, run_id, project_id,
// tenant_id, principal_type, principal_id, agent_id, root, parent (empty for a
// root run), opened_at, expires_at, closed_at (empty while open) and
// secret_sha256, times in UTC RFC 3339. A state holds schema_version, root,
// untrusted and max_read, a sensitivity's name without its prefix or UNKNOWN.
// A run id or root inside a file must equal the one in its name.
//
// Nothing here reads a clock: every time is the caller's.
package runs
