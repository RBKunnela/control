package observelog

// Error is a refusal by this package, matched with errors.Is. They are
// constants, so no other code in the binary can reassign one and turn a
// refusal into a pass.
type Error string

// Error returns the refusal's text.
func (e Error) Error() string { return string(e) }

const (
	// ErrNoPermissionBits is a platform that keeps no permission bits, so the
	// directory and the file cannot be checked.
	ErrNoPermissionBits Error = "observelog: this platform keeps no permission bits to check"
	// ErrNoLock is a platform with no file lock, so the log cannot be held by
	// one writer.
	ErrNoLock Error = "observelog: this platform has no file lock, so the log cannot be held"
	// ErrPath is a directory path that is empty.
	ErrPath Error = "observelog: no directory named"
	// ErrDirMode is a directory the group or others may enter, read or write.
	ErrDirMode Error = "observelog: the directory gives the group or others access"
	// ErrFileMode is a log file the group or others may read or write.
	ErrFileMode Error = "observelog: the log file gives the group or others access"
	// ErrNotRegular is a log file name that holds no regular file: a link, a
	// directory, a named pipe, a device or a socket.
	ErrNotRegular Error = "observelog: not a regular file"
	// ErrLinks is a log file with a name besides the log's, or one whose
	// names the platform does not count.
	ErrLinks Error = "observelog: the log file has another name"
	// ErrTooLarge is a log file past MaxLogBytes, or a write that would take
	// it past.
	ErrTooLarge Error = "observelog: the log file is larger than an open reads"
	// ErrOwner is a directory or a log file another account owns, or one whose
	// owner the platform does not name.
	ErrOwner Error = "observelog: the directory or the log file is not owned by this process's account"
	// ErrLocked is a log another writer holds.
	ErrLocked Error = "observelog: the log is held by another writer"
	// ErrDamaged is a log no writer of this package leaves behind: a whole
	// line that is not one record this build reads in the form the codec
	// writes it, a line with a carriage return, bytes after the last newline
	// that cannot be the start of a line the codec writes or are longer than
	// any line it writes, or one observation id carried with two contents.
	ErrDamaged Error = "observelog: the log is damaged"
	// ErrRecord is an observation or a report the codec will not write, or
	// none given where one is required. Nothing of the call is written.
	ErrRecord Error = "observelog: a record the log will not write"
	// ErrKind is a write naming a source, tenant and project the log holds
	// records of under another source kind: one source's liveness and doubt
	// are read from one kind's reports. Nothing of the call is written.
	ErrKind Error = "observelog: the log holds this source's records under another kind"
	// ErrClosed is a write to a log that is closed.
	ErrClosed Error = "observelog: the log is closed"
	// ErrWrite is a write that did not reach the disk. The file is cut back
	// to what it held before it; when that fails too, the log is ErrFailed
	// from then on.
	ErrWrite Error = "observelog: the write did not reach the disk"
	// ErrFailed is a write to a log that could not cut a failed write back.
	// The file may hold that write, so the log takes no more until it is
	// opened again. The open cuts the write unless its import report reached
	// the file whole; a write that failed only at its sync can stay.
	ErrFailed Error = "observelog: an earlier write could not be cut back; open the log again"
	// ErrChanged is a log file removed, renamed, replaced, cut or extended
	// under the writer. This write and every later one are refused until the
	// log is opened again.
	ErrChanged Error = "observelog: the log file was removed, renamed, replaced, cut or extended under the writer; open the log again"
)

const (
	// ErrQuery is a query the export refuses: a limit outside 1 to
	// MaxExportLimit or a negative byte bound.
	ErrQuery Error = "observelog: the export's query is refused"
	// ErrByteBound is a next line longer than the byte bound, which no export
	// under that bound can pass.
	ErrByteBound Error = "observelog: the next line is longer than the byte bound"
	// ErrShortRead is a file that no longer holds what it held when the
	// export opened it.
	ErrShortRead Error = "observelog: the file no longer holds what it held when the export opened it"
	// ErrCursorMalformed is a cursor not spelled v1:<first>:<offset>:<line>.
	ErrCursorMalformed Error = "observelog: the cursor is not v1:<sha256>:<offset>:<sha256>"
	// ErrCursorOtherFile is a cursor whose first line is not this file's.
	ErrCursorOtherFile Error = "observelog: the cursor is from another file"
	// ErrCursorPastEnd is a cursor past where the export ends: the end of
	// the last committed write, or the last newline of a log no writer cuts.
	ErrCursorPastEnd Error = "observelog: the cursor is past the end of what the export reads"
	// ErrCursorOffLine is a cursor whose offset does not follow a newline.
	ErrCursorOffLine Error = "observelog: the cursor does not follow a newline"
	// ErrCursorChanged is a cursor whose line is not the line ending there.
	ErrCursorChanged Error = "observelog: the line before the cursor is not the one the cursor names"
)
