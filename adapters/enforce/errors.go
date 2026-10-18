package enforce

// Error is a refusal by this package, matched with errors.Is. They are
// constants, so nothing can reassign one into a pass.
type Error string

// Error returns the refusal's text.
func (e Error) Error() string { return string(e) }

// New's refusals.
const (
	// ErrSocket is a socket path that is empty, relative, or longer than a
	// Unix socket address holds on every platform the releases ship.
	ErrSocket Error = "enforce: the socket path is empty, relative or too long"
	// ErrLifetime is an execution lifetime outside MinExecutionLifetime and
	// MaxExecutionLifetime; there is no default.
	ErrLifetime Error = "enforce: the execution lifetime is required and bounded"
	// ErrBodyBound is a body bound that is negative, below MinBodyBytes or
	// above MaxBodyBytes.
	ErrBodyBound Error = "enforce: the body bound is outside its limits"
	// ErrIdentity is a listener with no principal, no principal id or no
	// agent id: the run a token names is checked against this identity.
	ErrIdentity Error = "enforce: the listener's identity is missing"
	// ErrNoRuns is a nil run resolver: every request presents a run token.
	ErrNoRuns Error = "enforce: no run resolver"
	// ErrTool is an empty tool table, or a tool with no name, a name another
	// tool has, an effect class or resource type it lacks, an enumeration
	// value the contract does not declare, or a resource pointer outside the
	// bound.
	ErrTool Error = "enforce: the tool table is empty, incomplete or out of bounds"
	// ErrBound is a negative bound on kept handles, on a run's open
	// executions, on a sweep or on a request's time.
	ErrBound Error = "enforce: a bound cannot be negative"
	// ErrNoClock is a nil clock.
	ErrNoClock Error = "enforce: no clock"
	// ErrNoIDSource is a nil id source.
	ErrNoIDSource Error = "enforce: no id source"
)

// Start's refusals.
const (
	// ErrNoPipeline is a nil pipeline.
	ErrNoPipeline Error = "enforce: no pipeline"
	// ErrStarted is a second Start.
	ErrStarted Error = "enforce: the adapter is started already"
)

// Listen's refusals.
const (
	// ErrSocketDir is a socket directory that is not a directory this process
	// owns with no access for group or others.
	ErrSocketDir Error = "enforce: the socket's directory is not the plane's own"
	// ErrSocketInUse is a path something other than a stale socket of this
	// user holds, a socket something still answers on, a lock beside the
	// socket another receiver holds, or a lock file that is not this user's
	// one-named file with mode 0600.
	ErrSocketInUse Error = "enforce: the socket path is in use"
	// ErrSocketMode is a socket that is not this process's with mode 0600
	// once bound.
	ErrSocketMode Error = "enforce: the bound socket is not owned with mode 0600"
	// ErrPlatform is a platform with no Unix domain socket owner to check.
	ErrPlatform Error = "enforce: this platform serves no enforcement socket"
)

// ErrListener is Serve's refusal of a listener that is not a Unix socket's.
const ErrListener Error = "enforce: Serve takes the Unix socket listener Listen returns"

// ErrDraining is Shutdown's answer when requests it waited for were still in
// flight as its context ended; each of their executions is closed by its own
// request or abandoned by it.
const ErrDraining Error = "enforce: requests were still in flight at shutdown"
