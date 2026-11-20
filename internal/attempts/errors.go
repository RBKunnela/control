package attempts

// Error is a class of refusal, matched with errors.Is. They are constants,
// so no other code can reassign one and turn a refusal into a pass.
type Error string

// Error returns the refusal's text.
func (e Error) Error() string { return string(e) }

// The classes of refusal of a manifest, and of a journal line.
const (
	ErrTooLarge      Error = "attempts: the document is over its size bound"
	ErrSyntax        Error = "attempts: the document is not JSON"
	ErrTooDeep       Error = "attempts: the document nests past its bound"
	ErrTrailing      Error = "attempts: something follows the document"
	ErrNotUTF8       Error = "attempts: a string is not UTF-8"
	ErrSurrogate     Error = "attempts: a string escapes a lone surrogate"
	ErrNull          Error = "attempts: null is refused"
	ErrDuplicate     Error = "attempts: a member is repeated"
	ErrUnknownMember Error = "attempts: an unknown member"
	ErrMissing       Error = "attempts: a required member is missing"
	ErrKind          Error = "attempts: a kind this build does not read"
	ErrWrongType     Error = "attempts: a value of the wrong type"
	ErrBound         Error = "attempts: a value past its bound"
	ErrValue         Error = "attempts: a value outside its set"
	ErrPath          Error = "attempts: a path the manifest may not name"
	ErrLabel         Error = "attempts: the labels do not cover the scenario"
	ErrEffect        Error = "attempts: an effect is not named as the format requires"
	ErrJournal       Error = "attempts: the journal cannot be judged"
	ErrReport        Error = "attempts: the report cannot be written"
)
