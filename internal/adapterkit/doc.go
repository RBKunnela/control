// Package adapterkit reads a tool call alike for every adapter: the resource
// id a pointer names in its arguments, whether rewritten bytes still name the
// resource the call was decided on, the placeholder of an id past the
// contract's bound, the run token a request presents with the cause of a
// refusal, the trace context a caller claims, and the arguments hash every
// envelope carries.
//
// Two adapters reading one call two ways would let a spelling one of them
// does not normalise slip past a rule the other enforces, so the reading
// lives here once.
package adapterkit
