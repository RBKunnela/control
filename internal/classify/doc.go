// Package classify is the operator's classification of one tool: the effect
// class of a call to it, the resource it acts on, where it sends data and what
// its results hold, with the one check every configuration that classifies a
// tool applies.
//
// A classification Check accepts is one an envelope can carry: the fields it
// supplies are never the reason contract.Validate refuses every call to the
// tool.
package classify
