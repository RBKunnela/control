// Package attempts reads an attempt manifest, judges what a victim's journal
// shows after each attempt, counts the outcomes over their own denominators
// with a positive and a negative control, and writes the report line by
// line. It runs no plane and sends no call; nothing here reaches the
// authorization path.
package attempts
