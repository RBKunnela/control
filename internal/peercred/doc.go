// Package peercred reads the account on the other end of a connected Unix
// socket, as the kernel recorded it when the connection was made. A plane
// checks it before it answers a peer or sends one a credential.
package peercred
