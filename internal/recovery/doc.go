// Package recovery backs up a plane's authority state and restores it so
// that nothing restored is lower than what survived or what the backup holds
// (ADR-0078). It runs as the plane's account while no plane runs, and
// restores only what that account owns: the floors, the runs and, under the
// directory authority, the pause file and the stop list. An operator's
// signed file is never
// written; the floors it is judged against are raised, and doctor names what
// an operator has to put back.
//
// A backup is a new directory holding a copy of each file of each class the
// configuration names, under the class's name, and backup.json, written
// last: the manifest of schema 0.1 naming the authority, the tenant, the
// project, when it was taken, and per file its class, the configuration key,
// its absolute source, its path in the backup, its SHA-256 and its size.
// The spool, the hold journal and its ledger, the approvals store and inbox,
// the trail, the signer's floors and every key are never backed up, so a
// restore resumes no hold and reuses no approval.
package recovery
