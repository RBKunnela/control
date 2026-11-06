//go:build !unix

package main

// ownerText says the owner is unknown on a platform without uids.
func ownerText(string) string { return "a file whose owner this platform does not say" }
