//go:build !unix

package attempts

import "errors"

// readJournalFile cannot judge a journal here: this platform reports no link
// count and no owner, so a journal is never read as whole.
func readJournalFile(string) ([]byte, error) {
	return nil, errors.New("this platform reports no link count and no owner to judge a journal by")
}
