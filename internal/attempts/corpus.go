package attempts

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
)

// Digest is the sha256 of raw in lower-case hex.
func Digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// CorpusDigest is the sha256 of one line per file, `<path> <sha256>`, in
// the byte order of the paths, so the same files under the same paths give
// the same digest whatever order the manifest names them in.
func CorpusDigest(files []FileDigest) string {
	sorted := slices.SortedFunc(slices.Values(files), func(a, b FileDigest) int { return strings.Compare(a.Path, b.Path) })
	var b strings.Builder
	for _, f := range sorted {
		b.WriteString(f.Path + " " + f.SHA256 + "\n")
	}
	return Digest([]byte(b.String()))
}
