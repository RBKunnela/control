package gatewayconfig

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/guardana/control/internal/files"
)

// planeMayWrite asks whether the plane's account may write a path.
var planeMayWrite = accessWrite

// hasACL asks whether an entry carries an access control list.
var hasACL = aclPresent

var (
	errPlaneIsRoot = errors.New("the plane runs as root, which may write every path, so no placement keeps one from it")
	errPlaneOwns   = errors.New("owned by the plane's account, which may change its mode whatever the mode says")
	errPlaneWrites = errors.New("the plane's account may write it")
	errACL         = errors.New("it carries an access control list, which may let an account append to, delete or take it over whatever access(2) answers")
	errEmptyPath   = errors.New("the path is empty and names no entry")
)

// planeJudge refuses a directory or a link on the path that the plane's
// account could change.
var planeJudge = walkJudge{
	dir: func(dir string, info fs.FileInfo) error {
		if err := judgePlaneEntry(dir, info, true); err != nil {
			return fmt.Errorf("the directory %s: %w", dir, err)
		}
		return nil
	},
	link: func(link string, info fs.FileInfo) error {
		err := judgePlaneOwner(info)
		if err == nil {
			err = judgeACL(link, info)
		}
		if err != nil {
			return fmt.Errorf("the link %s: %w", link, err)
		}
		return nil
	},
}

// CheckNotPlaneWritable refuses path unless the plane's own account can
// change nothing that decides what it names. The path is walked as the
// configuration's is, a component at a time with each link followed, and it
// is refused where that account owns any entry on it, from the root of the
// file system to the entry it names, since an owner may change an entry's
// mode whatever it says; where that account may write the entry named or a
// directory on the way, as access(2) answers, unless the directory is sticky
// and so lets only an entry's owner replace the entry; and where an entry is
// missing, since an entry the plane could create is one it may write. A plane
// run as root is refused outright: root may write every path. Root's entries
// of mode 0644 in root's directories of mode 0755 are the shape that passes.
// Any entry that carries an access control list is refused too, on Linux and
// Darwin, since access(2) does not ask for the append, delete or ownership an
// entry may grant; and so is a plane whose real and effective ids differ, or
// that holds, on Linux, a capability that writes past access(2). A refusal
// names the entry and the reason, never what a file holds.
//
// It does not see a bind mount or a user namespace the plane's account
// controls, a network file system such as NFS or SMB whose server decides,
// an access control list outside Linux and Darwin, or a capability outside
// Linux. The environment outside the product's prefix, such as SSL_CERT_FILE
// and SSL_CERT_DIR, still feeds the decision point's TLS roots, which can
// only veto (ADR-0017).
func CheckNotPlaneWritable(path string) error {
	_, err := JudgeNotPlaneWritable(path)
	return err
}

// JudgeNotPlaneWritable judges path as CheckNotPlaneWritable does and returns
// the entry the walk ended at as it was judged, so a caller can hold it to a
// file it read before.
func JudgeNotPlaneWritable(path string) (fs.FileInfo, error) {
	if path == "" {
		return nil, errEmptyPath
	}
	if !files.PermissionBits {
		return nil, fmt.Errorf("%s: %w", path, files.ErrNoPermissionBits)
	}
	top, err := os.Lstat(separator)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if ownerWanted(top) == 0 {
		return nil, fmt.Errorf("%s: %w", path, errPlaneIsRoot)
	}
	var end fs.FileInfo
	resolved, err := walkJudged(path, planeJudge)
	if err == nil {
		configStep(stepWalked)
		end, err = judgePlaneEnd(resolved)
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("%s: %w; an entry the plane's account could create is one it may write", path, err)
	case err != nil:
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return end, nil
}

// judgePlaneEnd judges the entry the walk reached, which holds no link, as
// strictly as any: a sticky directory the plane may write still takes a new
// entry from it. It returns the entry as the Lstat it was judged by read it.
func judgePlaneEnd(resolved string) (fs.FileInfo, error) {
	info, err := os.Lstat(resolved)
	if err != nil {
		return nil, err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s %w", resolved, errChanged)
	}
	what := resolved
	if info.IsDir() {
		what = "the directory " + resolved
	}
	if err := judgePlaneEntry(resolved, info, false); err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	return info, nil
}

// judgePlaneOwner refuses an entry the plane's account owns, or one whose
// owner, or the plane's account, cannot be named.
func judgePlaneOwner(info fs.FileInfo) error {
	want := ownerWanted(info)
	owner, named := ownerOf(info)
	switch {
	case want < 0 || !named:
		return fmt.Errorf("%w; it may not be the plane's account's", files.ErrOwnerUnknown)
	case owner == want:
		return fmt.Errorf("%w: uid %d", errPlaneOwns, owner)
	}
	return nil
}

// judgePlaneEntry refuses an entry the plane's account owns or may write. A
// directory the walk passes through may be one it may write when it is
// sticky, since the entry taken from it is judged by its owner in turn. The
// kernel is asked by name, so the entry has to be the one judged once it has
// answered.
func judgePlaneEntry(path string, info fs.FileInfo, passed bool) error {
	if err := judgePlaneOwner(info); err != nil {
		return err
	}
	if err := judgeACL(path, info); err != nil {
		return err
	}
	if passed && info.Mode()&fs.ModeSticky != 0 {
		return nil
	}
	writable, err := planeMayWrite(path)
	if err != nil {
		return fmt.Errorf("whether the plane's account may write it is not known: %w", err)
	}
	again, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !os.SameFile(info, again) {
		return errChanged
	}
	if writable {
		return errPlaneWrites
	}
	return nil
}

// judgeACL refuses an entry that carries an access control list, or one the
// platform cannot say whether it does.
func judgeACL(path string, info fs.FileInfo) error {
	acl, err := hasACL(path, info)
	switch {
	case err != nil:
		return fmt.Errorf("whether it carries an access control list is not known: %w", err)
	case acl:
		return errACL
	}
	return nil
}
