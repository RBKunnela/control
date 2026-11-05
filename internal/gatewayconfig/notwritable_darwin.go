package gatewayconfig

import (
	"encoding/binary"
	"errors"
	"io/fs"
	"syscall"
	"unsafe"
)

// The getattrlist(2) request for an entry's access control list: the
// attribute and the set the kernel says it returned, and the options not to
// follow a link and to leave out of that set what the entry does not have.
// The attribute itself, com.apple.system.Security, is not readable through
// getxattr(2).
const (
	attrBitmapCount         = 5
	attrCmnExtendedSecurity = 0x00400000
	attrCmnReturnedAttrs    = 0x80000000
	fsoptNoFollow           = 0x1
	fsoptPackInvalAttrs     = 0x4
)

// attrList is the request getattrlist(2) reads.
type attrList struct {
	bitmapCount uint16
	_           uint16
	common      uint32
	_           [4]uint32
}

// judgeCapabilities has nothing to judge: Darwin grants no capabilities.
func judgeCapabilities() error { return nil }

// aclPresent reports whether the entry at path, a link itself rather than
// what it reaches, carries an access control list.
func aclPresent(path string, _ fs.FileInfo) (bool, error) {
	p, err := syscall.BytePtrFromString(path)
	if err != nil {
		return false, err
	}
	req := attrList{bitmapCount: attrBitmapCount, common: attrCmnExtendedSecurity | attrCmnReturnedAttrs}
	// The length and the returned set are all that is read; the kernel
	// fills the set whatever room the list itself would need.
	var buf [32]byte
	_, _, errno := syscall.Syscall6(syscall.SYS_GETATTRLIST, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&req)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), fsoptNoFollow|fsoptPackInvalAttrs, 0) //nolint:gosec // G103: the conversion syscall.Syscall6 requires
	if errno != 0 {
		return false, errno
	}
	returned := binary.NativeEndian.Uint32(buf[4:])
	if binary.NativeEndian.Uint32(buf[:4]) < 8 || returned&attrCmnReturnedAttrs == 0 {
		return false, errors.New("getattrlist named no attributes it returned")
	}
	return returned&attrCmnExtendedSecurity != 0, nil
}
