//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package notify

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// supported is true where the state can be judged and held and a program's
// group killed.
const supported = true

// openFlags keep an open from following a link at a file's name and from
// waiting on a named pipe before its type is judged.
const openFlags = syscall.O_NOFOLLOW | syscall.O_NONBLOCK

// lock takes an exclusive lock on the open lock file. Closing the file
// releases it, and the kernel drops it when the process dies, so a run that
// crashed leaves nothing behind that refuses the next one.
func lock(f *os.File) error {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return ErrLocked
		}
		return fmt.Errorf("locking the state: %w", err)
	}
	return nil
}

// ownGroup starts cmd as the leader of a process group of its own and makes
// its cancellation kill that whole group at the timeout; endGroup kills what
// is left of the group once the program has exited.
func ownGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
}

// killGroup sends endGroup's signal; a test replaces it.
var killGroup = func(pgid int) error { return syscall.Kill(-pgid, syscall.SIGKILL) }

// groupSettle bounds how long endGroup asks again while the group is refused
// with EPERM. On a loaded darwin kernel a leader just reaped can stay in its
// group for a moment with no credentials to check, which is answered EPERM
// though the group is the program's alone; a process of another account in
// the group answers EPERM for good.
const groupSettle = time.Second

// endGroup kills the process group of a program that was started, so no
// child of it outlives its delivery. A group with no process left is ESRCH.
func endGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	deadline := time.Now().Add(groupSettle)
	for pause := time.Millisecond; ; pause = min(2*pause, 100*time.Millisecond) {
		err := killGroup(cmd.Process.Pid)
		switch {
		case err == nil, errors.Is(err, syscall.ESRCH):
			return nil
		case !errors.Is(err, syscall.EPERM) || time.Now().After(deadline):
			return fmt.Errorf("killing the program's process group: %w", err)
		}
		time.Sleep(pause)
	}
}
