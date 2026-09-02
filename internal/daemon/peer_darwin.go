//go:build darwin

package daemon

import (
	"net"
	"os"
	"syscall"
	"unsafe"
)

// xucred is the macOS equivalent of Linux's ucred struct.
// struct xucred { u_int cr_version; uid_t cr_uid; short cr_ngroups; gid_t cr_groups[16]; }
type xucred struct {
	Version uint32
	UID     uint32
	Ngroups int16
	_       [2]byte // padding
	Groups  [16]uint32
}

// LOCAL_PEERCRED is the macOS socket option for getting peer credentials.
const LOCAL_PEERCRED = 0x001

// verifyPeer checks that the connected Unix socket client has the same UID as
// this process using macOS LOCAL_PEERCRED.
//
// Caller must hold d.mu.
func (d *Daemon) verifyPeer(conn net.Conn) bool {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}

	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return false
	}

	var cred xucred
	var credErr error
	err = rawConn.Control(func(fd uintptr) {
		credLen := uint32(unsafe.Sizeof(cred))
		// Use getsockopt with LOCAL_PEERCRED (0x001) at SOL_LOCAL (0x0)
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			0, // SOL_LOCAL
			LOCAL_PEERCRED,
			uintptr(unsafe.Pointer(&cred)),
			uintptr(unsafe.Pointer(&credLen)),
			0,
		)
		if errno != 0 {
			credErr = errno
		}
	})

	if err != nil || credErr != nil {
		// Fail closed: reject the connection if we cannot verify peer credentials.
		return false
	}

	return cred.UID == uint32(os.Getuid())
}
