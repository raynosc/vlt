//go:build linux

package daemon

import (
	"net"
	"os"
	"syscall"
)

// verifyPeer checks that the connected Unix socket client has the same UID as
// this process. This prevents other users on the same machine from connecting
// to the daemon socket even if they somehow bypass filesystem permissions.
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

	var cred *syscall.Ucred
	var credErr error
	err = rawConn.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil || credErr != nil {
		// SO_PEERCRED is the standard peer credential mechanism on Linux.
		// If it fails, reject the connection — fail closed.
		// Socket permissions (0o600) alone are not sufficient defense-in-depth.
		return false
	}

	return cred.Uid == uint32(os.Getuid())
}
