//go:build windows

package daemon

import "net"

// verifyPeer on Windows always returns true since Unix domain sockets
// with peer credentials are not available. Security relies on filesystem ACLs.
func (d *Daemon) verifyPeer(conn net.Conn) bool {
	return true
}
