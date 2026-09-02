//go:build !windows

package cli

import (
	"syscall"
)

// GetSysProcAttrDetached returns the SysProcAttr needed to detach a spawned process on Unix/macOS.
func GetSysProcAttrDetached() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setsid: true,
	}
}
