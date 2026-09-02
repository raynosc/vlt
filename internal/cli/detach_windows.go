//go:build windows

package cli

import (
	"syscall"
)

// GetSysProcAttrDetached returns the SysProcAttr needed to detach a spawned process on Windows.
func GetSysProcAttrDetached() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
}
