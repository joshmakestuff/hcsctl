//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/joshmakestuff/hcsctl/internal/guestproto"
	"golang.org/x/sys/unix"
)

// applyMount attaches the share with mount(2) directly: cifs is a kernel filesystem, so no
// mount.cifs helper is needed and a guest image carries nothing extra. The Rocky 10 fixture
// kernel ships cifs.ko (CONFIG_CIFS=m).
func applyMount(m *guestproto.Mount) (guestproto.MountResult, error) {
	if err := validateMount(m); err != nil {
		return guestproto.MountResult{}, err
	}
	if !filepath.IsAbs(m.Path) {
		return guestproto.MountResult{}, fmt.Errorf("guest path %q must be absolute", m.Path)
	}
	if err := os.MkdirAll(m.Path, 0o755); err != nil {
		return guestproto.MountResult{}, fmt.Errorf("create mount point: %w", err)
	}
	var flags uintptr
	if m.ReadOnly {
		flags |= unix.MS_RDONLY
	}
	if err := unix.Mount(cifsSource(m.UNC), m.Path, "cifs", flags, cifsOptions(m)); err != nil {
		return guestproto.MountResult{}, fmt.Errorf("mount cifs %s at %s: %w", m.UNC, m.Path, err)
	}
	return guestproto.MountResult{
		OK:       true,
		Protocol: guestproto.Protocol,
		Applied:  "cifs",
		Path:     m.Path,
		UNC:      m.UNC,
		ReadOnly: m.ReadOnly,
	}, nil
}

// applyUnmount detaches the mount. A lazy detach handles a mount still busy: the mount point
// leaves the namespace at once and the filesystem is released when the last user lets go.
func applyUnmount(u *guestproto.Unmount) (guestproto.UnmountResult, error) {
	if err := validateUnmount(u); err != nil {
		return guestproto.UnmountResult{}, err
	}
	err := unix.Unmount(u.Path, 0)
	if err == unix.EBUSY {
		err = unix.Unmount(u.Path, unix.MNT_DETACH)
	}
	if err != nil {
		return guestproto.UnmountResult{}, fmt.Errorf("unmount %s: %w", u.Path, err)
	}
	return guestproto.UnmountResult{
		OK:       true,
		Protocol: guestproto.Protocol,
		Applied:  "umount",
		Path:     u.Path,
	}, nil
}
