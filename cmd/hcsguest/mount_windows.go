//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/joshmakestuff/hcsctl/internal/guestproto"
	"golang.org/x/sys/windows"
)

// The share connection is made with WNetAddConnection2 but never cancelled here: it is shared
// with any sibling mount of the same share and is torn down when the guest stops. So there is
// no WNetCancelConnection2 binding.
var (
	mpr                     = windows.NewLazySystemDLL("mpr.dll")
	procWNetAddConnection2W = mpr.NewProc("WNetAddConnection2W")
)

type netResourceW struct {
	Scope       uint32
	Type        uint32
	DisplayType uint32
	Usage       uint32
	LocalName   *uint16
	RemoteName  *uint16
	Comment     *uint16
	Provider    *uint16
}

const (
	resourcetypeDisk           = 0x00000001
	errorAlreadyAssigned       = 85
	symbolicLinkFlagDirectory  = 0x1
	ioReparseTagSymlink        = 0xA000000C
)

// applyMount connects the share root with the guest's own SMB client and puts a directory
// symlink at Path pointing at the full UNC. It does NOT use an SMB global mapping: that fails
// from the agent's session-0 LocalSystem context (measured, findings.md "SMB bind mounts",
// G5). The WNet connection is per-logon-session, so the mount serves the agent and its
// `guest exec` children, not an interactive RDP user.
func applyMount(m *guestproto.Mount) (guestproto.MountResult, error) {
	if err := validateMount(m); err != nil {
		return guestproto.MountResult{}, err
	}
	if !filepath.IsAbs(m.Path) {
		return guestproto.MountResult{}, fmt.Errorf("guest path %q must be absolute", m.Path)
	}
	if _, err := os.Lstat(m.Path); err == nil {
		return guestproto.MountResult{}, fmt.Errorf("guest path %q already exists", m.Path)
	}

	root := shareRoot(m.UNC)
	nr := netResourceW{
		Type:       resourcetypeDisk,
		RemoteName: windows.StringToUTF16Ptr(root),
	}
	var pw, user *uint16
	if m.Password != "" {
		pw = windows.StringToUTF16Ptr(m.Password)
	}
	if m.User != "" {
		user = windows.StringToUTF16Ptr(m.User)
	}
	r, _, _ := procWNetAddConnection2W.Call(
		uintptr(unsafe.Pointer(&nr)),
		uintptr(unsafe.Pointer(pw)),
		uintptr(unsafe.Pointer(user)),
		0,
	)
	// A UNC with no local device reconnects idempotently; ERROR_ALREADY_ASSIGNED means the
	// share is already connected (a sibling mount of the same share), which is fine.
	if r != 0 && r != errorAlreadyAssigned {
		return guestproto.MountResult{}, fmt.Errorf("WNetAddConnection2 %s: %w", root, windows.Errno(r))
	}

	if err := os.MkdirAll(filepath.Dir(m.Path), 0o755); err != nil {
		return guestproto.MountResult{}, fmt.Errorf("create parent of %s: %w", m.Path, err)
	}
	link := windows.StringToUTF16Ptr(m.Path)
	target := windows.StringToUTF16Ptr(m.UNC)
	if err := windows.CreateSymbolicLink(link, target, symbolicLinkFlagDirectory); err != nil {
		return guestproto.MountResult{}, fmt.Errorf("symlink %s -> %s: %w", m.Path, m.UNC, err)
	}
	return guestproto.MountResult{
		OK:       true,
		Protocol: guestproto.Protocol,
		Applied:  "wnet+symlink",
		Path:     m.Path,
		UNC:      m.UNC,
		ReadOnly: m.ReadOnly,
	}, nil
}

// applyUnmount removes the directory symlink after verifying it is a symlink reparse point,
// so it can never recurse into the share. The share connection is left in place: it is shared
// with any sibling mount of the same share and is torn down when the guest stops.
func applyUnmount(u *guestproto.Unmount) (guestproto.UnmountResult, error) {
	if err := validateUnmount(u); err != nil {
		return guestproto.UnmountResult{}, err
	}
	tag, err := reparseTag(u.Path)
	if err != nil {
		return guestproto.UnmountResult{}, fmt.Errorf("inspect %s: %w", u.Path, err)
	}
	if tag != ioReparseTagSymlink {
		return guestproto.UnmountResult{}, fmt.Errorf("%s is not a mount symlink (reparse tag 0x%x)", u.Path, tag)
	}
	if err := windows.RemoveDirectory(windows.StringToUTF16Ptr(u.Path)); err != nil {
		return guestproto.UnmountResult{}, fmt.Errorf("remove %s: %w", u.Path, err)
	}
	return guestproto.UnmountResult{
		OK:       true,
		Protocol: guestproto.Protocol,
		Applied:  "symlink",
		Path:     u.Path,
	}, nil
}

// reparseTag returns the reparse tag of a path, or an error when it is not a reparse point.
func reparseTag(path string) (uint32, error) {
	p := windows.StringToUTF16Ptr(path)
	attrs, err := windows.GetFileAttributes(p)
	if err != nil {
		return 0, err
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
		return 0, fmt.Errorf("not a reparse point")
	}
	h, err := windows.CreateFile(p, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(h)
	buf := make([]byte, 16*1024)
	var ret uint32
	if err := windows.DeviceIoControl(h, windows.FSCTL_GET_REPARSE_POINT, nil, 0, &buf[0], uint32(len(buf)), &ret, nil); err != nil {
		return 0, err
	}
	if ret < 4 {
		return 0, fmt.Errorf("reparse buffer too small")
	}
	return binary.LittleEndian.Uint32(buf[:4]), nil
}
