//go:build windows

package files

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	netapi32             = windows.NewLazySystemDLL("netapi32.dll")
	procNetShareAdd      = netapi32.NewProc("NetShareAdd")
	procNetShareDel      = netapi32.NewProc("NetShareDel")
	procNetShareGetInfo  = netapi32.NewProc("NetShareGetInfo")
	procNetUserAdd       = netapi32.NewProc("NetUserAdd")
	procNetUserSetInfo   = netapi32.NewProc("NetUserSetInfo")
	procNetUserDel       = netapi32.NewProc("NetUserDel")
	procNetApiBufferFree = netapi32.NewProc("NetApiBufferFree")
)

const (
	stypeDisktree      = 0
	nerrNetNameNotFound = 2310
	nerrUserNotFound   = 2221

	usePrivUser        = 1
	ufScript           = 0x0001
	ufDontExpirePasswd = 0x10000
)

// shareInfo502 mirrors SHARE_INFO_502. Only the fields we set are meaningful; the rest keep
// the struct's layout.
type shareInfo502 struct {
	Netname            *uint16
	Type               uint32
	Remark             *uint16
	Permissions        uint32
	MaxUses            uint32
	CurrentUses        uint32
	Path               *uint16
	Passwd             *uint16
	Reserved           uint32
	SecurityDescriptor *windows.SECURITY_DESCRIPTOR
}

type shareInfo1 struct {
	Netname *uint16
	Type    uint32
	Remark  *uint16
}

type userInfo1 struct {
	Name        *uint16
	Password    *uint16
	PasswordAge uint32
	Priv        uint32
	HomeDir     *uint16
	Comment     *uint16
	Flags       uint32
	ScriptPath  *uint16
}

type userInfo1003 struct {
	Password *uint16
}

func u16(s string) *uint16 { return windows.StringToUTF16Ptr(s) }

// shareExists reports whether a share is present, using NetShareGetInfo level 1, which reads
// unelevated.
func shareExists(name string) (bool, error) {
	var buf *shareInfo1
	r, _, _ := procNetShareGetInfo.Call(0, uintptr(unsafe.Pointer(u16(name))), 1, uintptr(unsafe.Pointer(&buf)))
	if r == nerrNetNameNotFound {
		return false, nil
	}
	if r != 0 {
		return false, fmt.Errorf("NetShareGetInfo(%q): status %d", name, r)
	}
	procNetApiBufferFree.Call(uintptr(unsafe.Pointer(buf)))
	return true, nil
}

// shareAdd creates a disk share at path with the given SDDL. It is not idempotent: the caller
// checks shareExists first, so an existing share is left untouched.
func shareAdd(name, path, sddl, remark string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("security descriptor %q: %w", sddl, err)
	}
	info := shareInfo502{
		Netname:            u16(name),
		Type:               stypeDisktree,
		Remark:             u16(remark),
		MaxUses:            0xFFFFFFFF,
		Path:               u16(path),
		SecurityDescriptor: sd,
	}
	var parmErr uint32
	r, _, _ := procNetShareAdd.Call(0, 502, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parmErr)))
	if r != 0 {
		return fmt.Errorf("NetShareAdd(%q): status %d (bad field %d)", name, r, parmErr)
	}
	return nil
}

func shareDel(name string) error {
	r, _, _ := procNetShareDel.Call(0, uintptr(unsafe.Pointer(u16(name))), 0)
	if r != 0 && r != nerrNetNameNotFound {
		return fmt.Errorf("NetShareDel(%q): status %d", name, r)
	}
	return nil
}

// userExists reports whether a local user is present, by looking up its SID.
func userExists(name string) bool {
	_, _, _, err := windows.LookupSID("", name)
	return err == nil
}

// userSID returns the local user's SID string.
func userSID(name string) (string, error) {
	sid, _, _, err := windows.LookupSID("", name)
	if err != nil {
		return "", fmt.Errorf("LookupSID(%q): %w", name, err)
	}
	return sid.String(), nil
}

// userAdd creates a local user that never expires and cannot log on interactively in practice
// (it is hidden from the sign-in screen by hideUser). It is not idempotent; the caller checks
// userExists first.
func userAdd(name, password string) error {
	info := userInfo1{
		Name:     u16(name),
		Password: u16(password),
		Priv:     usePrivUser,
		Comment:  u16("hcsctl VM file-sharing account"),
		Flags:    ufScript | ufDontExpirePasswd,
	}
	var parmErr uint32
	r, _, _ := procNetUserAdd.Call(0, 1, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parmErr)))
	if r != 0 {
		return fmt.Errorf("NetUserAdd(%q): status %d (bad field %d)", name, r, parmErr)
	}
	return nil
}

// userSetPassword rotates a local user's password (USER_INFO_1003).
func userSetPassword(name, password string) error {
	info := userInfo1003{Password: u16(password)}
	var parmErr uint32
	r, _, _ := procNetUserSetInfo.Call(0, uintptr(unsafe.Pointer(u16(name))), 1003, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parmErr)))
	if r != 0 {
		return fmt.Errorf("NetUserSetInfo(%q, 1003): status %d (bad field %d)", name, r, parmErr)
	}
	return nil
}

func userDel(name string) error {
	r, _, _ := procNetUserDel.Call(0, uintptr(unsafe.Pointer(u16(name))))
	if r != 0 && r != nerrUserNotFound {
		return fmt.Errorf("NetUserDel(%q): status %d", name, r)
	}
	return nil
}

const userListKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList`

// hideUser keeps the service account off the sign-in screen (a value of 0 under UserList).
// A best-effort convenience, not a security boundary; failure is not fatal to prepare.
func hideUser(name string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, userListKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetDWordValue(name, 0)
}

// unhideUser removes the UserList entry. A missing value is not an error.
func unhideUser(name string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, userListKey, registry.SET_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return err
	}
	defer k.Close()
	if err := k.DeleteValue(name); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}
